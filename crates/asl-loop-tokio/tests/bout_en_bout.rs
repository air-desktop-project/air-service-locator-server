//! **Un vrai client, une vraie socket, une vraie réponse.**
//!
//! # CE QUE CET ESSAI PROUVE, ET QU'AUCUN AUTRE NE PROUVE
//!
//! Toutes les pièces sont éprouvées séparément : `asl-session` à 100 %,
//! `scripts/ca.sh` par l'essai de certificat, et la pile QUIC chez son amont.
//! **Rien ne dit qu'elles s'emboîtent.** Un ALPN oublié, un flux de contrôle
//! jamais ouvert, une réponse écrite sur le mauvais flux : chacune de ces fautes
//! laisse tout compiler, tous les essais unitaires passer, et le serveur ne rien
//! répondre.
//!
//! Ici, la chaîne entière tourne :
//!
//!   1. `scripts/ca.sh` frappe une autorité et un certificat ;
//!   2. [`asl_loop_tokio::configuration_tls`] les monte, ALPN comprise ;
//!   3. [`asl_loop_tokio::servir_quic`] écoute sur une vraie socket UDP ;
//!   4. un client QUIC réel monte la poignée de main et envoie une requête ;
//!   5. la réponse est celle qu'`asl-session` décide.
//!
//! # POURQUOI IPv4, DANS UN PRODUIT QUI EST « IPv6 D'ABORD »
//!
//! **C'est une limite du harnais, pas du serveur.** `ams_quic_client::Client`
//! se lie sur `127.0.0.1:0`, en dur. Notre écoute, elle, prend la socket qu'on
//! lui donne et ne connaît aucune famille d'adresses.
//!
//! # LE HARNAIS VÉRIFIE LE NOM `localhost`
//!
//! `ams_quic_client::config_client` construit un `ServerName::try_from(
//! "localhost")`. Le certificat de banc doit donc porter ce nom — et c'est le
//! cas, la cérémonie le met en premier SAN.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use ams_proto_h3::{FrameHeader, FrameKind, qpack};
use asl_api::corps::{CreationDeCompte, PlateformeAttestation};
use asl_id::{Genre, Identifiant};
use asl_loop_tokio::h3::{Attestations, ConfigAndroid, ConfigApple, Voie};
use asl_loop_tokio::{Annuaire, Comptes, configuration_tls, servir_quic};
use asl_registre::{AliasRange, Provenance};
use asl_store::Entrepot;

/// La racine du dépôt, depuis ce paquet.
fn depot() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("le paquet vit sous `crates/`")
        .to_path_buf()
}

/// Frappe une autorité et un certificat de banc dans un temporaire.
fn materiel(quoi: &str) -> (PathBuf, Vec<u8>, Vec<u8>, Vec<u8>) {
    let autorite = std::env::temp_dir().join(format!("asl-bout-{}-{quoi}", std::process::id()));
    let _ = std::fs::remove_dir_all(&autorite);

    for arguments in [
        vec!["racine"],
        vec!["serveur", "banc", "localhost", "127.0.0.1", "::1"],
    ] {
        let sortie = Command::new(depot().join("scripts/ca.sh"))
            .args(&arguments)
            .env("ASL_CA", &autorite)
            .current_dir(depot())
            .output()
            .expect("`scripts/ca.sh` doit être lançable — et `openssl` présent");
        assert!(
            sortie.status.success(),
            "la cérémonie a échoué :\n{}\n{}",
            String::from_utf8_lossy(&sortie.stdout),
            String::from_utf8_lossy(&sortie.stderr),
        );
    }

    let racine = std::fs::read(autorite.join("racine.crt")).expect("la racine");
    let chaine = std::fs::read(autorite.join("banc/chaine.pem")).expect("la chaîne");
    let cle = std::fs::read(autorite.join("banc/serveur.key")).expect("la clé");
    (autorite, racine, chaine, cle)
}

/// Un entrepôt neuf, dans un fichier à nous.
fn entrepot(quoi: &str) -> (Entrepot, PathBuf) {
    let chemin = std::env::temp_dir().join(format!("asl-bout-{}-{quoi}.redb", std::process::id()));
    let _ = std::fs::remove_file(&chemin);
    let racine = Identifiant::depuis_entropie(Genre::Annuaire, [0xEE; 16]);
    (
        Entrepot::ouvrir(&chemin, racine).expect("un entrepôt neuf"),
        chemin,
    )
}

/// Une machine de ce compte, avec cette clé déjà liée — enrôlée sans code,
/// comme le banc la veut.
fn machine_enrolee(
    base: &Entrepot,
    quelle: Identifiant,
    proprietaire: Identifiant,
    cle: [u8; 32],
    capacites: asl_registre::Capacites,
) {
    base.creer_machine(
        quelle,
        Provenance::Ici,
        proprietaire,
        nom_de_machine("grenier"),
        capacites,
    )
    .expect("la machine est écrite");
    let emission = asl_registre::Estampille {
        compteur: 0,
        racine: base.racine(),
    };
    base.lier_cle(quelle, cle, [0; 32], emission)
        .expect("la clé est liée");
}

/// Les deux capacités.
const TOUT: asl_registre::Capacites = asl_registre::Capacites {
    annonce: true,
    lecture: true,
};

/// Lance l'écoute sur une socket éphémère, et rend son adresse et de quoi
/// l'arrêter.
async fn lever(
    chaine: &[u8],
    cle: &[u8],
    entrepot: Entrepot,
) -> (
    SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<Comptes>,
) {
    // Le bail du produit : dix secondes de cadence, trente d'inactivité.
    lever_avec_bail(
        chaine,
        cle,
        entrepot,
        asl_proto::Bail::nouveau(10, 30).expect("un bail"),
    )
    .await
}

/// La même, en choisissant le bail qu'on accorde.
///
/// **C'EST CE QUI REND LE MAINTIEN ÉPROUVABLE EN QUELQUES SECONDES.** Avec le
/// bail du produit, voir une annonce expirer demanderait d'attendre trente
/// secondes par essai.
async fn lever_avec_bail(
    chaine: &[u8],
    cle: &[u8],
    entrepot: Entrepot,
    bail: asl_proto::Bail,
) -> (
    SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<Comptes>,
) {
    lever_complet(
        chaine,
        cle,
        entrepot,
        bail,
        asl_auth::Politique::AttestationFacultative,
        Attestations::AUCUNE,
        None,
    )
    .await
}

/// Ce que l'annuaire dit à son journal d'exploitation, pour les essais qui
/// veulent lire la cause d'un refus.
static JOURNAL: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn journaliser(ligne: &str) {
    JOURNAL
        .lock()
        .expect("le journal n'est pas empoisonné")
        .push(ligne.to_owned());
}

/// La plus générale : on choisit la posture, les configurations
/// d'attestation, et le délai de la règle des orphelins (`None` : jamais).
async fn lever_complet(
    chaine: &[u8],
    cle: &[u8],
    entrepot: Entrepot,
    bail: asl_proto::Bail,
    politique: asl_auth::Politique,
    attestations: Attestations<'static>,
    orphelins: Option<u64>,
) -> (
    SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<Comptes>,
) {
    let tls = Arc::new(configuration_tls(chaine, cle).expect("une configuration TLS"));
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("une socket");
    let adresse = socket.local_addr().expect("une adresse");

    let (dire_stop, entendre_stop) = tokio::sync::oneshot::channel();
    let tache = tokio::spawn(async move {
        // Un défi FIXE dans l'essai : ce qui est éprouvé ici est le transport,
        // pas la qualité du tirage — celle-là l'est dans `asl-server::entropie`.
        let tirer = || Some(asl_cle::Defi::depuis_octets([0x5A; 32]));
        // **UN IDENTIFIANT DE SERVICE QUI VARIE**, même dans l'essai : deux
        // annonces de noms différents doivent donner deux services.
        let compteur = std::sync::atomic::AtomicU8::new(1);
        let nommer = || {
            let rang = compteur.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Some([rang; 16])
        };
        let mut application = Annuaire::new(
            &entrepot,
            &tirer,
            &nommer,
            politique,
            attestations,
            bail,
            Voie {
                journal: &journaliser,
                ..Voie::AUCUNE
            },
        );
        if let Some(delai) = orphelins {
            application.effacer_les_orphelins_apres(delai);
        }
        let arret = async {
            let _ = entendre_stop.await;
        };
        // Trente secondes d'inactivité : bien plus que ce que l'essai prend, et
        // assez pour qu'un délai ne vienne pas fermer la connexion en cours de
        // route sur une machine chargée.
        // **L'INACTIVITÉ DU TRANSPORT SUIT CELLE DU BAIL**, comme dans le
        // binaire : `protocole.md` §1.2 promet que la connexion EST le bail, et
        // un essai qui les laisserait diverger n'éprouverait pas le produit.
        let inactivite = u64::from(bail.inactivite_secondes()).saturating_mul(1_000_000);
        servir_quic(socket, tls, 16, inactivite, &mut application, arret)
            .await
            .expect("l'écoute rend ses comptes")
    });

    (adresse, dire_stop, tache)
}

/// Les champs de la réponse, décodés.
///
/// # POURQUOI DÉCODER, PLUTÔT QUE CHERCHER UNE CHAÎNE DANS LES OCTETS
///
/// La première version de cet essai cherchait `no-store` dans la charge du
/// flux, et échouait. **Le champ était pourtant là** : `cache-control: no-store`
/// est une entrée de la TABLE STATIQUE de QPACK (annexe A de RFC 9204), donc il
/// voyage sur un seul octet d'index et la chaîne n'apparaît jamais sur le fil.
///
/// Un essai qui cherche des octets ne distingue pas « le champ est absent » de
/// « le champ est encodé mieux que je ne croyais ». Celui-ci décode, et peut
/// donc affirmer sur le STATUT autant que sur les champs.
fn champs(reponse: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    // §4.1 de RFC 9114 : les en-têtes d'abord, le corps ensuite.
    let entete = FrameHeader::parse(reponse).expect("une trame HTTP/3");
    assert_eq!(
        entete.kind(),
        FrameKind::Headers,
        "la première trame doit être HEADERS"
    );
    let fin = usize::try_from(entete.total()).expect("tient");
    let mut section = reponse
        .get(entete.header_len()..fin)
        .expect("la section entière");

    // Le préfixe : nous n'annonçons aucune capacité de table dynamique, donc il
    // se lit avec zéro insertion.
    let prefixe = qpack::read_prefix(section, 0, 0).expect("un préfixe");
    section = section.get(prefixe.read..).unwrap_or_default();

    let mut sortie = Vec::new();
    let mut place = [0_u8; 4096];
    let mut libre = &mut place[..];
    while !section.is_empty() {
        let decode = qpack::read_field_line(section, libre).expect("une ligne de champ");
        libre = decode.rest;
        section = section.get(decode.read..).unwrap_or_default();
        let (nom, valeur) = match decode.line {
            qpack::FieldLine::Indexed { index, .. } => {
                qpack::entree_statique(index).expect("une entrée statique")
            }
            qpack::FieldLine::LiteralWithName { index, value, .. } => {
                let (nom, _) = qpack::entree_statique(index).expect("un nom statique");
                (nom, value)
            }
            qpack::FieldLine::Literal { name, value, .. } => (name, value),
            autre => panic!("une représentation qu'on n'attend pas : {autre:?}"),
        };
        sortie.push((nom.to_vec(), valeur.to_vec()));
    }
    sortie
}

/// La valeur de ce champ, si la réponse le porte.
fn champ<'a>(champs: &'a [(Vec<u8>, Vec<u8>)], nom: &[u8]) -> Option<&'a [u8]> {
    champs
        .iter()
        .find(|(cle, _)| cle == nom)
        .map(|(_, valeur)| valeur.as_slice())
}

#[tokio::test]
async fn une_requete_traverse_toute_la_pile_et_revient() {
    let (autorite, racine, chaine, cle) = materiel("servie");
    let (base, fichier) = entrepot("servie");
    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;

    let mut client =
        ams_quic_client::Client::new(ams_quic_client::config_client(&racine), adresse).await;
    // La poignée de main : on parle, on écoute, jusqu'à ce qu'elle aboutisse.
    for _ in 0..64_u32 {
        client.parler().await;
        if !client.ecouter().await {
            break;
        }
    }

    // `17` est l'index QPACK de `:method: GET` (annexe A de RFC 9204).
    //
    // `/v1/expositions` SE ROUTE et sert `GET`, et la réponse est `401` — et
    // non `404`, qui dirait que la cible n'existe pas, ni `501`, qui dirait
    // qu'elle existe et n'est pas écrite.
    //
    // **L'EXIGENCE EST EXAMINÉE AVANT L'IMPLÉMENTATION, ET C'EST L'ORDRE
    // JUSTE.** Un inconnu qui reçoit `501` apprend quels verbes cet annuaire ne
    // sait pas encore servir, donc lesquels il saura servir demain. Il n'a
    // aucun besoin de le savoir : il n'a pas prouvé de clé.
    ams_quic_client::envoyer_une_requete(&mut client, 0, 17, b"/v1/expositions", None, b"").await;
    // **ELLE NE REND QUE LE CORPS** : le harnais jette les en-têtes après les
    // avoir validés. Elle sert donc à ATTENDRE, et le flux brut se lit à côté.
    let corps = ams_quic_client::attendre_la_reponse(&mut client, 0).await;
    let brut = client.recu(0).to_vec();

    let champs = champs(&brut);
    assert_eq!(
        champ(&champs, b":status"),
        Some(&b"401"[..]),
        "la réponse n'est pas celle qu'`asl-session` décide : {champs:?}"
    );
    assert_eq!(
        champ(&champs, b"cache-control"),
        Some(&b"no-store"[..]),
        "la garde `no-store` n'a pas traversé QPACK"
    );
    assert_eq!(
        champ(&champs, b"x-content-type-options"),
        Some(&b"nosniff"[..]),
        "la garde `nosniff` n'a pas traversé QPACK"
    );
    assert_eq!(
        champ(&champs, b"content-type"),
        Some(&b"application/problem+json"[..]),
        "le type de média d'un refus est celui de RFC 9457"
    );

    // **LE CORPS EST ARRIVÉ ENTIER**, et sa longueur est celle qui a été
    // annoncée. C'est ce qui éprouve la réservation que le fuzz avait imposée à
    // `asl_session::composer` : une longueur tronquée ferait couper ici.
    let annoncee = champ(&champs, b"content-length").expect("une longueur annoncée");
    let annoncee: usize = core::str::from_utf8(annoncee)
        .expect("des chiffres")
        .parse()
        .expect("un nombre");
    assert_eq!(corps.len(), annoncee, "le corps ne fait pas sa longueur");
    assert!(
        corps.windows(3).any(|f| f == b"401"),
        "le corps d'un problème porte son propre code : {:?}",
        String::from_utf8_lossy(&corps)
    );

    // **L'EXTINCTION VA JUSQU'AU BOUT.** Si le second temps de §5.2 bloquait,
    // cette attente ne rendrait jamais et l'essai expirerait sans rien dire de
    // plus. Les comptes prouvent en outre que la connexion a bien été comptée
    // là où il faut : une acceptée, aucune refusée, aucune perdue.
    let _ = dire_stop.send(());
    let comptes = tache.await.expect("l'écoute s'éteint proprement");
    assert_eq!(comptes.acceptees, 1, "{comptes:?}");
    assert_eq!(comptes.refusees, 0, "{comptes:?}");

    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

#[tokio::test]
async fn une_cible_inconnue_revient_en_404_et_non_en_501() {
    // **LES DEUX REFUS DOIVENT SE DISTINGUER SUR LE FIL**, et pas seulement dans
    // un essai unitaire : `404` dit « cette cible ne désigne rien », `501` dit
    // « elle désigne quelque chose que je ne sais pas encore servir ». Les
    // confondre ferait chercher une faute d'URL là où il n'y en a pas.
    let (autorite, racine, chaine, cle) = materiel("inconnue");
    let (base, fichier) = entrepot("inconnue");
    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;

    let mut client =
        ams_quic_client::Client::new(ams_quic_client::config_client(&racine), adresse).await;
    for _ in 0..64_u32 {
        client.parler().await;
        if !client.ecouter().await {
            break;
        }
    }

    ams_quic_client::envoyer_une_requete(&mut client, 0, 17, b"/v1/rien-de-tel", None, b"").await;
    let _ = ams_quic_client::attendre_la_reponse(&mut client, 0).await;
    let brut = client.recu(0).to_vec();

    let champs = champs(&brut);
    assert_eq!(
        champ(&champs, b":status"),
        Some(&b"404"[..]),
        "une cible inconnue n'a pas rendu 404 : {champs:?}"
    );

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

#[tokio::test]
async fn un_compte_ecrit_dans_l_entrepot_revient_par_son_alias() {
    // **C'EST LA CHAÎNE ENTIÈRE**, et c'est le premier essai où l'annuaire rend
    // une donnée qu'il a vraiment rangée : la cérémonie frappe un certificat,
    // l'entrepôt garde un compte, la boucle sert QUIC, la session dit ce qu'il
    // lui faut, l'étage 3 va le chercher, et le client reçoit l'identifiant.
    let (autorite, racine, chaine, cle) = materiel("alias");
    let (base, fichier) = entrepot("alias");

    let qui = Identifiant::depuis_entropie(Genre::Utilisateur, [0x2A; 16]);
    base.creer_compte(
        qui,
        Provenance::Ici,
        Some(AliasRange::nouveau("thierry").expect("il tient")),
    )
    .expect("le compte est écrit");

    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;
    let mut client =
        ams_quic_client::Client::new(ams_quic_client::config_client(&racine), adresse).await;
    for _ in 0..64_u32 {
        client.parler().await;
        if !client.ecouter().await {
            break;
        }
    }

    ams_quic_client::envoyer_une_requete(&mut client, 0, 17, b"/v1/alias/thierry", None, b"").await;
    let corps = ams_quic_client::attendre_la_reponse(&mut client, 0).await;
    let brut = client.recu(0).to_vec();

    let champs = champs(&brut);
    assert_eq!(
        champ(&champs, b":status"),
        Some(&b"200"[..]),
        "l'alias n'a pas été résolu : {champs:?}"
    );
    assert_eq!(
        champ(&champs, b"content-type"),
        Some(&b"application/json"[..])
    );

    let rendu = String::from_utf8_lossy(&corps);
    assert!(
        rendu.contains(qui.texte().as_str()),
        "l'identifiant n'est pas dans la réponse : {rendu}"
    );
    assert!(
        rendu.contains("thierry"),
        "l'alias n'est pas dans la réponse : {rendu}"
    );

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

#[tokio::test]
async fn un_alias_que_personne_ne_porte_revient_en_404() {
    let (autorite, racine, chaine, cle) = materiel("sans-alias");
    let (base, fichier) = entrepot("sans-alias");
    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;

    let mut client =
        ams_quic_client::Client::new(ams_quic_client::config_client(&racine), adresse).await;
    for _ in 0..64_u32 {
        client.parler().await;
        if !client.ecouter().await {
            break;
        }
    }

    ams_quic_client::envoyer_une_requete(&mut client, 0, 17, b"/v1/alias/personne", None, b"")
        .await;
    let _ = ams_quic_client::attendre_la_reponse(&mut client, 0).await;
    let brut = client.recu(0).to_vec();

    assert_eq!(champ(&champs(&brut), b":status"), Some(&b"404"[..]));

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

#[tokio::test]
async fn une_machine_s_authentifie_de_bout_en_bout() {
    // **LA CHAÎNE CRYPTOGRAPHIQUE ENTIÈRE**, sur une vraie socket : le client
    // tire un défi, le signe avec sa clé Ed25519 en le liant au certificat du
    // serveur, et la connexion devient authentifiée.
    let (autorite, racine, chaine, cle) = materiel("authentifie");
    let (base, fichier) = entrepot("authentifie");

    // La machine et sa clé. L'annuaire ne connaît que la PUBLIQUE.
    let secrete = asl_cle::CleSecrete::depuis_entropie([0x33; 32]);
    let machine = Identifiant::depuis_entropie(Genre::Machine, [0x44; 16]);
    let proprietaire = Identifiant::depuis_entropie(Genre::Utilisateur, [0x55; 16]);
    machine_enrolee(
        &base,
        machine,
        proprietaire,
        secrete.publique().octets(),
        TOUT,
    );

    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;
    let mut client =
        ams_quic_client::Client::new(ams_quic_client::config_client(&racine), adresse).await;
    for _ in 0..64_u32 {
        client.parler().await;
        if !client.ecouter().await {
            break;
        }
    }

    // ── SANS PREUVE, UNE LECTURE EST REFUSÉE ────────────────────────────────
    ams_quic_client::envoyer_une_requete(&mut client, 0, 17, b"/v1/ou?service=imap", None, b"")
        .await;
    let _ = ams_quic_client::attendre_la_reponse(&mut client, 0).await;
    assert_eq!(
        champ(&champs(client.recu(0)), b":status"),
        Some(&b"401"[..]),
        "une lecture sans preuve doit être refusée"
    );

    // ── LE DÉFI ─────────────────────────────────────────────────────────────
    ams_quic_client::envoyer_une_requete(&mut client, 4, 17, b"/v1/defi", None, b"").await;
    let octets = ams_quic_client::attendre_la_reponse(&mut client, 4).await;
    assert_eq!(
        octets.len(),
        asl_cle::DEFI_OCTETS,
        "un défi fait trente-deux octets : {octets:?}"
    );
    let mut brut = [0_u8; asl_cle::DEFI_OCTETS];
    brut.copy_from_slice(&octets);
    let defi = asl_cle::Defi::depuis_octets(brut);

    // ── LA PREUVE ───────────────────────────────────────────────────────────
    //
    // **LE CLIENT EXPORTE DE SA PROPRE POIGNÉE DE MAIN** (RFC 8446 §7.5), et le
    // serveur de la sienne. Les deux valeurs ne s'accordent que si c'est LA MÊME
    // poignée de main — ce qui est exactement ce que la liaison doit prouver.
    let liaison = liaison_du_client(&client);
    let signature = secrete
        .signer(machine, &defi, &liaison)
        .expect("la machine signe");
    let mut preuve = Vec::with_capacity(81);
    preuve.push(Genre::Machine.prefixe());
    preuve.extend_from_slice(machine.octets());
    preuve.extend_from_slice(signature.octets());

    ams_quic_client::envoyer_avec_media(
        &mut client,
        8,
        20, // `:method: POST`
        b"/v1/defi",
        None,
        &preuve,
        b"application/octet-stream",
    )
    .await;
    let _ = ams_quic_client::attendre_la_reponse(&mut client, 8).await;
    assert_eq!(
        champ(&champs(client.recu(8)), b":status"),
        Some(&b"204"[..]),
        "la preuve a été refusée"
    );

    // ── ET LA MÊME LECTURE N'EST PLUS REFUSÉE POUR DÉFAUT DE PREUVE ─────────
    ams_quic_client::envoyer_une_requete(&mut client, 12, 17, b"/v1/ou?service=imap", None, b"")
        .await;
    let _ = ams_quic_client::attendre_la_reponse(&mut client, 12).await;
    let apres = champs(client.recu(12));
    assert_ne!(
        champ(&apres, b":status"),
        Some(&b"401"[..]),
        "la connexion est authentifiée, le refus ne peut plus être celui-là : {apres:?}"
    );

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

/// Authentifie ce client comme cette machine, sur cette connexion.
async fn authentifier(
    client: &mut ams_quic_client::Client,
    machine: Identifiant,
    secrete: &asl_cle::CleSecrete,
    flux_defi: u64,
    flux_preuve: u64,
) {
    ams_quic_client::envoyer_une_requete(client, flux_defi, 17, b"/v1/defi", None, b"").await;
    let octets = ams_quic_client::attendre_la_reponse(client, flux_defi).await;
    let mut brut = [0_u8; asl_cle::DEFI_OCTETS];
    brut.copy_from_slice(&octets);
    let defi = asl_cle::Defi::depuis_octets(brut);

    let liaison = liaison_du_client(client);
    let signature = secrete
        .signer(machine, &defi, &liaison)
        .expect("elle signe");
    let mut preuve = Vec::with_capacity(81);
    preuve.push(Genre::Machine.prefixe());
    preuve.extend_from_slice(machine.octets());
    preuve.extend_from_slice(signature.octets());

    ams_quic_client::envoyer_avec_media(
        client,
        flux_preuve,
        20,
        b"/v1/defi",
        None,
        &preuve,
        b"application/octet-stream",
    )
    .await;
    let _ = ams_quic_client::attendre_la_reponse(client, flux_preuve).await;
    assert_eq!(
        champ(&champs(client.recu(flux_preuve)), b":status"),
        Some(&b"204"[..]),
        "l'authentification a échoué"
    );
}

#[tokio::test]
async fn une_autorisation_ouvre_le_service_d_un_autre_compte() {
    // **C'EST LE PRODUIT ENTIER, EN UN ESSAI.** A possède une machine qui sert
    // `imap`. B possède une machine qui cherche. Sans autorisation, B ne
    // trouve rien — et il ne peut même pas savoir que ça existe. Avec, il
    // trouve.
    let (autorite, racine, chaine, cle) = materiel("autorise");
    let (base, fichier) = entrepot("autorise");

    let compte_a = Identifiant::depuis_entropie(Genre::Utilisateur, [0xA1; 16]);
    let compte_b = Identifiant::depuis_entropie(Genre::Utilisateur, [0xB2; 16]);
    let machine_a = Identifiant::depuis_entropie(Genre::Machine, [0xA1; 16]);
    let machine_b = Identifiant::depuis_entropie(Genre::Machine, [0xB2; 16]);
    let secrete_b = asl_cle::CleSecrete::depuis_entropie([0xB2; 32]);

    for (quelle, proprietaire, cle_publique) in [
        (machine_a, compte_a, [0_u8; 32]),
        (machine_b, compte_b, secrete_b.publique().octets()),
    ] {
        machine_enrolee(&base, quelle, proprietaire, cle_publique, TOUT);
    }
    base.declarer_service(
        Identifiant::depuis_entropie(Genre::Service, [0xA1; 16]),
        Provenance::Ici,
        machine_a,
        asl_registre::NomRange::nouveau("imap").expect("il tient"),
    )
    .expect("le service est écrit");

    let cible = format!("/v1/ou/{}/imap", machine_a.texte());
    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;
    let mut client =
        ams_quic_client::Client::new(ams_quic_client::config_client(&racine), adresse).await;
    for _ in 0..64_u32 {
        client.parler().await;
        if !client.ecouter().await {
            break;
        }
    }
    authentifier(&mut client, machine_b, &secrete_b, 0, 4).await;

    // ── SANS AUTORISATION : INTROUVABLE, ET NON « INTERDIT » ─────────────────
    ams_quic_client::envoyer_une_requete(&mut client, 8, 17, cible.as_bytes(), None, b"").await;
    let _ = ams_quic_client::attendre_la_reponse(&mut client, 8).await;
    assert_eq!(
        champ(&champs(client.recu(8)), b":status"),
        Some(&b"404"[..]),
        "un `403` dirait à B que ce service existe (C10)"
    );

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

#[tokio::test]
async fn avec_l_autorisation_le_meme_service_cesse_d_etre_introuvable() {
    let (autorite, racine, chaine, cle) = materiel("ouvert");
    let (base, fichier) = entrepot("ouvert");

    let compte_a = Identifiant::depuis_entropie(Genre::Utilisateur, [0xA1; 16]);
    let compte_b = Identifiant::depuis_entropie(Genre::Utilisateur, [0xB2; 16]);
    let machine_a = Identifiant::depuis_entropie(Genre::Machine, [0xA1; 16]);
    let machine_b = Identifiant::depuis_entropie(Genre::Machine, [0xB2; 16]);
    let secrete_b = asl_cle::CleSecrete::depuis_entropie([0xB2; 32]);

    for (quelle, proprietaire, cle_publique) in [
        (machine_a, compte_a, [0_u8; 32]),
        (machine_b, compte_b, secrete_b.publique().octets()),
    ] {
        machine_enrolee(&base, quelle, proprietaire, cle_publique, TOUT);
    }
    base.declarer_service(
        Identifiant::depuis_entropie(Genre::Service, [0xA1; 16]),
        Provenance::Ici,
        machine_a,
        asl_registre::NomRange::nouveau("imap").expect("il tient"),
    )
    .expect("le service est écrit");

    // **L'ARÊTE ENTRE LES DEUX COMPTES** : A autorise B, sur tout son compte.
    base.accorder_autorisation(
        Identifiant::depuis_entropie(Genre::Autorisation, [0x01; 16]),
        Provenance::Ici,
        compte_a,
        compte_b,
        asl_registre::Portee::ToutLeCompte,
        asl_registre::NomRange::nouveau("essai").expect("court"),
    )
    .expect("l'autorisation est écrite");

    let cible = format!("/v1/ou/{}/imap", machine_a.texte());
    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;
    let mut client =
        ams_quic_client::Client::new(ams_quic_client::config_client(&racine), adresse).await;
    for _ in 0..64_u32 {
        client.parler().await;
        if !client.ecouter().await {
            break;
        }
    }
    authentifier(&mut client, machine_b, &secrete_b, 0, 4).await;

    ams_quic_client::envoyer_une_requete(&mut client, 8, 17, cible.as_bytes(), None, b"").await;
    let _ = ams_quic_client::attendre_la_reponse(&mut client, 8).await;
    let apres = champs(client.recu(8));
    assert_eq!(
        champ(&apres, b":status"),
        Some(&b"404"[..]),
        "l'autorisation ouvre l'accès, et il n'y a pourtant rien à joindre : \
         aucun daemon ne tient de connexion pour ce service : {apres:?}"
    );

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

#[tokio::test]
async fn un_daemon_annonce_et_son_service_devient_trouvable() {
    // **LA RAISON D'ÊTRE DU PRODUIT, EN UN ESSAI.** Un daemon obtient du système
    // le port qu'il veut, l'annonce, et ses clients le retrouvent — sans qu'il
    // ait jamais eu besoin d'un numéro de port fixe.
    let (autorite, racine, chaine, cle) = materiel("annonce");
    let (base, fichier) = entrepot("annonce");

    let compte = Identifiant::depuis_entropie(Genre::Utilisateur, [0xC1; 16]);
    let machine = Identifiant::depuis_entropie(Genre::Machine, [0xD1; 16]);
    let secrete = asl_cle::CleSecrete::depuis_entropie([0xD1; 32]);
    machine_enrolee(&base, machine, compte, secrete.publique().octets(), TOUT);

    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;
    let mut client =
        ams_quic_client::Client::new(ams_quic_client::config_client(&racine), adresse).await;
    for _ in 0..64_u32 {
        client.parler().await;
        if !client.ecouter().await {
            break;
        }
    }
    authentifier(&mut client, machine, &secrete, 0, 4).await;

    // ── L'ANNONCE ───────────────────────────────────────────────────────────
    //
    // Le daemon dit sur quel port il écoute. Le port est celui que le système
    // lui a donné — ici 49152, un éphémère.
    let annonce = format!(
        r#"{{"machine":"{}","service":"depot-de-messages",\
"points":[{{"protocole":"tcp","port":49152}}],\
"adresses_locales":["192.168.1.20"]}}"#,
        machine.texte()
    )
    .replace('\\', "");

    ams_quic_client::envoyer_avec_media(
        &mut client,
        8,
        20,
        b"/v1/annonce",
        None,
        annonce.as_bytes(),
        b"application/json",
    )
    .await;
    let rendu = ams_quic_client::attendre_la_reponse(&mut client, 8).await;
    let apres = champs(client.recu(8));
    assert_eq!(
        champ(&apres, b":status"),
        Some(&b"200"[..]),
        "l'annonce a été refusée : {apres:?}"
    );

    let dit = String::from_utf8_lossy(&rendu);
    assert!(
        dit.contains("49152"),
        "la réponse doit porter le port annoncé : {dit}"
    );
    // **`en_cours` PLUTÔT QU'UN VERDICT** : l'annuaire n'a pas encore sondé, et
    // il le DIT au lieu de l'affirmer. C'est C6 dans la réponse.
    assert!(
        dit.contains("en_cours"),
        "l'annuaire ne doit rien affirmer qu'il n'a pas mesuré : {dit}"
    );

    // **LE VERDICT DE NAT EST CALCULÉ, ET IL EST JUSTE.** Le daemon annonce
    // `192.168.1.20` ; l'annuaire le voit venir de `127.0.0.1`. Les deux ne
    // concordent pas, donc il est derrière un NAT — et c'est le seul endroit du
    // produit où cette comparaison peut se faire, puisque le daemon ne sait pas
    // comment on le voit.
    assert!(
        dit.contains(r#""derriere_nat":"oui""#),
        "le verdict de NAT n'a pas été tiré de la comparaison : {dit}"
    );

    // **L'ADRESSE CONSTATÉE, ET NON CELLE QU'ON A ENTENDUE.**
    assert!(
        dit.contains("127.0.0.1"),
        "la réponse doit dire d'où l'annuaire a VU ce daemon : {dit}"
    );

    // Le service a reçu un identifiant : la première annonce d'un nom le crée.
    assert!(
        dit.contains(r#""service":"s-"#),
        "l'annonce doit avoir créé le service : {dit}"
    );

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

#[tokio::test]
async fn une_machine_sans_capacite_d_annonce_est_refusee() {
    // La capacité est une décision de l'utilisateur sur SA machine. Une machine
    // de lecture seule ne doit rien pouvoir écrire dans l'annuaire.
    let (autorite, racine, chaine, cle) = materiel("sans-annonce");
    let (base, fichier) = entrepot("sans-annonce");

    let machine = Identifiant::depuis_entropie(Genre::Machine, [0xE1; 16]);
    let secrete = asl_cle::CleSecrete::depuis_entropie([0xE1; 32]);
    machine_enrolee(
        &base,
        machine,
        Identifiant::depuis_entropie(Genre::Utilisateur, [0xE1; 16]),
        secrete.publique().octets(),
        asl_registre::Capacites {
            annonce: false,
            lecture: true,
        },
    );

    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;
    let mut client =
        ams_quic_client::Client::new(ams_quic_client::config_client(&racine), adresse).await;
    for _ in 0..64_u32 {
        client.parler().await;
        if !client.ecouter().await {
            break;
        }
    }
    authentifier(&mut client, machine, &secrete, 0, 4).await;

    let annonce = format!(
        r#"{{"machine":"{}","service":"imap","points":[{{"protocole":"tcp","port":993}}],"adresses_locales":[]}}"#,
        machine.texte()
    );
    ams_quic_client::envoyer_avec_media(
        &mut client,
        8,
        20,
        b"/v1/annonce",
        None,
        annonce.as_bytes(),
        b"application/json",
    )
    .await;
    let _ = ams_quic_client::attendre_la_reponse(&mut client, 8).await;
    assert_eq!(
        champ(&champs(client.recu(8)), b":status"),
        Some(&b"403"[..]),
        "une machine sans capacité `annonce` a pu annoncer"
    );

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

#[tokio::test]
async fn un_service_annonce_par_a_se_retrouve_chez_b_qui_y_a_droit() {
    // **LE PRODUIT ENTIER, D'UN BOUT À L'AUTRE.** Le daemon d'A annonce le port
    // que son système lui a donné. B, qu'A a autorisé, demande où est ce
    // service — et reçoit le port, sans qu'aucun numéro n'ait été fixé
    // d'avance ni convenu entre eux.
    let (autorite, racine, chaine, cle) = materiel("trouve");
    let (base, fichier) = entrepot("trouve");

    let compte_a = Identifiant::depuis_entropie(Genre::Utilisateur, [0xA1; 16]);
    let compte_b = Identifiant::depuis_entropie(Genre::Utilisateur, [0xB2; 16]);
    let machine_a = Identifiant::depuis_entropie(Genre::Machine, [0xA1; 16]);
    let machine_b = Identifiant::depuis_entropie(Genre::Machine, [0xB2; 16]);
    let secrete_a = asl_cle::CleSecrete::depuis_entropie([0xA1; 32]);
    let secrete_b = asl_cle::CleSecrete::depuis_entropie([0xB2; 32]);

    for (quelle, proprietaire, secrete) in [
        (machine_a, compte_a, &secrete_a),
        (machine_b, compte_b, &secrete_b),
    ] {
        machine_enrolee(
            &base,
            quelle,
            proprietaire,
            secrete.publique().octets(),
            TOUT,
        );
    }
    base.accorder_autorisation(
        Identifiant::depuis_entropie(Genre::Autorisation, [0x01; 16]),
        Provenance::Ici,
        compte_a,
        compte_b,
        asl_registre::Portee::ToutLeCompte,
        asl_registre::NomRange::nouveau("essai").expect("court"),
    )
    .expect("l'autorisation est écrite");

    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;

    // ── A ANNONCE, SUR SA CONNEXION ─────────────────────────────────────────
    let mut daemon =
        ams_quic_client::Client::new(ams_quic_client::config_client(&racine), adresse).await;
    for _ in 0..64_u32 {
        daemon.parler().await;
        if !daemon.ecouter().await {
            break;
        }
    }
    authentifier(&mut daemon, machine_a, &secrete_a, 0, 4).await;

    let annonce = format!(
        r#"{{"machine":"{}","service":"depot","points":[{{"protocole":"tcp","port":49152}}],"adresses_locales":[]}}"#,
        machine_a.texte()
    );
    ams_quic_client::envoyer_avec_media(
        &mut daemon,
        8,
        20,
        b"/v1/annonce",
        None,
        annonce.as_bytes(),
        b"application/json",
    )
    .await;
    let _ = ams_quic_client::attendre_la_reponse(&mut daemon, 8).await;
    assert_eq!(
        champ(&champs(daemon.recu(8)), b":status"),
        Some(&b"200"[..]),
        "l'annonce a échoué"
    );

    // ── B CHERCHE, SUR LA SIENNE ────────────────────────────────────────────
    //
    // **UNE AUTRE CONNEXION** : c'est bien l'annuaire qui fait le lien, pas un
    // état de session partagé par hasard.
    let mut chercheur =
        ams_quic_client::Client::new(ams_quic_client::config_client(&racine), adresse).await;
    for _ in 0..64_u32 {
        chercheur.parler().await;
        if !chercheur.ecouter().await {
            break;
        }
    }
    authentifier(&mut chercheur, machine_b, &secrete_b, 0, 4).await;

    let cible = format!("/v1/ou/{}/depot", machine_a.texte());
    ams_quic_client::envoyer_une_requete(&mut chercheur, 8, 17, cible.as_bytes(), None, b"").await;
    let corps = ams_quic_client::attendre_la_reponse(&mut chercheur, 8).await;
    let apres = champs(chercheur.recu(8));

    assert_eq!(
        champ(&apres, b":status"),
        Some(&b"200"[..]),
        "B n'a pas trouvé le service qu'A lui a ouvert : {apres:?}"
    );
    let dit = String::from_utf8_lossy(&corps);
    assert!(
        dit.contains("49152"),
        "B doit recevoir le PORT, c'est tout l'objet du produit : {dit}"
    );

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

#[tokio::test]
async fn la_sonde_mesure_la_joignabilite_et_le_verdict_bascule() {
    // **C'EST LA FONCTION LA PLUS UTILE DU PRODUIT** (`modele.md` §4.3) :
    // l'annuaire dit au propriétaire si son service est joignable, à la seconde
    // où il démarre — plutôt qu'il ne le découvre quand quelqu'un essaie.
    let (autorite, racine, chaine, cle) = materiel("sonde");
    let (base, fichier) = entrepot("sonde");

    let compte = Identifiant::depuis_entropie(Genre::Utilisateur, [0xF1; 16]);
    let machine = Identifiant::depuis_entropie(Genre::Machine, [0xF1; 16]);
    let secrete = asl_cle::CleSecrete::depuis_entropie([0xF1; 32]);
    machine_enrolee(&base, machine, compte, secrete.publique().octets(), TOUT);

    // **UN VRAI SERVICE QUI ÉCOUTE**, sur la boucle locale — c'est-à-dire
    // exactement l'adresse d'où l'annuaire verra le daemon venir, donc le
    // candidat RÉFLEXIF qu'il a le droit de sonder.
    let service = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("un service d'essai");
    let port = service.local_addr().expect("une adresse").port();
    tokio::spawn(async move {
        // On accepte et l'on referme : la sonde ne dit rien, on ne lui répond
        // rien.
        while let Ok((flux, _)) = service.accept().await {
            drop(flux);
        }
    });

    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;
    let mut client =
        ams_quic_client::Client::new(ams_quic_client::config_client(&racine), adresse).await;
    for _ in 0..64_u32 {
        client.parler().await;
        if !client.ecouter().await {
            break;
        }
    }
    authentifier(&mut client, machine, &secrete, 0, 4).await;

    let annonce = format!(
        r#"{{"machine":"{}","service":"depot","points":[{{"protocole":"tcp","port":{port}}}],"adresses_locales":[]}}"#,
        machine.texte()
    );
    ams_quic_client::envoyer_avec_media(
        &mut client,
        8,
        20,
        b"/v1/annonce",
        None,
        annonce.as_bytes(),
        b"application/json",
    )
    .await;
    let rendu = ams_quic_client::attendre_la_reponse(&mut client, 8).await;

    // **LA RÉPONSE N'ATTEND PAS LA MESURE.** Attendre le trois-temps ferait
    // patienter le daemon, et bloquerait une boucle qui n'a qu'une tâche.
    assert!(
        String::from_utf8_lossy(&rendu).contains("en_cours"),
        "l'annonce doit répondre avant d'avoir sondé : {}",
        String::from_utf8_lossy(&rendu)
    );

    // ── ET LE VERDICT BASCULE ───────────────────────────────────────────────
    //
    // On redemande jusqu'à ce que la sonde ait rapporté. Chaque requête fait un
    // tour de boucle, et c'est au tour que les verdicts sont recueillis.
    let cible = format!("/v1/ou/{}/depot", machine.texte());
    let mut vu = String::new();
    let mut flux = 12_u64;
    for _ in 0..40_u32 {
        ams_quic_client::envoyer_une_requete(&mut client, flux, 17, cible.as_bytes(), None, b"")
            .await;
        let corps = ams_quic_client::attendre_la_reponse(&mut client, flux).await;
        vu = String::from_utf8_lossy(&corps).into_owned();
        if vu.contains("joignable") {
            break;
        }
        flux = flux.saturating_add(4);
        tokio::time::sleep(core::time::Duration::from_millis(50)).await;
    }

    assert!(
        vu.contains("joignable"),
        "la sonde n'a jamais rapporté que le service était joignable : {vu}"
    );
    assert!(
        vu.contains(&port.to_string()),
        "et le port sondé doit être celui qu'on a annoncé : {vu}"
    );

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

#[tokio::test]
async fn un_port_ou_rien_n_ecoute_reste_injoignable() {
    // **C6 EN ACTION** : l'annuaire ne dit `joignable` que de ce qu'il a mesuré,
    // et dit `injoignable` de ce qu'il a mesuré aussi. C'est ce qui prévient un
    // administrateur derrière un NAT AVANT que quelqu'un n'essaie.
    let (autorite, racine, chaine, cle) = materiel("injoignable");
    let (base, fichier) = entrepot("injoignable");

    let machine = Identifiant::depuis_entropie(Genre::Machine, [0xF2; 16]);
    let secrete = asl_cle::CleSecrete::depuis_entropie([0xF2; 32]);
    machine_enrolee(
        &base,
        machine,
        Identifiant::depuis_entropie(Genre::Utilisateur, [0xF2; 16]),
        secrete.publique().octets(),
        TOUT,
    );

    // Un port qu'on prend puis qu'on rend : plus personne n'écoute.
    let port = {
        let ecoute = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("une écoute");
        ecoute.local_addr().expect("une adresse").port()
    };

    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;
    let mut client =
        ams_quic_client::Client::new(ams_quic_client::config_client(&racine), adresse).await;
    for _ in 0..64_u32 {
        client.parler().await;
        if !client.ecouter().await {
            break;
        }
    }
    authentifier(&mut client, machine, &secrete, 0, 4).await;

    let annonce = format!(
        r#"{{"machine":"{}","service":"depot","points":[{{"protocole":"tcp","port":{port}}}],"adresses_locales":[]}}"#,
        machine.texte()
    );
    ams_quic_client::envoyer_avec_media(
        &mut client,
        8,
        20,
        b"/v1/annonce",
        None,
        annonce.as_bytes(),
        b"application/json",
    )
    .await;
    let _ = ams_quic_client::attendre_la_reponse(&mut client, 8).await;

    let cible = format!("/v1/ou/{}/depot", machine.texte());
    let mut vu = String::new();
    let mut flux = 12_u64;
    for _ in 0..40_u32 {
        ams_quic_client::envoyer_une_requete(&mut client, flux, 17, cible.as_bytes(), None, b"")
            .await;
        let corps = ams_quic_client::attendre_la_reponse(&mut client, flux).await;
        vu = String::from_utf8_lossy(&corps).into_owned();
        if vu.contains("injoignable") {
            break;
        }
        flux = flux.saturating_add(4);
        tokio::time::sleep(core::time::Duration::from_millis(50)).await;
    }

    assert!(
        vu.contains("injoignable"),
        "la sonde devait rapporter que rien n'écoute : {vu}"
    );

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

/// Un nom de machine, pour les essais.
fn nom_de_machine(texte: &str) -> asl_registre::NomRange {
    asl_registre::NomRange::nouveau(texte).expect("un nom court se range")
}

/// Monte une connexion cliente et achève sa poignée de main.
async fn connecter(racine: &[u8], adresse: SocketAddr) -> ams_quic_client::Client {
    let mut client =
        ams_quic_client::Client::new(ams_quic_client::config_client(racine), adresse).await;
    for _ in 0..64_u32 {
        client.parler().await;
        if !client.ecouter().await {
            break;
        }
    }
    client
}

/// Tire le défi de cette connexion.
async fn tirer_le_defi(client: &mut ams_quic_client::Client, flux: u64) -> asl_cle::Defi {
    ams_quic_client::envoyer_une_requete(client, flux, 17, b"/v1/defi", None, b"").await;
    let octets = ams_quic_client::attendre_la_reponse(client, flux).await;
    let mut brut = [0_u8; asl_cle::DEFI_OCTETS];
    brut.copy_from_slice(&octets);
    asl_cle::Defi::depuis_octets(brut)
}

/// Poste ce corps d'octets bruts, et rend le statut et le corps de la réponse.
async fn poster(
    client: &mut ams_quic_client::Client,
    flux: u64,
    cible: &[u8],
    corps: &[u8],
    media: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    // `20` est l'index QPACK de `:method: POST`.
    ams_quic_client::envoyer_avec_media(client, flux, 20, cible, None, corps, media).await;
    let rendu = ams_quic_client::attendre_la_reponse(client, flux).await;
    let statut = champ(&champs(client.recu(flux)), b":status")
        .expect("un statut")
        .to_vec();
    (statut, rendu)
}

/// Envoie un `PATCH`, **dont la méthode ne tient dans aucun index**.
///
/// # POURQUOI CELUI-CI SE BÂTIT À LA MAIN
///
/// L'annexe A de RFC 9204 donne un index à `GET`, `POST`, `PUT` et `DELETE` —
/// et **aucun à `PATCH`**. `une_section` ne sait donc pas l'écrire, et il faut
/// une ligne de champ littérale (§4.5.6). Les pseudo-champs restent en tête,
/// comme §4.3 de RFC 9114 l'exige : un serveur qui recevrait `content-type`
/// avant `:method` doit clore le flux.
async fn patcher(
    client: &mut ams_quic_client::Client,
    flux: u64,
    cible: &[u8],
    corps: &[u8],
) -> Vec<u8> {
    let mut section = vec![0x00_u8, 0x00];
    for (nom, valeur) in [
        (&b":method"[..], &b"PATCH"[..]),
        (b":scheme", b"https"),
        (b":authority", b"exemple.test"),
        (b":path", cible),
        (b"content-type", b"application/json"),
    ] {
        ams_quic_client::poser_champ(nom, valeur, &mut section);
    }
    ams_quic_client::envoyer_la_section(client, flux, &section, corps).await;
    let _ = ams_quic_client::attendre_la_reponse(client, flux).await;
    champ(&champs(client.recu(flux)), b":status")
        .expect("un statut")
        .to_vec()
}

/// La valeur d'un champ JSON plat, sans analyseur.
///
/// Ces corps sont écrits par `asl-session`, à champs fixes et sans échappement :
/// une recherche de `"nom":"` suffit, et évite de tirer un analyseur JSON dans
/// un essai pour vérifier ce qu'un encodeur vient d'écrire.
fn valeur_json(corps: &[u8], nom: &str) -> String {
    let texte = String::from_utf8_lossy(corps).into_owned();
    let marque = alloc_format(nom);
    let debut = texte
        .find(&marque)
        .unwrap_or_else(|| panic!("`{nom}` absent de {texte}"))
        .saturating_add(marque.len());
    let reste = &texte[debut..];
    let fin = reste
        .find(['"', ',', '}'])
        .expect("une valeur se termine toujours");
    reste[..fin].to_owned()
}

/// `"<nom>":` suivi du guillemet ouvrant, s'il y en a un.
fn alloc_format(nom: &str) -> String {
    format!("\"{nom}\":\"")
}

/// La valeur d'un champ JSON numérique.
fn nombre_json(corps: &[u8], nom: &str) -> u64 {
    let texte = String::from_utf8_lossy(corps).into_owned();
    let marque = format!("\"{nom}\":");
    let debut = texte
        .find(&marque)
        .expect("le champ existe")
        .saturating_add(marque.len());
    let reste = &texte[debut..];
    let fin = reste.find([',', '}']).expect("une valeur se termine");
    reste[..fin].parse().expect("un nombre")
}

/// Crée un compte : une clé d'appareil, sa preuve de possession, et le tour.
///
/// Rend le compte, l'appareil, et la clé secrète de l'appareil.
async fn creer_un_compte(
    client: &mut ams_quic_client::Client,
    flux: u64,
    graine: u8,
) -> (Identifiant, Identifiant, asl_cle::CleSecreteAppareil) {
    // **UNE CLÉ D'APPAREIL, P-256** : c'est un téléphone, et sa clé vit dans la
    // Secure Enclave, qui ne fait que cette courbe.
    let secrete =
        asl_cle::CleSecreteAppareil::depuis_entropie([graine; 32]).expect("un scalaire valide");
    let defi = tirer_le_defi(client, flux).await;
    let liaison = liaison_du_client(client);
    let preuve = secrete.prouver_la_possession(&defi, &liaison);

    // **PLATE-FORME `Aucune`** : ce banc n'a pas d'attestation à présenter. Le
    // corps est plate-forme (1) ‖ clé (33) ‖ preuve (64), sans rien derrière.
    let objet = asl_api::corps::CreationDeCompte {
        plateforme: asl_api::corps::PlateformeAttestation::Aucune,
        cle: &secrete.publique().octets(),
        preuve: preuve.octets(),
        attestation: &[],
    };
    let mut tampon = [0_u8; 98];
    let n = objet.encoder(&mut tampon).expect("un corps bien formé");
    let corps = tampon[..n].to_vec();

    let (statut, rendu) = poster(
        client,
        flux.saturating_add(4),
        b"/v1/comptes",
        &corps,
        b"application/octet-stream",
    )
    .await;
    assert_eq!(statut, b"201", "{}", String::from_utf8_lossy(&rendu));

    let compte = Identifiant::analyser(&valeur_json(&rendu, "compte")).expect("un identifiant");
    let appareil = Identifiant::analyser(&valeur_json(&rendu, "appareil")).expect("un identifiant");
    assert_eq!(compte.genre(), Genre::Utilisateur);
    assert_eq!(appareil.genre(), Genre::Appareil);
    (compte, appareil, secrete)
}

/// La capture réelle du Fairphone 5 — `docs/attestation/captures/
/// keystore-fp5-2026-09-16/` : une case qui porte la feuille et le premier
/// intermédiaire, et la racine de Google.
///
/// **Pas la chaîne entière** : le harnais `ams-quic-client` scelle chaque
/// requête dans UN paquet, et les 3 421 octets de la chaîne n'y tiennent pas.
/// La feuille et l'intermédiaire de TEE font 1 193 octets, et suffisent à ce
/// que cet essai prouve — que la plate-forme `2` arrive bien à
/// `asl_keystore::verifier`, sous les réglages de l'exploitant, et que le
/// refus se journalise avec sa cause. La chaîne entière, elle, remonte à
/// Google dans les essais d'`asl-keystore`.
fn capture_android() -> (Vec<u8>, Vec<u8>) {
    let dossier = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/attestation/captures/keystore-fp5-2026-09-16");
    let certificats: Vec<Vec<u8>> = (0..4)
        .map(|i| std::fs::read(dossier.join(format!("cert{i}.der"))).expect("la capture"))
        .collect();
    let case =
        asl_keystore::case::assembler(&[&certificats[0], &certificats[1]]).expect("la case tient");
    (case, certificats[3].clone())
}

#[tokio::test]
async fn une_attestation_que_l_annuaire_ne_peut_pas_prouver_est_refusee() {
    // **CE QUE CET ESSAI PROUVE** : une attestation déclarée mais invalide ne
    // crée pas de compte, et le journal d'exploitation dit pourquoi. L'annuaire
    // est configuré pour Apple ET pour Android (la racine de Google, le paquet
    // et l'empreinte du Fairphone 5), donc il ESSAIE de vérifier — et échoue :
    // les octets d'Apple ne remontent pas à sa racine ; la chaîne du Fairphone
    // 5, amputée de ce que le harnais ne sait pas porter, ne remonte pas à
    // Google. L'invitation n'est pas servie. Les trois rendent `403` : la règle refuse,
    // ce n'est pas une panne (`500`). La possession, elle, est bien prouvée :
    // c'est l'attestation seule qui fait tomber la création.
    let (autorite, racine, chaine, cle) = materiel("attest");
    let (base, fichier) = entrepot("attest");
    let bail = asl_proto::Bail::nouveau(10, 30).expect("un bail");
    let apple = Some(ConfigApple {
        identifiant_app: "ABCDE12345.ch.narro.essai",
        environnement: asl_apple::Environnement::Production,
    });
    let (case_reelle, google) = capture_android();
    let racines: &'static [Vec<u8>] = Box::leak(vec![google].into_boxed_slice());
    let mut signataire = [0_u8; 32];
    for (place, paire) in signataire.iter_mut().zip(
        "5ea316f1b50f2ce54b8225aba85ff5cc8238a710b8fae44b4f3a195aadeb5f68"
            .as_bytes()
            .chunks(2),
    ) {
        *place = u8::from_str_radix(std::str::from_utf8(paire).expect("ascii"), 16)
            .expect("hexadécimal");
    }
    let android = Some(ConfigAndroid {
        racines,
        paquet: "org.airdesktop.servicelocator",
        signataire,
    });
    let (adresse, dire_stop, tache) = lever_complet(
        &chaine,
        &cle,
        base,
        bail,
        asl_auth::Politique::AttestationFacultative,
        Attestations { apple, android },
        None,
    )
    .await;
    let mut client = connecter(&racine, adresse).await;

    let cas: [(PlateformeAttestation, &[u8], &str); 3] = [
        // Des octets qui ne sont même pas une attestation : peu importe, la
        // chaîne ne remonte de toute façon pas à Apple.
        (
            PlateformeAttestation::Apple,
            &[0xA5, 0x01, 0x02, 0x03, 0x04],
            "attestation refusée : Apple, ",
        ),
        (
            PlateformeAttestation::Android,
            &case_reelle,
            "attestation refusée : Android, chaîne refusée",
        ),
        (
            PlateformeAttestation::Invitation,
            b"4K9M2P7R1T",
            "attestation refusée : invitation, pas encore servie",
        ),
    ];
    for (rang, (plateforme, attestation, cause)) in cas.into_iter().enumerate() {
        let flux_defi = (rang as u64).saturating_mul(8);
        let flux_post = flux_defi.saturating_add(4);
        let defi = tirer_le_defi(&mut client, flux_defi).await;
        let liaison = liaison_du_client(&client);
        let secrete =
            asl_cle::CleSecreteAppareil::depuis_entropie([0x5C; 32]).expect("un scalaire valide");
        let preuve = secrete.prouver_la_possession(&defi, &liaison);
        let objet = CreationDeCompte {
            plateforme,
            cle: &secrete.publique().octets(),
            preuve: preuve.octets(),
            attestation,
        };
        let mut tampon = [0_u8; asl_api::corps::COMPTE_CORPS_MAX];
        let n = objet.encoder(&mut tampon).expect("un corps bien formé");
        let (statut, _) = poster(
            &mut client,
            flux_post,
            b"/v1/comptes",
            &tampon[..n],
            b"application/octet-stream",
        )
        .await;
        assert_eq!(statut, b"403", "{plateforme:?} aurait dû être refusée");
        // **LE JOURNAL DIT LA CAUSE, SANS L'ATTESTATION.** C'est ce que
        // l'exploitant lit ; une chaîne de certificats n'y a pas sa place.
        let journal = JOURNAL.lock().expect("le journal n'est pas empoisonné");
        let ligne = journal
            .iter()
            .rev()
            .find(|ligne| ligne.starts_with("attestation refusée"))
            .cloned()
            .unwrap_or_default();
        assert!(ligne.starts_with(cause), "{plateforme:?} : « {ligne} »");
        assert!(ligne.len() < 200, "le journal ne porte pas l'attestation");
    }

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

#[tokio::test]
async fn le_produit_entier_se_monte_par_l_api_et_rien_d_autre() {
    // ── CE QUE CET ESSAI PROUVE, ET QU'AUCUN AUTRE NE PROUVAIT ──────────────
    //
    // Jusqu'ici, tous les essais de résolution ÉCRIVAIENT L'ENTREPÔT À LA MAIN :
    // comptes, machines, clés et autorisations étaient posés par le harnais,
    // parce qu'aucun verbe ne savait les créer. L'annuaire était donc éprouvé
    // sur un état que personne n'aurait pu produire en s'en servant.
    //
    // Ici, **rien n'est écrit à la main**. Tout passe par l'API :
    //
    //   A crée son compte, déclare une machine, l'enrôle avec le code reçu ;
    //   B fait de même ; A autorise B ; le daemon d'A annonce son port ;
    //   la machine de B demande où il est, et l'obtient.
    //
    // C'est l'énoncé du produit, du premier geste au dernier, sans qu'aucun
    // numéro de port n'ait été convenu ni aucune ligne posée sous la table.
    let (autorite, racine, chaine, cle) = materiel("api");
    let (base, fichier) = entrepot("api");
    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;

    // ── A : COMPTE, MACHINE, ENRÔLEMENT ─────────────────────────────────────
    let mut alice = connecter(&racine, adresse).await;
    let (compte_a, _appareil_a, _cle_a) = creer_un_compte(&mut alice, 0, 0xA1).await;

    // La connexion est désormais celle de cet appareil : `POST /v1/comptes`
    // portait déjà sa preuve, et la refaire par `/v1/defi` serait la même
    // démonstration deux fois.
    let (statut, rendu) = poster(
        &mut alice,
        8,
        b"/v1/machines",
        br#"{"nom":"grenier","capacites":["annonce"]}"#,
        b"application/json",
    )
    .await;
    assert_eq!(statut, b"201", "{}", String::from_utf8_lossy(&rendu));
    let machine_a = Identifiant::analyser(&valeur_json(&rendu, "machine")).expect("une machine");
    let code_a = valeur_json(&rendu, "code");
    assert_eq!(code_a.len(), 11, "le code s'affiche groupé : {code_a}");
    assert!(nombre_json(&rendu, "expire_a") > 0, "le code expire");

    // **LA MACHINE PARLE SUR SA PROPRE CONNEXION**, et elle ne connaît que le
    // code — pas le compte, pas l'appareil, rien d'autre.
    let mut daemon = connecter(&racine, adresse).await;
    let secrete_a = asl_cle::CleSecrete::depuis_entropie([0xD1; 32]);
    let enrolee = enroler(&mut daemon, 0, &code_a, &secrete_a).await;
    assert_eq!(enrolee, machine_a, "le code désigne la machine d'A");

    // ── B : COMPTE ET MACHINE DE LECTURE ────────────────────────────────────
    let mut bob = connecter(&racine, adresse).await;
    let (compte_b, _appareil_b, _cle_b) = creer_un_compte(&mut bob, 0, 0xB1).await;
    let (statut, rendu) = poster(
        &mut bob,
        8,
        b"/v1/machines",
        br#"{"nom":"portable","capacites":["lecture"]}"#,
        b"application/json",
    )
    .await;
    assert_eq!(statut, b"201", "{}", String::from_utf8_lossy(&rendu));
    let machine_b = Identifiant::analyser(&valeur_json(&rendu, "machine")).expect("une machine");
    let code_b = valeur_json(&rendu, "code");

    let mut chercheur = connecter(&racine, adresse).await;
    let secrete_b = asl_cle::CleSecrete::depuis_entropie([0xD2; 32]);
    assert_eq!(
        enroler(&mut chercheur, 0, &code_b, &secrete_b).await,
        machine_b
    );

    // ── B CHERCHE AVANT D'ÊTRE AUTORISÉ, ET NE TROUVE RIEN ──────────────────
    authentifier(&mut chercheur, machine_b, &secrete_b, 12, 16).await;

    // ── LE DAEMON D'A ANNONCE ───────────────────────────────────────────────
    authentifier(&mut daemon, machine_a, &secrete_a, 12, 16).await;
    let annonce = format!(
        r#"{{"machine":"{}","service":"depot","points":[{{"protocole":"tcp","port":49152}}]}}"#,
        machine_a.texte()
    );
    let (statut, _) = poster(
        &mut daemon,
        20,
        b"/v1/annonce",
        annonce.as_bytes(),
        b"application/json",
    )
    .await;
    assert_eq!(statut, b"200", "l'annonce est prise");

    let cible = format!("/v1/ou/{}/depot", machine_a.texte());
    ams_quic_client::envoyer_une_requete(&mut chercheur, 20, 17, cible.as_bytes(), None, b"").await;
    let _ = ams_quic_client::attendre_la_reponse(&mut chercheur, 20).await;
    assert_eq!(
        champ(&champs(chercheur.recu(20)), b":status"),
        Some(&b"404"[..]),
        "sans autorisation, B ne trouve rien — et n'apprend pas que ça existe"
    );

    // ── A AUTORISE B ────────────────────────────────────────────────────────
    let demande = format!(
        r#"{{"a":"{}","portee":"tout","etiquette":"banc d'essai"}}"#,
        compte_b.texte()
    );
    let (statut, rendu) = poster(
        &mut alice,
        12,
        b"/v1/autorisations",
        demande.as_bytes(),
        b"application/json",
    )
    .await;
    assert_eq!(statut, b"201", "{}", String::from_utf8_lossy(&rendu));
    let accordee =
        Identifiant::analyser(&valeur_json(&rendu, "autorisation")).expect("une autorisation");
    assert_eq!(accordee.genre(), Genre::Autorisation);

    // ── ET B TROUVE LE PORT ─────────────────────────────────────────────────
    ams_quic_client::envoyer_une_requete(&mut chercheur, 24, 17, cible.as_bytes(), None, b"").await;
    let rendu = ams_quic_client::attendre_la_reponse(&mut chercheur, 24).await;
    assert_eq!(
        champ(&champs(chercheur.recu(24)), b":status"),
        Some(&b"200"[..]),
        "l'autorisation ouvre le service"
    );
    let texte = String::from_utf8_lossy(&rendu);
    assert!(
        texte.contains("49152"),
        "B doit obtenir le port qu'A a annoncé : {texte}"
    );
    assert_ne!(compte_a, compte_b, "deux comptes distincts");

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

/// Présente un code et une clé neuve, et rend la machine que le code désignait.
async fn enroler(
    client: &mut ams_quic_client::Client,
    flux: u64,
    code: &str,
    secrete: &asl_cle::CleSecrete,
) -> Identifiant {
    let defi = tirer_le_defi(client, flux).await;
    let liaison = liaison_du_client(client);
    let preuve = secrete.prouver_la_possession(&defi, &liaison);

    // **DIX SYMBOLES, ET NON ONZE** : le corps porte la forme canonique, sans le
    // tiret d'affichage. C'est un champ de longueur fixe, comme la clé et la
    // signature qui le suivent.
    let sans_tiret: String = code.chars().filter(|c| *c != '-').collect();
    let mut corps = Vec::with_capacity(106);
    corps.extend_from_slice(sans_tiret.as_bytes());
    corps.extend_from_slice(&secrete.publique().octets());
    corps.extend_from_slice(preuve.octets());

    let (statut, rendu) = poster(
        client,
        flux.saturating_add(4),
        b"/v1/enrolement",
        &corps,
        b"application/octet-stream",
    )
    .await;
    assert_eq!(statut, b"200", "{}", String::from_utf8_lossy(&rendu));
    // **LA MACHINE ET SON PROPRIÉTAIRE** (`protocole.md` §2.0) : la machine ne
    // connaissait que le code, et repart en sachant pour qui elle agit.
    let proprietaire =
        Identifiant::analyser(&valeur_json(&rendu, "proprietaire")).expect("un propriétaire");
    assert_eq!(proprietaire.genre(), Genre::Utilisateur);
    Identifiant::analyser(&valeur_json(&rendu, "machine")).expect("une machine")
}

#[tokio::test]
async fn une_autorisation_donne_a_voir_les_machines_et_une_machine_sait_qui_elle_est() {
    // ── CE QUE CET ESSAI PROUVE ─────────────────────────────────────────────
    //
    // `modele.md` §2.5 : « tout mon compte » veut dire tout, les machines
    // comprises. Bob ne voit rien des machines d'Alice — une liste vide, pas un
    // refus — tant qu'elle ne lui a rien accordé ; avec « tout », il les voit
    // toutes, par son téléphone comme par sa machine de lecture. Et une machine
    // sait dire qui elle est et à qui elle appartient.
    let (autorite, racine, chaine, cle) = materiel("machines-vues");
    let (base, fichier) = entrepot("machines-vues");
    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;

    // ── ALICE : DEUX MACHINES, DONT UNE QUI NE SERT RIEN ────────────────────
    let mut alice = connecter(&racine, adresse).await;
    let (compte_a, _, _) = creer_un_compte(&mut alice, 0, 0xA3).await;
    let mut machines_a = Vec::new();
    for (flux, corps) in [
        (8_u64, &br#"{"nom":"grenier","capacites":["annonce"]}"#[..]),
        (12, &br#"{"nom":"nas","capacites":[]}"#[..]),
    ] {
        let (statut, rendu) = poster(
            &mut alice,
            flux,
            b"/v1/machines",
            corps,
            b"application/json",
        )
        .await;
        assert_eq!(statut, b"201", "{}", String::from_utf8_lossy(&rendu));
        machines_a
            .push(Identifiant::analyser(&valeur_json(&rendu, "machine")).expect("une machine"));
    }

    // ── BOB : UN COMPTE, UNE MACHINE DE LECTURE ENRÔLÉE ─────────────────────
    let mut bob = connecter(&racine, adresse).await;
    let (compte_b, _, _) = creer_un_compte(&mut bob, 0, 0xB3).await;
    let (statut, rendu) = poster(
        &mut bob,
        8,
        b"/v1/machines",
        br#"{"nom":"portable","capacites":["lecture"]}"#,
        b"application/json",
    )
    .await;
    assert_eq!(statut, b"201", "{}", String::from_utf8_lossy(&rendu));
    let machine_b = Identifiant::analyser(&valeur_json(&rendu, "machine")).expect("une machine");
    let code_b = valeur_json(&rendu, "code");
    let mut chercheur = connecter(&racine, adresse).await;
    let secrete_b = asl_cle::CleSecrete::depuis_entropie([0xD3; 32]);
    assert_eq!(
        enroler(&mut chercheur, 0, &code_b, &secrete_b).await,
        machine_b
    );
    authentifier(&mut chercheur, machine_b, &secrete_b, 12, 16).await;

    // ── LA MACHINE SAIT QUI ELLE EST ────────────────────────────────────────
    ams_quic_client::envoyer_une_requete(&mut chercheur, 20, 17, b"/v1/moi", None, b"").await;
    let rendu = ams_quic_client::attendre_la_reponse(&mut chercheur, 20).await;
    assert_eq!(
        champ(&champs(chercheur.recu(20)), b":status"),
        Some(&b"200"[..])
    );
    assert_eq!(
        rendu,
        format!(
            r#"{{"machine":"{}","proprietaire":"{}"}}"#,
            machine_b.texte(),
            compte_b.texte()
        )
        .into_bytes()
    );
    // Et un appareil, lui, n'a pas ce verbe : il sait déjà qui il est.
    ams_quic_client::envoyer_une_requete(&mut bob, 12, 17, b"/v1/moi", None, b"").await;
    let _ = ams_quic_client::attendre_la_reponse(&mut bob, 12).await;
    assert_eq!(champ(&champs(bob.recu(12)), b":status"), Some(&b"401"[..]));

    // ── SANS ARÊTE : UNE LISTE VIDE, ET NON UN REFUS (C9) ───────────────────
    let cible = format!("/v1/utilisateurs/{}/machines", compte_a.texte());
    for (client, flux) in [(&mut bob, 16_u64), (&mut chercheur, 24)] {
        ams_quic_client::envoyer_une_requete(client, flux, 17, cible.as_bytes(), None, b"").await;
        let rendu = ams_quic_client::attendre_la_reponse(client, flux).await;
        assert_eq!(
            champ(&champs(client.recu(flux)), b":status"),
            Some(&b"200"[..])
        );
        assert_eq!(
            rendu, b"[]",
            "sans arête, Bob n'apprend rien du parc d'Alice"
        );
    }

    // ── ALICE ACCORDE « TOUT LE COMPTE » ────────────────────────────────────
    let demande = format!(
        r#"{{"a":"{}","portee":"tout","etiquette":"bob"}}"#,
        compte_b.texte()
    );
    let (statut, _) = poster(
        &mut alice,
        16,
        b"/v1/autorisations",
        demande.as_bytes(),
        b"application/json",
    )
    .await;
    assert_eq!(statut, b"201");

    // ── ET BOB VOIT LES DEUX MACHINES, SUR LES DEUX VOIES ───────────────────
    for (client, flux) in [(&mut bob, 20_u64), (&mut chercheur, 28)] {
        ams_quic_client::envoyer_une_requete(client, flux, 17, cible.as_bytes(), None, b"").await;
        let rendu = ams_quic_client::attendre_la_reponse(client, flux).await;
        assert_eq!(
            champ(&champs(client.recu(flux)), b":status"),
            Some(&b"200"[..])
        );
        let texte = String::from_utf8_lossy(&rendu).into_owned();
        for (machine, nom) in machines_a.iter().zip(["grenier", "nas"]) {
            assert!(
                texte.contains(&format!(
                    r#"{{"machine":"{}","nom":"{nom}"}}"#,
                    machine.texte()
                )),
                "{texte}"
            );
        }
        // **L'IDENTIFIANT ET LE NOM, ET RIEN D'AUTRE** : ni capacités, ni clé.
        assert!(
            !texte.contains("capacites") && !texte.contains("\"cle\""),
            "{texte}"
        );
    }

    // ── ALICE VOIT LES SIENNES, SANS ARÊTE ──────────────────────────────────
    ams_quic_client::envoyer_une_requete(&mut alice, 20, 17, cible.as_bytes(), None, b"").await;
    let rendu = ams_quic_client::attendre_la_reponse(&mut alice, 20).await;
    let texte = String::from_utf8_lossy(&rendu).into_owned();
    assert_eq!(texte.matches("\"machine\":").count(), 2, "{texte}");

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

#[tokio::test]
async fn une_machine_voit_les_appareils_de_son_compte_et_d_aucun_autre() {
    // ── CE QUE CET ESSAI PROUVE ─────────────────────────────────────────────
    //
    // `protocole.md` §3, `GET /v1/moi/appareils` : une machine enrôlée lit la
    // liste des appareils du compte qui la possède — OCTET POUR OCTET celle
    // que `GET /v1/appareils` rend à un appareil de ce compte : révoqués
    // marqués, description quand elle a été posée. Un compte étranger n'y
    // apparaît pas ; un appareil n'a pas ce verbe ; et une machine dont la clé
    // est révoquée n'a plus de propriétaire à qui poser la question.
    let (autorite, racine, chaine, cle) = materiel("appareils-du-proprietaire");
    let (base, fichier) = entrepot("appareils-du-proprietaire");
    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;

    // ── ALICE : DEUX APPAREILS, DONT UN RÉVOQUÉ, ET UNE MACHINE ─────────────
    let mut alice = connecter(&racine, adresse).await;
    let (_compte_a, premier, _secrete_a) = creer_un_compte(&mut alice, 0, 0xA4).await;
    // Le premier se décrit : c'est ce que l'écran Compte montre, et ce que la
    // machine doit voir aussi. `21` est l'index QPACK de `:method: PUT`.
    let cible = format!("/v1/appareils/{}/description", premier.texte());
    ams_quic_client::envoyer_avec_media(
        &mut alice,
        8,
        21,
        cible.as_bytes(),
        None,
        br#"{"plateforme":"macos","modele":"MacBookPro15,2"}"#,
        b"application/json",
    )
    .await;
    let _ = ams_quic_client::attendre_la_reponse(&mut alice, 8).await;
    assert_eq!(champ(&champs(alice.recu(8)), b":status"), Some(&b"204"[..]));
    // Un second appareil entre — une clé nue, signée par le premier —, puis
    // il est révoqué : il doit RESTER dans la liste, marqué.
    let seconde = asl_cle::CleSecreteAppareil::depuis_entropie([0xA5; 32]).expect("un scalaire");
    let (statut, rendu) = poster(
        &mut alice,
        12,
        b"/v1/appareils",
        &seconde.publique().octets(),
        b"application/octet-stream",
    )
    .await;
    assert_eq!(statut, b"201", "{}", String::from_utf8_lossy(&rendu));
    let second = Identifiant::analyser(&valeur_json(&rendu, "appareil")).expect("un appareil");
    let cible = format!("/v1/appareils/{}", second.texte());
    // `16` est l'index QPACK de `:method: DELETE`.
    ams_quic_client::envoyer_une_requete(&mut alice, 16, 16, cible.as_bytes(), None, b"").await;
    let _ = ams_quic_client::attendre_la_reponse(&mut alice, 16).await;
    assert_eq!(
        champ(&champs(alice.recu(16)), b":status"),
        Some(&b"204"[..]),
        "le second appareil est révoqué"
    );
    let (statut, rendu) = poster(
        &mut alice,
        20,
        b"/v1/machines",
        br#"{"nom":"grenier","capacites":[]}"#,
        b"application/json",
    )
    .await;
    assert_eq!(statut, b"201", "{}", String::from_utf8_lossy(&rendu));
    let machine = Identifiant::analyser(&valeur_json(&rendu, "machine")).expect("une machine");
    let code = valeur_json(&rendu, "code");

    // ── BOB : UN COMPTE ÉTRANGER, QUI NE DOIT PAS APPARAÎTRE ────────────────
    let mut bob = connecter(&racine, adresse).await;
    let (_compte_b, etranger, _secrete_b) = creer_un_compte(&mut bob, 0, 0xB4).await;

    // ── LA MACHINE S'ENRÔLE, PROUVE SA CLÉ, ET LIT LES APPAREILS ────────────
    let mut daemon = connecter(&racine, adresse).await;
    let secrete = asl_cle::CleSecrete::depuis_entropie([0xD4; 32]);
    assert_eq!(enroler(&mut daemon, 0, &code, &secrete).await, machine);
    authentifier(&mut daemon, machine, &secrete, 8, 12).await;
    ams_quic_client::envoyer_une_requete(&mut daemon, 16, 17, b"/v1/moi/appareils", None, b"")
        .await;
    let vu_par_la_machine = ams_quic_client::attendre_la_reponse(&mut daemon, 16).await;
    assert_eq!(
        champ(&champs(daemon.recu(16)), b":status"),
        Some(&b"200"[..]),
        "{}",
        String::from_utf8_lossy(&vu_par_la_machine)
    );
    let texte = String::from_utf8_lossy(&vu_par_la_machine).into_owned();
    assert!(
        texte.contains(&format!(
            r#"{{"appareil":"{}","attestation":"aucune","revoque":false,"plateforme":"macos","modele":"MacBookPro15,2"}}"#,
            premier.texte()
        )),
        "le premier, décrit : {texte}"
    );
    assert!(
        texte.contains(&format!(
            r#"{{"appareil":"{}","attestation":"aucune","revoque":true}}"#,
            second.texte()
        )),
        "le second, révoqué et marqué : {texte}"
    );
    assert!(
        !texte.contains(etranger.texte().as_str()),
        "un appareil d'un autre compte n'y est pas : {texte}"
    );
    // Et chaque objet se relit avec le décodeur de `GET /v1/appareils` : c'est
    // LE MÊME objet, pas un cousin.
    let objets = texte
        .strip_prefix('[')
        .and_then(|reste| reste.strip_suffix(']'))
        .unwrap_or_else(|| panic!("une liste : {texte}"));
    let mut lus = 0_usize;
    for objet in objets.split("},{") {
        let entier = format!(
            "{}{}{}",
            if objet.starts_with('{') { "" } else { "{" },
            objet,
            if objet.ends_with('}') { "" } else { "}" }
        );
        let lu = asl_api::corps::AppareilRendu::decoder(entier.as_bytes())
            .unwrap_or_else(|faute| panic!("{entier} : {faute:?}"));
        assert!(lu.appareil == premier || lu.appareil == second);
        lus = lus.saturating_add(1);
    }
    assert_eq!(lus, 2, "{texte}");

    // ── OCTET POUR OCTET CE QUE L'APPAREIL LIT LUI-MÊME ─────────────────────
    ams_quic_client::envoyer_une_requete(&mut alice, 24, 17, b"/v1/appareils", None, b"").await;
    let vu_par_l_appareil = ams_quic_client::attendre_la_reponse(&mut alice, 24).await;
    assert_eq!(
        vu_par_la_machine, vu_par_l_appareil,
        "la voie machine rend la liste de l'écran Compte, sans une virgule de différence"
    );

    // ── UN APPAREIL N'A PAS CE VERBE ; UN INCONNU NON PLUS ──────────────────
    ams_quic_client::envoyer_une_requete(&mut bob, 12, 17, b"/v1/moi/appareils", None, b"").await;
    let _ = ams_quic_client::attendre_la_reponse(&mut bob, 12).await;
    assert_eq!(champ(&champs(bob.recu(12)), b":status"), Some(&b"401"[..]));
    let mut inconnu = connecter(&racine, adresse).await;
    ams_quic_client::envoyer_une_requete(&mut inconnu, 0, 17, b"/v1/moi/appareils", None, b"")
        .await;
    let _ = ams_quic_client::attendre_la_reponse(&mut inconnu, 0).await;
    assert_eq!(
        champ(&champs(inconnu.recu(0)), b":status"),
        Some(&b"401"[..])
    );

    // ── LA CLÉ RÉVOQUÉE : PLUS DE PROPRIÉTAIRE, DONC `401` ──────────────────
    //
    // La révocation ferme la connexion du daemon ; celle qu'il rouvrirait ne
    // peut plus prouver une clé que l'annuaire ne tient plus. Ici, la preuve
    // est rejouée avec l'ancienne clé, et c'est elle qui est refusée.
    let cible = format!("/v1/machines/{}/cle", machine.texte());
    ams_quic_client::envoyer_une_requete(&mut alice, 28, 16, cible.as_bytes(), None, b"").await;
    let _ = ams_quic_client::attendre_la_reponse(&mut alice, 28).await;
    assert_eq!(
        champ(&champs(alice.recu(28)), b":status"),
        Some(&b"204"[..]),
        "la clé est retirée"
    );
    for _ in 0..32_u32 {
        daemon.parler().await;
        if !daemon.ecouter().await {
            break;
        }
    }
    assert!(daemon.ferme().is_some(), "la révocation ferme la connexion");
    let mut revenant = connecter(&racine, adresse).await;
    let defi = tirer_le_defi(&mut revenant, 0).await;
    let liaison = liaison_du_client(&revenant);
    let signature = secrete
        .signer(machine, &defi, &liaison)
        .expect("elle signe");
    let mut preuve = Vec::with_capacity(81);
    preuve.push(Genre::Machine.prefixe());
    preuve.extend_from_slice(machine.octets());
    preuve.extend_from_slice(signature.octets());
    let (statut, _) = poster(
        &mut revenant,
        4,
        b"/v1/defi",
        &preuve,
        b"application/octet-stream",
    )
    .await;
    assert_ne!(statut, b"204", "une clé révoquée ne prouve plus rien");
    ams_quic_client::envoyer_une_requete(&mut revenant, 8, 17, b"/v1/moi/appareils", None, b"")
        .await;
    let _ = ams_quic_client::attendre_la_reponse(&mut revenant, 8).await;
    assert_eq!(
        champ(&champs(revenant.recu(8)), b":status"),
        Some(&b"401"[..]),
        "sans propriétaire, pas de liste"
    );

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

#[tokio::test]
async fn revoquer_la_cle_d_une_machine_ferme_sa_connexion_et_fait_tomber_son_bail() {
    // ── CE QUE CET ESSAI PROUVE ─────────────────────────────────────────────
    //
    // `protocole.md` §2.2 promet un EFFET IMMÉDIAT : « connexions fermées, baux
    // tombés ». Effacer la clé dans l'entrepôt ne suffirait pas — une connexion
    // déjà authentifiée porte son pair avec elle, c'est tout l'intérêt du
    // transport tenu, et elle continuerait de servir.
    //
    // Ici le daemon annonce, son propriétaire révoque la clé depuis une AUTRE
    // connexion, et l'annonce disparaît sans que le daemon ait rien fait.
    let (autorite, racine, chaine, cle) = materiel("revoque");
    let (base, fichier) = entrepot("revoque");
    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;

    // A crée son compte, déclare une machine, et l'enrôle.
    let mut alice = connecter(&racine, adresse).await;
    let (_compte, _appareil, _secrete) = creer_un_compte(&mut alice, 0, 0xA1).await;
    let (statut, rendu) = poster(
        &mut alice,
        8,
        b"/v1/machines",
        br#"{"nom":"grenier","capacites":["annonce"]}"#,
        b"application/json",
    )
    .await;
    assert_eq!(statut, b"201", "{}", String::from_utf8_lossy(&rendu));
    let machine = Identifiant::analyser(&valeur_json(&rendu, "machine")).expect("une machine");
    let code = valeur_json(&rendu, "code");

    let mut daemon = connecter(&racine, adresse).await;
    let secrete = asl_cle::CleSecrete::depuis_entropie([0xD1; 32]);
    assert_eq!(enroler(&mut daemon, 0, &code, &secrete).await, machine);
    authentifier(&mut daemon, machine, &secrete, 12, 16).await;

    let annonce = format!(
        r#"{{"machine":"{}","service":"depot","points":[{{"protocole":"tcp","port":49152}}]}}"#,
        machine.texte()
    );
    let (statut, _) = poster(
        &mut daemon,
        20,
        b"/v1/annonce",
        annonce.as_bytes(),
        b"application/json",
    )
    .await;
    assert_eq!(statut, b"200", "l'annonce est prise");

    // ── LA RÉVOCATION, DEPUIS L'AUTRE CONNEXION ─────────────────────────────
    let cible = format!("/v1/machines/{}/cle", machine.texte());
    // `16` est l'index QPACK de `:method: DELETE` (annexe A de RFC 9204).
    ams_quic_client::envoyer_une_requete(&mut alice, 12, 16, cible.as_bytes(), None, b"").await;
    let _ = ams_quic_client::attendre_la_reponse(&mut alice, 12).await;
    assert_eq!(
        champ(&champs(alice.recu(12)), b":status"),
        Some(&b"204"[..]),
        "la clé est retirée"
    );

    // ── ET LA CONNEXION DU DAEMON TOMBE ─────────────────────────────────────
    //
    // On laisse la boucle passer quelques tours : `au_tour` traduit le pair
    // révoqué en connexions à fermer, et la fermeture part au tour suivant.
    for _ in 0..32_u32 {
        daemon.parler().await;
        if !daemon.ecouter().await {
            break;
        }
    }
    // `ferme()` rend le code applicatif reçu dans le `CONNECTION_CLOSE`.
    assert!(
        daemon.ferme().is_some(),
        "la connexion du daemon aurait dû être fermée par la révocation"
    );

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

#[tokio::test]
async fn on_apprend_d_ou_l_on_est_vu_sans_rien_annoncer_ni_prouver() {
    // ── CE QUE CET ESSAI PROUVE ─────────────────────────────────────────────
    //
    // La réponse à une annonce porte le candidat réflexif — mais il faut avoir
    // annoncé pour l'obtenir. Une machine de lecture seule, ou un daemon qu'on
    // est en train d'installer, n'avaient donc aucun moyen de savoir sous quelle
    // adresse ils sortent : c'est précisément ce qu'on veut regarder en premier
    // quand personne n'arrive à joindre un port.
    //
    // **AUCUNE PREUVE N'EST PRÉSENTÉE ICI** : la connexion vient d'être ouverte,
    // et rien n'a été signé.
    let (autorite, racine, chaine, cle) = materiel("vu");
    let (base, fichier) = entrepot("vu");
    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;

    let mut client = connecter(&racine, adresse).await;
    // `17` est l'index QPACK de `:method: GET`.
    ams_quic_client::envoyer_une_requete(&mut client, 0, 17, b"/v1/vu", None, b"").await;
    let rendu = ams_quic_client::attendre_la_reponse(&mut client, 0).await;
    assert_eq!(
        champ(&champs(client.recu(0)), b":status"),
        Some(&b"200"[..]),
        "elle n'exige rien"
    );

    // L'essai tourne sur la boucle locale : ce qu'on doit y lire est l'adresse
    // de bouclage, et le port éphémère que le noyau a donné au client.
    let texte = String::from_utf8_lossy(&rendu).into_owned();
    let vue = valeur_json(&rendu, "adresse");
    assert!(
        vue == "::1" || vue == "127.0.0.1",
        "l'annuaire doit nous voir sur la boucle locale, pas sur {vue}"
    );
    assert!(
        texte.contains(r#""famille":6"#) || texte.contains(r#""famille":4"#),
        "{texte}"
    );
    // **LE PORT N'EST PAS ZÉRO** : c'est celui de la socket, pas un champ oublié.
    // `valeur_json` ne sait lire que des chaînes ; celui-ci est un nombre, et
    // c'est bien ainsi qu'on veut le rendre.
    let port: u32 = texte
        .split(r#""port":"#)
        .nth(1)
        .and_then(|reste| reste.split(',').next())
        .and_then(|chiffres| chiffres.parse().ok())
        .unwrap_or_else(|| panic!("pas de port dans {texte}"));
    assert!(port > 0, "{texte}");

    // ── ET DEUX APPELS SUR LA MÊME CONNEXION DISENT LA MÊME CHOSE ───────────
    //
    // Ce n'est pas une évidence : le port source d'une connexion QUIC peut
    // changer si le client migre. Sur la même socket, il ne doit pas.
    ams_quic_client::envoyer_une_requete(&mut client, 4, 17, b"/v1/vu", None, b"").await;
    let encore = ams_quic_client::attendre_la_reponse(&mut client, 4).await;
    assert_eq!(encore, rendu, "la même connexion est vue du même endroit");

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

#[tokio::test]
async fn la_version_se_lit_sans_rien_prouver() {
    // ── CE QUE CET ESSAI PROUVE ─────────────────────────────────────────────
    //
    // Une connexion qui n'a présenté aucune clé lit la version de l'annuaire,
    // et c'est celle du workspace — la même que `asl-server --version`.
    let (autorite, racine, chaine, cle) = materiel("version");
    let (base, fichier) = entrepot("version");
    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;

    let mut client = connecter(&racine, adresse).await;
    ams_quic_client::envoyer_une_requete(&mut client, 0, 17, b"/v1/version", None, b"").await;
    let rendu = ams_quic_client::attendre_la_reponse(&mut client, 0).await;
    assert_eq!(
        champ(&champs(client.recu(0)), b":status"),
        Some(&b"200"[..]),
        "{}",
        String::from_utf8_lossy(&rendu)
    );
    assert_eq!(
        rendu,
        format!(r#"{{"version":"{}"}}"#, env!("CARGO_PKG_VERSION")).into_bytes()
    );

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

#[tokio::test]
async fn une_racine_seule_dit_qu_elle_est_seule_a_une_machine_et_a_personne_d_autre() {
    // ── CE QUE CET ESSAI PROUVE ─────────────────────────────────────────────
    //
    // `GET /v1/replication` (`replication.md` §8) est sur la voie MACHINE : un
    // inconnu reçoit `401`, une machine enrôlée — quelle que soit sa capacité —
    // lit l'état. Sans `--peer`, la racine dit « seule », avec son compteur, et
    // ni `pair` ni `applique`.
    let (autorite, racine, chaine, cle) = materiel("replication-seule");
    let (base, fichier) = entrepot("replication-seule");
    let proprietaire = Identifiant::depuis_entropie(Genre::Utilisateur, [0x01; 16]);
    let machine = Identifiant::depuis_entropie(Genre::Machine, [0x02; 16]);
    let secrete = asl_cle::CleSecrete::depuis_entropie([0x03; 32]);
    base.creer_compte(proprietaire, Provenance::Ici, None)
        .expect("le compte");
    machine_enrolee(
        &base,
        machine,
        proprietaire,
        secrete.publique().octets(),
        asl_registre::Capacites {
            annonce: false,
            lecture: false,
        },
    );
    let compteur = base.compteur().expect("lisible");
    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;

    // Un inconnu : `401`.
    let mut inconnu = connecter(&racine, adresse).await;
    ams_quic_client::envoyer_une_requete(&mut inconnu, 0, 17, b"/v1/replication", None, b"").await;
    let _ = ams_quic_client::attendre_la_reponse(&mut inconnu, 0).await;
    assert_eq!(
        champ(&champs(inconnu.recu(0)), b":status"),
        Some(&b"401"[..])
    );

    // Une machine sans aucune capacité : elle lit.
    let mut client = connecter(&racine, adresse).await;
    authentifier(&mut client, machine, &secrete, 0, 4).await;
    ams_quic_client::envoyer_une_requete(&mut client, 8, 17, b"/v1/replication", None, b"").await;
    let rendu = ams_quic_client::attendre_la_reponse(&mut client, 8).await;
    assert_eq!(
        champ(&champs(client.recu(8)), b":status"),
        Some(&b"200"[..]),
        "{}",
        String::from_utf8_lossy(&rendu)
    );
    assert_eq!(
        rendu,
        format!(r#"{{"voie":"seule","compteur":{compteur}}}"#).into_bytes()
    );

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

#[tokio::test]
async fn un_jeton_de_poussee_se_depose_pour_soi_et_pour_personne_d_autre() {
    // ── CE QUE CET ESSAI PROUVE ─────────────────────────────────────────────
    //
    // Le jeton vient du système du téléphone qui le porte, et personne d'autre
    // ne l'a. Déposer pour l'appareil d'un AUTRE détournerait ses notifications
    // — c'est-à-dire celles d'un compte vers le téléphone de qui l'a volé.
    //
    // Le refus est un `404`, et non un `403` : dire « ce n'est pas vous » à qui
    // vise l'identifiant d'un autre confirmerait que cet identifiant existe.
    let (autorite, racine, chaine, cle) = materiel("jeton-poussee");
    let (base, fichier) = entrepot("jeton-poussee");
    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;

    let mut alice = connecter(&racine, adresse).await;
    let (_compte, appareil, _secrete) = creer_un_compte(&mut alice, 0, 0xA1).await;

    let mut bob = connecter(&racine, adresse).await;
    let (_autre_compte, autre, _autre_secrete) = creer_un_compte(&mut bob, 0, 0xB1).await;

    // `21` est l'index QPACK de `:method: PUT`.
    let cible = format!("/v1/appareils/{}/poussee", appareil.texte());
    ams_quic_client::envoyer_avec_media(
        &mut alice,
        12,
        21,
        cible.as_bytes(),
        None,
        br#"{"plateforme":"apns","jeton":"c0ffee"}"#,
        b"application/json",
    )
    .await;
    let _ = ams_quic_client::attendre_la_reponse(&mut alice, 12).await;
    assert_eq!(
        champ(&champs(alice.recu(12)), b":status"),
        Some(&b"204"[..]),
        "un appareil dépose pour lui-même"
    );

    // ── ET POUR CELUI D'UN AUTRE, RIEN ──────────────────────────────────────
    let cible = format!("/v1/appareils/{}/poussee", autre.texte());
    ams_quic_client::envoyer_avec_media(
        &mut alice,
        16,
        21,
        cible.as_bytes(),
        None,
        br#"{"plateforme":"fcm","jeton":"vole"}"#,
        b"application/json",
    )
    .await;
    let _ = ams_quic_client::attendre_la_reponse(&mut alice, 16).await;
    assert_eq!(
        champ(&champs(alice.recu(16)), b":status"),
        Some(&b"404"[..]),
        "déposer pour l'appareil d'un autre ne dit pas qu'il existe"
    );

    // ── UN CORPS MAL FORMÉ EST UN `400`, ET NON UN `404` ────────────────────
    //
    // Là, la faute est bien celle de l'appelant, et la lui cacher ne protège
    // rien : il vise son propre appareil.
    let cible = format!("/v1/appareils/{}/poussee", appareil.texte());
    ams_quic_client::envoyer_avec_media(
        &mut alice,
        20,
        21,
        cible.as_bytes(),
        None,
        br#"{"plateforme":"windows","jeton":"x"}"#,
        b"application/json",
    )
    .await;
    let _ = ams_quic_client::attendre_la_reponse(&mut alice, 20).await;
    assert_eq!(
        champ(&champs(alice.recu(20)), b":status"),
        Some(&b"400"[..]),
        "une plate-forme inconnue est une requête mal formée"
    );

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

#[tokio::test]
async fn un_appareil_se_decrit_et_l_ecran_compte_le_montre() {
    // ── CE QUE CET ESSAI PROUVE ─────────────────────────────────────────────
    //
    // L'écran Compte montrait le Mac comme « Autre » : `GET /v1/appareils` ne
    // rendait ni système ni modèle, et c'est pourtant l'écran qu'on regarde pour
    // vérifier qu'aucun appareil de trop n'est entré. Ici, un appareil se
    // décrit, et la liste le rend — pour lui seul, et jamais un « nom ».
    let (autorite, racine, chaine, cle) = materiel("description-appareil");
    let (base, fichier) = entrepot("description-appareil");
    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;

    let mut alice = connecter(&racine, adresse).await;
    let (_compte, appareil, _secrete) = creer_un_compte(&mut alice, 0, 0xA2).await;

    let mut bob = connecter(&racine, adresse).await;
    let (_autre_compte, autre, _autre_secrete) = creer_un_compte(&mut bob, 0, 0xB2).await;

    // ── AVANT : LA LISTE NE PORTE NI PLATE-FORME NI MODÈLE ───────────────────
    ams_quic_client::envoyer_une_requete(&mut alice, 12, 17, b"/v1/appareils", None, b"").await;
    let rendu = ams_quic_client::attendre_la_reponse(&mut alice, 12).await;
    assert_eq!(
        champ(&champs(alice.recu(12)), b":status"),
        Some(&b"200"[..])
    );
    let texte = String::from_utf8_lossy(&rendu).into_owned();
    assert!(texte.contains(appareil.texte().as_str()), "{texte}");
    assert!(
        !texte.contains("plateforme") && !texte.contains("modele"),
        "absents tant qu'ils n'ont pas été posés : {texte}"
    );

    // ── L'APPAREIL SE DÉCRIT ─────────────────────────────────────────────────
    // `21` est l'index QPACK de `:method: PUT`.
    let cible = format!("/v1/appareils/{}/description", appareil.texte());
    ams_quic_client::envoyer_avec_media(
        &mut alice,
        16,
        21,
        cible.as_bytes(),
        None,
        br#"{"plateforme":"macos","modele":"MacBook Pro (2019)"}"#,
        b"application/json",
    )
    .await;
    let _ = ams_quic_client::attendre_la_reponse(&mut alice, 16).await;
    assert_eq!(
        champ(&champs(alice.recu(16)), b":status"),
        Some(&b"204"[..]),
        "un appareil se décrit lui-même"
    );

    // ── APRÈS : L'ÉCRAN COMPTE MONTRE « MacBook Pro », ET NON « Autre » ─────
    ams_quic_client::envoyer_une_requete(&mut alice, 20, 17, b"/v1/appareils", None, b"").await;
    let rendu = ams_quic_client::attendre_la_reponse(&mut alice, 20).await;
    let texte = String::from_utf8_lossy(&rendu).into_owned();
    assert!(
        texte.contains(r#""plateforme":"macos","modele":"MacBook Pro (2019)""#),
        "{texte}"
    );
    // Un seul appareil sur ce compte : la liste est cet objet entre crochets, et
    // il se relit avec le décodeur des liaisons.
    let seul = texte
        .strip_prefix('[')
        .and_then(|reste| reste.strip_suffix(']'))
        .unwrap_or_else(|| panic!("une liste : {texte}"));
    let lu = asl_api::corps::AppareilRendu::decoder(seul.as_bytes()).expect("il se relit");
    assert_eq!(lu.appareil, appareil);
    assert_eq!(
        lu.description,
        Some(asl_api::corps::DescriptionAppareil {
            systeme: asl_api::corps::Systeme::Macos,
            modele: "MacBook Pro (2019)",
        })
    );

    // ── ET BOB NE VOIT PAS LA DESCRIPTION D'ALICE : CE N'EST PAS SON COMPTE ─
    ams_quic_client::envoyer_une_requete(&mut bob, 12, 17, b"/v1/appareils", None, b"").await;
    let rendu = ams_quic_client::attendre_la_reponse(&mut bob, 12).await;
    let texte = String::from_utf8_lossy(&rendu).into_owned();
    assert!(texte.contains(autre.texte().as_str()), "{texte}");
    assert!(!texte.contains("MacBook"), "{texte}");

    // ── DÉCRIRE L'APPAREIL D'UN AUTRE : LE `404` DE CE QUI N'EXISTE PAS ─────
    let cible = format!("/v1/appareils/{}/description", autre.texte());
    ams_quic_client::envoyer_avec_media(
        &mut alice,
        24,
        21,
        cible.as_bytes(),
        None,
        br#"{"plateforme":"ios","modele":"iPhone 17"}"#,
        b"application/json",
    )
    .await;
    let _ = ams_quic_client::attendre_la_reponse(&mut alice, 24).await;
    assert_eq!(
        champ(&champs(alice.recu(24)), b":status"),
        Some(&b"404"[..]),
        "décrire l'appareil d'un autre ne dit pas qu'il existe"
    );

    // ── UN « NOM » N'EST PAS UN CHAMP, ET C'EST `400` ────────────────────────
    //
    // « iPhone de Thierry » est ce que C13 refuse. Le verbe ne connaît pas ce
    // champ, et le dit à l'appelant : c'est lui qui vise son propre appareil.
    let cible = format!("/v1/appareils/{}/description", appareil.texte());
    ams_quic_client::envoyer_avec_media(
        &mut alice,
        28,
        21,
        cible.as_bytes(),
        None,
        br#"{"plateforme":"ios","nom":"iPhone de Thierry"}"#,
        b"application/json",
    )
    .await;
    let _ = ams_quic_client::attendre_la_reponse(&mut alice, 28).await;
    assert_eq!(
        champ(&champs(alice.recu(28)), b":status"),
        Some(&b"400"[..]),
        "un nom n'est pas une description"
    );

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

#[tokio::test]
async fn retirer_la_capacite_d_annonce_ferme_la_connexion_du_daemon() {
    // ── CE QUE CET ESSAI PROUVE ─────────────────────────────────────────────
    //
    // Décocher « annonce » dans l'application doit RETIRER quelque chose. Écrire
    // la nouvelle capacité dans l'entrepôt ne suffirait pas : la connexion déjà
    // authentifiée porte son pair avec elle, son bail vit tant qu'elle vit, et
    // l'annuaire continuerait de publier les adresses d'une machine à qui l'on
    // vient d'interdire d'annoncer.
    //
    // **Un changement de NOM, lui, ne ferme rien**, et l'essai le montre dans le
    // même souffle : le daemon survit au premier `PATCH` et tombe au second.
    let (autorite, racine, chaine, cle) = materiel("patch-machine");
    let (base, fichier) = entrepot("patch-machine");
    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;

    let mut alice = connecter(&racine, adresse).await;
    let (_compte, _appareil, _secrete) = creer_un_compte(&mut alice, 0, 0xA1).await;
    let (statut, rendu) = poster(
        &mut alice,
        8,
        b"/v1/machines",
        br#"{"nom":"grenier","capacites":["annonce"]}"#,
        b"application/json",
    )
    .await;
    assert_eq!(statut, b"201", "{}", String::from_utf8_lossy(&rendu));
    let machine = Identifiant::analyser(&valeur_json(&rendu, "machine")).expect("une machine");
    let code = valeur_json(&rendu, "code");

    let mut daemon = connecter(&racine, adresse).await;
    let secrete = asl_cle::CleSecrete::depuis_entropie([0xD2; 32]);
    assert_eq!(enroler(&mut daemon, 0, &code, &secrete).await, machine);
    authentifier(&mut daemon, machine, &secrete, 12, 16).await;

    let annonce = format!(
        r#"{{"machine":"{}","service":"depot","points":[{{"protocole":"tcp","port":49152}}]}}"#,
        machine.texte()
    );
    let (statut, _) = poster(
        &mut daemon,
        20,
        b"/v1/annonce",
        annonce.as_bytes(),
        b"application/json",
    )
    .await;
    assert_eq!(statut, b"200", "l'annonce est prise");

    // ── LE NOM CHANGE, ET RIEN NE TOMBE ─────────────────────────────────────
    let cible = format!("/v1/machines/{}", machine.texte());
    assert_eq!(
        patcher(&mut alice, 16, cible.as_bytes(), br#"{"nom":"cave"}"#).await,
        b"204",
        "le nom se change"
    );
    for _ in 0..16_u32 {
        daemon.parler().await;
        if !daemon.ecouter().await {
            break;
        }
    }
    assert!(
        daemon.ferme().is_none(),
        "renommer ne retire aucun droit, et ne doit rien fermer"
    );

    // ── LA CAPACITÉ PART, ET LA CONNEXION AVEC ──────────────────────────────
    assert_eq!(
        patcher(&mut alice, 20, cible.as_bytes(), br#"{"capacites":[]}"#).await,
        b"204",
        "les capacités se retirent"
    );
    for _ in 0..32_u32 {
        daemon.parler().await;
        if !daemon.ecouter().await {
            break;
        }
    }
    assert!(
        daemon.ferme().is_some(),
        "la connexion du daemon aurait dû être fermée par le retrait de l'annonce"
    );

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

#[tokio::test]
async fn l_alias_se_pose_se_cherche_et_se_retire() {
    // **C'EST LA SEULE DONNÉE PERSONNELLE DU PRODUIT** (C13), et jusqu'ici aucun
    // verbe ne savait la poser : `GET /v1/alias/{alias}` interrogeait un champ
    // que rien ne remplissait.
    let (autorite, racine, chaine, cle) = materiel("alias-api");
    let (base, fichier) = entrepot("alias-api");
    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;

    let mut alice = connecter(&racine, adresse).await;
    let (compte, _appareil, _secrete) = creer_un_compte(&mut alice, 0, 0xA1).await;

    // Avant : personne ne répond à cet alias.
    ams_quic_client::envoyer_une_requete(&mut alice, 8, 17, b"/v1/alias/thierry", None, b"").await;
    let _ = ams_quic_client::attendre_la_reponse(&mut alice, 8).await;
    assert_eq!(champ(&champs(alice.recu(8)), b":status"), Some(&b"404"[..]));

    // On le pose. `21` est l'index QPACK de `:method: PUT`.
    ams_quic_client::envoyer_avec_media(
        &mut alice,
        12,
        21,
        b"/v1/alias",
        None,
        br#"{"alias":"thierry"}"#,
        b"application/json",
    )
    .await;
    let _ = ams_quic_client::attendre_la_reponse(&mut alice, 12).await;
    assert_eq!(
        champ(&champs(alice.recu(12)), b":status"),
        Some(&b"204"[..]),
        "l'alias est posé"
    );

    // **ET IL EST PUBLIC** : la recherche n'exige rien, et ne rend QUE
    // l'identifiant.
    ams_quic_client::envoyer_une_requete(&mut alice, 16, 17, b"/v1/alias/thierry", None, b"").await;
    let rendu = ams_quic_client::attendre_la_reponse(&mut alice, 16).await;
    assert_eq!(
        champ(&champs(alice.recu(16)), b":status"),
        Some(&b"200"[..])
    );
    let texte = String::from_utf8_lossy(&rendu).into_owned();
    assert!(texte.contains(compte.texte().as_str()), "{texte}");
    assert!(
        !texte.contains("machine") && !texte.contains("service"),
        "l'alias ne rend qu'un identifiant : {texte}"
    );

    // Un autre compte ne peut pas le prendre.
    let mut bob = connecter(&racine, adresse).await;
    let (_, _, _) = creer_un_compte(&mut bob, 0, 0xB1).await;
    ams_quic_client::envoyer_avec_media(
        &mut bob,
        12,
        21,
        b"/v1/alias",
        None,
        br#"{"alias":"thierry"}"#,
        b"application/json",
    )
    .await;
    let _ = ams_quic_client::attendre_la_reponse(&mut bob, 12).await;
    assert_eq!(
        champ(&champs(bob.recu(12)), b":status"),
        Some(&b"409"[..]),
        "un alias pris est un CONFLIT, et non un refus de droit"
    );

    // A le retire, et il redevient introuvable.
    ams_quic_client::envoyer_une_requete(&mut alice, 20, 16, b"/v1/alias", None, b"").await;
    let _ = ams_quic_client::attendre_la_reponse(&mut alice, 20).await;
    assert_eq!(
        champ(&champs(alice.recu(20)), b":status"),
        Some(&b"204"[..])
    );

    ams_quic_client::envoyer_une_requete(&mut alice, 24, 17, b"/v1/alias/thierry", None, b"").await;
    let _ = ams_quic_client::attendre_la_reponse(&mut alice, 24).await;
    assert_eq!(
        champ(&champs(alice.recu(24)), b":status"),
        Some(&b"404"[..]),
        "l'index part avec l'alias"
    );

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

/// La liaison de canal, vue du client.
///
/// # ELLE S'EXPORTE, ELLE NE SE CALCULE PLUS
///
/// Elle était l'empreinte du certificat que le client avait vérifié — la même
/// pour toutes ses connexions à ce serveur. Elle est désormais dérivée du secret
/// maître de CETTE poignée de main, et le serveur dérive la sienne pareillement.
///
/// **C'est ce que l'essai éprouve sans le dire** : chaque authentification qui
/// réussit dans ce fichier prouve que les deux camps sont tombés sur les mêmes
/// octets, sans jamais se les être transmis.
fn liaison_du_client(client: &ams_quic_client::Client) -> asl_cle::LiaisonDeCanal {
    asl_cle::LiaisonDeCanal::depuis_octets(
        client
            .export(asl_cle::ETIQUETTE_LIAISON, None)
            .expect("la poignée de main est terminée"),
    )
}

// ── UN `ClientHello` QUI NE TIENT PAS DANS UN DATAGRAMME ────────────────────

/// Monte une configuration cliente dont le `ClientHello` dépasse 1200 octets.
///
/// **L'ALPN SERT DE LEST**, et n'importe quoi d'autre ferait l'affaire : ce
/// qu'on veut est un `ClientHello` que §14.1 oblige à répartir sur DEUX paquets
/// `Initial`. Dans la vraie vie, c'est un échange de clés post-quantique qui le
/// produit — les navigateurs en proposent un par défaut depuis 2024, et leur
/// `ClientHello` fait environ 1600 octets.
fn config_cliente_bavarde(autorite: &[u8]) -> std::sync::Arc<rustls::ClientConfig> {
    use rustls::pki_types::pem::PemObject as _;

    let mut racines = rustls::RootCertStore::empty();
    for der in rustls::pki_types::CertificateDer::pem_slice_iter(autorite) {
        racines
            .add(der.expect("certificat lisible"))
            .expect("racine");
    }
    let mut config =
        rustls::ClientConfig::builder_with_provider(Arc::new(ams_tls::provider_quic()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .with_root_certificates(racines)
            .with_no_client_auth();

    // `h3` d'abord — c'est celui que l'annuaire offre —, puis du lest.
    let mut alpn = ams_tls::alpn_h3();
    for rang in 0..24_u8 {
        alpn.push(format!("lest-{rang:02}-{}", "x".repeat(48)).into_bytes());
    }
    config.alpn_protocols = alpn;
    Arc::new(config)
}

#[tokio::test]
async fn un_client_hello_en_deux_paquets_monte_une_seule_connexion() {
    // ── CE QUE CET ESSAI PROUVE, ET CE QU'IL A ATTRAPÉ ──────────────────────
    //
    // §7.2 : un client invente un identifiant de destination et le garde
    // **jusqu'à ce qu'il ait vu le nôtre**. Un `ClientHello` qui ne tient pas
    // dans un datagramme part donc en DEUX paquets `Initial` portant le MÊME
    // identifiant, d'affilée, avant toute réponse de notre part.
    //
    // L'annuaire ne connaissait que les identifiants QU'IL AVAIT DISTRIBUÉS. Il
    // prenait le second paquet pour une connexion neuve, chaque moitié du
    // `ClientHello` atterrissait dans une connexion différente, et les deux
    // attendaient l'autre moitié pour toujours. **Sans faute, sans message, et
    // sans qu'aucun essai ne le voie** — les deux bancs de ce produit ne
    // tiennent qu'une connexion et routent tout vers elle.
    //
    // Ce n'est pas un cas limite : un `ClientHello` dépasse 1200 octets dès
    // qu'il porte un échange de clés post-quantique.
    let (autorite, racine, chaine, cle) = materiel("hello-long");
    let (base, fichier) = entrepot("hello-long");
    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("une socket");
    socket.connect(adresse).await.expect("la cible");

    let horloge = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |ecoule| u64::try_from(ecoule.as_micros()).unwrap_or(0))
    };
    let mut client = ams_quic_tls::Connection::connect(
        config_cliente_bavarde(&racine),
        rustls::pki_types::ServerName::try_from("localhost").expect("un nom"),
        ams_quic_client::identifiant(&[0x11; 8]),
        ams_quic_client::identifiant(&[0x22; 8]),
        ams_quic_tls::INACTIVITE_US,
        horloge(),
    )
    .expect("le client se monte");

    // **LA PREMIÈRE VOLÉE FAIT PLUS D'UN DATAGRAMME**, et c'est la prémisse de
    // l'essai : s'il n'en faisait qu'un, l'essai ne prouverait rien.
    let mut place = vec![0_u8; 1_500];
    let mut premiers = 0_u32;
    while let Ok(ecrit) = client.poll_transmit(&mut place, horloge()) {
        if ecrit == 0 {
            break;
        }
        socket.send(&place[..ecrit]).await.expect("l'envoi");
        premiers = premiers.saturating_add(1);
    }
    assert!(
        premiers >= 2,
        "le `ClientHello` tient dans un seul paquet : cet essai n'éprouve rien"
    );

    // ── ET LA POIGNÉE DE MAIN ABOUTIT ───────────────────────────────────────
    let mut recu = vec![0_u8; 1_500];
    let echeance = tokio::time::Instant::now() + tokio::time::Duration::from_secs(10);
    while !client.is_established() && tokio::time::Instant::now() < echeance {
        let attente = tokio::time::Duration::from_millis(200);
        if let Ok(Ok(lus)) = tokio::time::timeout(attente, socket.recv(&mut recu)).await {
            let mut datagramme = recu[..lus].to_vec();
            let _ = client.on_datagram(&mut datagramme, horloge());
        } else {
            client.on_timeout(horloge());
        }
        while let Ok(ecrit) = client.poll_transmit(&mut place, horloge()) {
            if ecrit == 0 {
                break;
            }
            let _ = socket.send(&place[..ecrit]).await;
        }
    }
    assert!(
        client.is_established(),
        "un `ClientHello` en deux paquets doit monter une connexion"
    );

    let _ = dire_stop.send(());
    let comptes = tache.await.expect("la tâche finit");
    // **UNE SEULE**, et non deux : c'est tout le défaut, et il se compte.
    assert_eq!(
        comptes.acceptees, 1,
        "deux paquets d'un même client ont monté deux connexions"
    );

    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

// ── LE BAIL QU'ON ACCORDE ───────────────────────────────────────────────────

#[tokio::test]
async fn le_bail_accorde_est_celui_que_la_mesure_a_choisi() {
    // ── CE QUE CET ESSAI ÉPINGLE, ET POURQUOI IL MANQUAIT ───────────────────
    //
    // **RIEN NE VÉRIFIAIT LE BAIL QUE L'ANNUAIRE ACCORDE.** C'est pourtant une
    // décision de produit, et la seule que tous les daemons du monde appliquent
    // sans pouvoir la discuter : `modele.md` §4.1 dit que les deux valeurs
    // viennent du serveur, précisément pour qu'on puisse les changer sans mettre
    // à jour ce qui est installé chez des tiers.
    //
    // Une décision que personne ne vérifie se perd à la première réécriture.
    //
    // Le DIX vient d'une mesure — `bancs/nat/README.md`, 2026-09-10 : sur un
    // lien résidentiel, vingt-huit secondes de silence tiennent et trente non.
    // À quinze, un SEUL keepalive perdu atteignait la borne.
    let (autorite, racine, chaine, cle) = materiel("bail");
    let (base, fichier) = entrepot("bail");
    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;

    let mut alice = connecter(&racine, adresse).await;
    let (_compte, _appareil, _secrete) = creer_un_compte(&mut alice, 0, 0xA1).await;
    let (statut, rendu) = poster(
        &mut alice,
        8,
        b"/v1/machines",
        br#"{"nom":"grenier","capacites":["annonce"]}"#,
        b"application/json",
    )
    .await;
    assert_eq!(statut, b"201", "{}", String::from_utf8_lossy(&rendu));
    let machine = Identifiant::analyser(&valeur_json(&rendu, "machine")).expect("une machine");
    let code = valeur_json(&rendu, "code");

    let mut daemon = connecter(&racine, adresse).await;
    let secrete = asl_cle::CleSecrete::depuis_entropie([0xD3; 32]);
    assert_eq!(enroler(&mut daemon, 0, &code, &secrete).await, machine);
    authentifier(&mut daemon, machine, &secrete, 12, 16).await;

    let annonce = format!(
        r#"{{"machine":"{}","service":"depot","points":[{{"protocole":"tcp","port":49152}}]}}"#,
        machine.texte()
    );
    let (statut, rendu) = poster(
        &mut daemon,
        20,
        b"/v1/annonce",
        annonce.as_bytes(),
        b"application/json",
    )
    .await;
    assert_eq!(statut, b"200", "l'annonce est prise");

    // **LE BAIL VOYAGE DANS LA RÉPONSE**, et c'est là qu'un daemon le lit.
    let mut tampons = asl_proto::cadrage::TamponsReponse::nouveaux();
    let lue = asl_proto::Reponse::decoder(&rendu, &mut tampons).expect("une réponse lisible");
    assert_eq!(
        lue.bail.keepalive_secondes(),
        10,
        "le keepalive accordé n'est plus celui que la mesure a choisi"
    );
    assert_eq!(
        lue.bail.inactivite_secondes(),
        30,
        "l'inactivité accordée a changé sans que personne le dise"
    );
    // **TROIS KEEPALIVES MANQUÉS**, qui est la politique écrite dans
    // `modele.md` §4.1 — et aussi ce que le chemin tolère.
    assert_eq!(
        u32::from(lue.bail.inactivite_secondes()),
        u32::from(lue.bail.keepalive_secondes()).saturating_mul(3),
        "le rapport de trois pour un a changé sans que personne le dise"
    );
    assert!(
        u32::from(lue.bail.inactivite_secondes())
            >= u32::from(lue.bail.keepalive_secondes()).saturating_mul(2),
        "l'invariant du type : l'inactivité vaut au moins deux keepalives"
    );

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

#[tokio::test]
async fn un_daemon_qui_ne_fait_que_maintenir_garde_son_annonce() {
    // ── CE QUE CET ESSAI PROUVE, ET CE QU'IL A FALLU CORRIGER POUR LUI ──────
    //
    // `modele.md` §4.1 promet que « le mapping NAT reste ouvert par le keepalive
    // lui-même ». Deux choses manquaient pour que ce soit vrai :
    //
    //   1. **rien n'émettait de keepalive** — corrigé dans `ams-quic-tls` ;
    //   2. **l'annuaire ne le comptait pas comme un signe de vie.** Le bail se
    //      rafraîchissait dans `a_la_lecture`, c'est-à-dire « un flux est
    //      lisible ». **Un `PING` n'ouvre aucun flux** (§10.1.2 de RFC 9000) :
    //      un daemon qui tenait sa connexion voyait donc son annonce expirer
    //      sous lui, alors qu'il faisait exactement ce qu'on lui demande.
    //
    // Le bail de cet essai vaut une seconde de cadence pour deux d'inactivité :
    // avec celui du produit — dix et trente —, il faudrait attendre trente
    // secondes pour voir quoi que ce soit.
    let (autorite, racine, chaine, cle) = materiel("maintien");
    let (base, fichier) = entrepot("maintien");
    let bail = asl_proto::Bail::nouveau(1, 2).expect("un bail court");
    let (adresse, dire_stop, tache) = lever_avec_bail(&chaine, &cle, base, bail).await;

    let mut alice = connecter(&racine, adresse).await;
    let (compte, _appareil, _secrete) = creer_un_compte(&mut alice, 0, 0xA1).await;
    let (statut, rendu) = poster(
        &mut alice,
        8,
        b"/v1/machines",
        br#"{"nom":"grenier","capacites":["annonce","lecture"]}"#,
        b"application/json",
    )
    .await;
    assert_eq!(statut, b"201", "{}", String::from_utf8_lossy(&rendu));
    let machine = Identifiant::analyser(&valeur_json(&rendu, "machine")).expect("une machine");
    let code = valeur_json(&rendu, "code");

    let mut daemon = connecter(&racine, adresse).await;
    let secrete = asl_cle::CleSecrete::depuis_entropie([0xD4; 32]);
    assert_eq!(enroler(&mut daemon, 0, &code, &secrete).await, machine);
    authentifier(&mut daemon, machine, &secrete, 12, 16).await;

    let annonce = format!(
        r#"{{"machine":"{}","service":"depot","points":[{{"protocole":"tcp","port":49152}}]}}"#,
        machine.texte()
    );
    let (statut, _) = poster(
        &mut daemon,
        20,
        b"/v1/annonce",
        annonce.as_bytes(),
        b"application/json",
    )
    .await;
    assert_eq!(statut, b"200", "l'annonce est prise");

    // ── LE DAEMON SE TAIT, ET NE FAIT QUE MAINTENIR ─────────────────────────
    //
    // **AUCUNE REQUÊTE**, donc aucun flux lisible côté annuaire : c'est tout
    // l'objet. Cinq secondes, soit plus du double de l'inactivité du bail.
    //
    // **`0x01` EST UNE TRAME `PING`** (§19.2 de RFC 9000), et `dire` pose des
    // trames applicatives brutes. C'est le maintien le plus dépouillé qui
    // soit : un octet, aucun flux, rien à lire pour l'application d'en face.
    //
    // Le client d'essai n'a pas d'émetteur de maintien — c'est `ams-quic-tls`
    // qui en porte un, et ses propres essais l'éprouvent. Ce qui est éprouvé
    // ICI est l'autre moitié : que l'annuaire COMPTE ce datagramme.
    let jusqu_a = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
    while tokio::time::Instant::now() < jusqu_a {
        daemon.dire(&[0x01]);
        daemon.parler().await;
        daemon.ecouter().await;
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }
    assert!(
        daemon.ferme().is_none(),
        "la connexion du daemon doit tenir : il la maintient"
    );

    // ── ET L'ANNONCE EST TOUJOURS LÀ ────────────────────────────────────────
    //
    // **C'EST LE DAEMON QUI DEMANDE, ET APRÈS LA FENÊTRE DE SILENCE.** La
    // résolution exige une machine porteuse de `lecture` (`protocole.md` §3) :
    // `alice` est un APPAREIL, et l'annuaire lui rend `401`. C'est la bonne
    // règle — une autorisation de lecture accordée pour joindre un service ne
    // doit pas ouvrir l'administration d'un compte.
    let cible = format!("/v1/ou/{}/depot", machine.texte());
    ams_quic_client::envoyer_une_requete(&mut daemon, 28, 17, cible.as_bytes(), None, b"").await;
    let rendu = ams_quic_client::attendre_la_reponse(&mut daemon, 28).await;
    assert_eq!(
        champ(&champs(daemon.recu(28)), b":status"),
        Some(&b"200"[..]),
        "après cinq secondes de maintien seul, l'annonce doit tenir"
    );
    let texte = String::from_utf8_lossy(&rendu);
    assert!(
        texte.contains("49152"),
        "et porter le port annoncé : {texte}"
    );
    assert_ne!(compte, machine, "deux identifiants distincts");

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

// ── Effacer mon compte (`protocole.md` §2.2, `modele.md` §2.1) ───────────────

/// Prouve la clé d'un appareil (P-256) sur cette connexion, et rend le statut.
async fn prouver_l_appareil(
    client: &mut ams_quic_client::Client,
    appareil: Identifiant,
    secrete: &asl_cle::CleSecreteAppareil,
    flux: u64,
) -> Vec<u8> {
    let defi = tirer_le_defi(client, flux).await;
    let signature = secrete
        .signer(appareil, &defi, &liaison_du_client(client))
        .expect("l'appareil signe");
    let mut preuve = Vec::with_capacity(81);
    preuve.push(Genre::Appareil.prefixe());
    preuve.extend_from_slice(appareil.octets());
    preuve.extend_from_slice(signature.octets());
    let suivant = flux.saturating_add(4);
    ams_quic_client::envoyer_avec_media(
        client,
        suivant,
        20,
        b"/v1/defi",
        None,
        &preuve,
        b"application/octet-stream",
    )
    .await;
    let _ = ams_quic_client::attendre_la_reponse(client, suivant).await;
    champ(&champs(client.recu(suivant)), b":status")
        .expect("un statut")
        .to_vec()
}

/// Le statut d'un `GET` sans corps sur cette cible, depuis une connexion neuve.
async fn statut_de(racine: &[u8], adresse: SocketAddr, cible: &str) -> Vec<u8> {
    let mut client = connecter(racine, adresse).await;
    ams_quic_client::envoyer_une_requete(&mut client, 0, 17, cible.as_bytes(), None, b"").await;
    let _ = ams_quic_client::attendre_la_reponse(&mut client, 0).await;
    champ(&champs(client.recu(0)), b":status")
        .expect("un statut")
        .to_vec()
}

/// Laisse passer des tours de boucle jusqu'à ce que cette connexion tombe, ou
/// que la patience s'épuise. Rend `true` si elle est tombée.
async fn attendre_la_fermeture(client: &mut ams_quic_client::Client) -> bool {
    for _ in 0..64_u32 {
        client.parler().await;
        if !client.ecouter().await {
            break;
        }
    }
    client.ferme().is_some()
}

#[tokio::test]
async fn effacer_mon_compte_retire_tout_ferme_les_connexions_et_le_compte_devient_inconnu() {
    // ── CE QUE CET ESSAI PROUVE ─────────────────────────────────────────────
    //
    // `protocole.md` §2.2 : `DELETE /v1/compte`, depuis un appareil vivant,
    // rend `204` puis l'annuaire ferme la connexion ; tout ce que le compte
    // tenait part dans une transaction — la machine et ses services, l'alias,
    // l'autorisation accordée à Bob — ; et le compte est un inconnu pour
    // qui tient encore son `u-…`.
    let (autorite, racine, chaine, cle) = materiel("effacer");
    let (base, fichier) = entrepot("effacer");
    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;

    // Alice : un compte, un alias, une machine enrôlée qui annonce, une
    // autorisation accordée à Bob.
    let mut alice = connecter(&racine, adresse).await;
    let (compte, appareil, secrete_alice) = creer_un_compte(&mut alice, 0, 0xA7).await;
    ams_quic_client::envoyer_avec_media(
        &mut alice,
        8,
        21,
        b"/v1/alias",
        None,
        br#"{"alias":"alice-qui-part"}"#,
        b"application/json",
    )
    .await;
    let _ = ams_quic_client::attendre_la_reponse(&mut alice, 8).await;
    assert_eq!(champ(&champs(alice.recu(8)), b":status"), Some(&b"204"[..]));
    let (statut, rendu) = poster(
        &mut alice,
        12,
        b"/v1/machines",
        br#"{"nom":"grenier","capacites":["annonce","lecture"]}"#,
        b"application/json",
    )
    .await;
    assert_eq!(statut, b"201", "{}", String::from_utf8_lossy(&rendu));
    let machine = Identifiant::analyser(&valeur_json(&rendu, "machine")).expect("une machine");
    let code = valeur_json(&rendu, "code");

    let mut bob = connecter(&racine, adresse).await;
    let (compte_bob, _appareil_bob, _secrete_bob) = creer_un_compte(&mut bob, 0, 0xB7).await;
    let demande = format!(
        r#"{{"a":"{}","portee":"tout","etiquette":"pour Bob"}}"#,
        compte_bob.texte()
    );
    let (statut, rendu) = poster(
        &mut alice,
        16,
        b"/v1/autorisations",
        demande.as_bytes(),
        b"application/json",
    )
    .await;
    assert_eq!(statut, b"201", "{}", String::from_utf8_lossy(&rendu));

    let mut daemon = connecter(&racine, adresse).await;
    let secrete_daemon = asl_cle::CleSecrete::depuis_entropie([0xD7; 32]);
    assert_eq!(
        enroler(&mut daemon, 0, &code, &secrete_daemon).await,
        machine
    );
    authentifier(&mut daemon, machine, &secrete_daemon, 8, 12).await;
    let annonce = format!(
        r#"{{"machine":"{}","service":"depot","points":[{{"protocole":"tcp","port":49152}}]}}"#,
        machine.texte()
    );
    let (statut, _) = poster(
        &mut daemon,
        16,
        b"/v1/annonce",
        annonce.as_bytes(),
        b"application/json",
    )
    .await;
    assert_eq!(statut, b"200", "l'annonce est prise");

    // Avant : le compte existe, l'alias répond, Bob voit son autorisation.
    assert_eq!(
        statut_de(
            &racine,
            adresse,
            &format!("/v1/utilisateurs/{}", compte.texte())
        )
        .await,
        b"200"
    );
    assert_eq!(
        statut_de(&racine, adresse, "/v1/alias/alice-qui-part").await,
        b"200"
    );

    // ── L'EFFACEMENT : `204`, PUIS LA CONNEXION TOMBE ───────────────────────
    //
    // `16` est l'index QPACK de `:method: DELETE`.
    ams_quic_client::envoyer_une_requete(&mut alice, 20, 16, b"/v1/compte", None, b"").await;
    let _ = ams_quic_client::attendre_la_reponse(&mut alice, 20).await;
    assert_eq!(
        champ(&champs(alice.recu(20)), b":status"),
        Some(&b"204"[..]),
        "le compte est effacé"
    );
    assert!(
        attendre_la_fermeture(&mut alice).await,
        "la connexion qui a porté la demande est fermée par l'annuaire"
    );
    assert!(
        attendre_la_fermeture(&mut daemon).await,
        "la connexion de la machine du compte est fermée — son bail tombe avec"
    );
    // Et le journal d'exploitation l'a dit, avec l'identifiant et la cause.
    let dit = JOURNAL
        .lock()
        .expect("le journal n'est pas empoisonné")
        .iter()
        .any(|ligne| {
            ligne.contains(&format!("compte {} effacé", compte.texte()))
                && ligne.contains("cause titulaire")
        });
    assert!(
        dit,
        "le journal d'exploitation dit l'effacement et sa cause"
    );

    // ── APRÈS : UN INCONNU, UN ALIAS LIBRE, RIEN CHEZ BOB ───────────────────
    assert_eq!(
        statut_de(
            &racine,
            adresse,
            &format!("/v1/utilisateurs/{}", compte.texte())
        )
        .await,
        b"404",
        "le même 404 qu'un identifiant qui n'a jamais existé"
    );
    assert_eq!(
        statut_de(&racine, adresse, "/v1/alias/alice-qui-part").await,
        b"404",
        "l'alias est libéré"
    );
    ams_quic_client::envoyer_une_requete(&mut bob, 8, 17, b"/v1/autorisations", None, b"").await;
    let rendu = ams_quic_client::attendre_la_reponse(&mut bob, 8).await;
    assert_eq!(champ(&champs(bob.recu(8)), b":status"), Some(&b"200"[..]));
    assert_eq!(
        String::from_utf8_lossy(&rendu),
        "[]",
        "l'autre partie ne voit plus rien — pas même une ligne révoquée"
    );
    // La clé de l'appareil ne vaut plus, celle de la machine non plus.
    let mut encore = connecter(&racine, adresse).await;
    assert_eq!(
        prouver_l_appareil(&mut encore, appareil, &secrete_alice, 0).await,
        b"401",
        "la clé qui a demandé est révoquée"
    );
    let mut daemon = connecter(&racine, adresse).await;
    ams_quic_client::envoyer_une_requete(&mut daemon, 0, 17, b"/v1/defi", None, b"").await;
    let octets = ams_quic_client::attendre_la_reponse(&mut daemon, 0).await;
    let mut brut = [0_u8; asl_cle::DEFI_OCTETS];
    brut.copy_from_slice(&octets);
    let defi = asl_cle::Defi::depuis_octets(brut);
    let signature = secrete_daemon
        .signer(machine, &defi, &liaison_du_client(&daemon))
        .expect("elle signe");
    let mut preuve = Vec::with_capacity(81);
    preuve.push(Genre::Machine.prefixe());
    preuve.extend_from_slice(machine.octets());
    preuve.extend_from_slice(signature.octets());
    ams_quic_client::envoyer_avec_media(
        &mut daemon,
        4,
        20,
        b"/v1/defi",
        None,
        &preuve,
        b"application/octet-stream",
    )
    .await;
    let _ = ams_quic_client::attendre_la_reponse(&mut daemon, 4).await;
    assert_eq!(
        champ(&champs(daemon.recu(4)), b":status"),
        Some(&b"401"[..]),
        "la machine du compte effacé ne peut plus se connecter"
    );
    // Bob, lui, est intact.
    assert_eq!(
        statut_de(
            &racine,
            adresse,
            &format!("/v1/utilisateurs/{}", compte_bob.texte())
        )
        .await,
        b"200"
    );

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

#[tokio::test]
async fn un_compte_orphelin_est_efface_au_passage_et_pas_un_compte_vivant() {
    // ── CE QUE CET ESSAI PROUVE ─────────────────────────────────────────────
    //
    // `modele.md` §2.1, la règle des orphelins : un compte dont TOUS les
    // appareils sont révoqués depuis plus de `--orphans` jours est effacé par
    // la racine, au premier passage — au démarrage — ; un compte dont un
    // appareil est vivant ne l'est pas ; et `--orphans 0` n'efface jamais.
    let (autorite, racine, chaine, cle) = materiel("orphelins");
    let jour = 24 * 60 * 60 * 1_000_u64;
    let maintenant = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |ecoule| {
            u64::try_from(ecoule.as_millis()).unwrap_or(u64::MAX)
        });
    let orphelin = Identifiant::depuis_entropie(Genre::Utilisateur, [0x61; 16]);
    let vivant = Identifiant::depuis_entropie(Genre::Utilisateur, [0x62; 16]);

    /// Garnit l'entrepôt : l'orphelin a deux appareils révoqués il y a
    /// quarante et trente et un jours ; le vivant en a un révoqué il y a
    /// quarante jours, et un vivant.
    fn garnir(base: &Entrepot, orphelin: Identifiant, vivant: Identifiant, maintenant: u64) {
        let jour = 24 * 60 * 60 * 1_000_u64;
        for (qui, graine, second_revoque) in [(orphelin, 0x61_u8, true), (vivant, 0x62, false)] {
            base.creer_compte(
                qui,
                Provenance::Ici,
                Some(AliasRange::nouveau(&format!("compte-{graine:x}")).unwrap()),
            )
            .expect("compte");
            let premier = Identifiant::depuis_entropie(Genre::Appareil, [graine; 16]);
            let second = Identifiant::depuis_entropie(Genre::Appareil, [graine ^ 0xFF; 16]);
            for quel in [premier, second] {
                base.creer_appareil(
                    quel,
                    Provenance::Ici,
                    qui,
                    [graine; 33],
                    asl_registre::Attestation::Aucune,
                )
                .expect("appareil");
            }
            base.revoquer_appareil(premier, maintenant - 40 * jour)
                .expect("révoqué");
            if second_revoque {
                base.revoquer_appareil(second, maintenant - 31 * jour)
                    .expect("révoqué");
            }
            machine_enrolee(
                base,
                Identifiant::depuis_entropie(Genre::Machine, [graine; 16]),
                qui,
                asl_cle::CleSecrete::depuis_entropie([graine; 32])
                    .publique()
                    .octets(),
                TOUT,
            );
        }
    }

    // ── `--orphans 30` : L'ORPHELIN PART AU PREMIER PASSAGE, LE VIVANT RESTE ─
    let (base, fichier) = entrepot("orphelins-trente");
    garnir(&base, orphelin, vivant, maintenant);
    let (adresse, dire_stop, tache) = lever_complet(
        &chaine,
        &cle,
        base,
        asl_proto::Bail::nouveau(10, 30).expect("un bail"),
        asl_auth::Politique::AttestationFacultative,
        Attestations::AUCUNE,
        Some(30 * jour),
    )
    .await;
    assert_eq!(
        statut_de(
            &racine,
            adresse,
            &format!("/v1/utilisateurs/{}", orphelin.texte())
        )
        .await,
        b"404",
        "l'orphelin est effacé au passage du démarrage"
    );
    assert_eq!(
        statut_de(&racine, adresse, "/v1/alias/compte-61").await,
        b"404",
        "son alias est libre"
    );
    assert_eq!(
        statut_de(
            &racine,
            adresse,
            &format!("/v1/utilisateurs/{}", vivant.texte())
        )
        .await,
        b"200",
        "un appareil vivant suffit : le compte reste"
    );
    // Sa machine ne se connecte plus ; celle du vivant, si.
    for (graine, attendu) in [(0x61_u8, &b"401"[..]), (0x62, &b"204"[..])] {
        let mut client = connecter(&racine, adresse).await;
        let machine = Identifiant::depuis_entropie(Genre::Machine, [graine; 16]);
        let secrete = asl_cle::CleSecrete::depuis_entropie([graine; 32]);
        ams_quic_client::envoyer_une_requete(&mut client, 0, 17, b"/v1/defi", None, b"").await;
        let octets = ams_quic_client::attendre_la_reponse(&mut client, 0).await;
        let mut brut = [0_u8; asl_cle::DEFI_OCTETS];
        brut.copy_from_slice(&octets);
        let defi = asl_cle::Defi::depuis_octets(brut);
        let signature = secrete
            .signer(machine, &defi, &liaison_du_client(&client))
            .expect("elle signe");
        let mut preuve = Vec::with_capacity(81);
        preuve.push(Genre::Machine.prefixe());
        preuve.extend_from_slice(machine.octets());
        preuve.extend_from_slice(signature.octets());
        ams_quic_client::envoyer_avec_media(
            &mut client,
            4,
            20,
            b"/v1/defi",
            None,
            &preuve,
            b"application/octet-stream",
        )
        .await;
        let _ = ams_quic_client::attendre_la_reponse(&mut client, 4).await;
        assert_eq!(
            champ(&champs(client.recu(4)), b":status"),
            Some(attendu),
            "machine {graine:x}"
        );
    }
    let dit = JOURNAL
        .lock()
        .expect("le journal n'est pas empoisonné")
        .iter()
        .any(|ligne| {
            ligne.contains(&format!("compte {} effacé", orphelin.texte()))
                && ligne.contains("cause orphelin")
        });
    assert!(
        dit,
        "le journal d'exploitation dit l'effacement et sa cause"
    );
    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_file(&fichier);

    // ── `--orphans 0` : JAMAIS ──────────────────────────────────────────────
    let (base, fichier) = entrepot("orphelins-jamais");
    garnir(&base, orphelin, vivant, maintenant);
    let (adresse, dire_stop, tache) = lever(&chaine, &cle, base).await;
    assert_eq!(
        statut_de(
            &racine,
            adresse,
            &format!("/v1/utilisateurs/{}", orphelin.texte())
        )
        .await,
        b"200",
        "sans délai, la racine n'efface jamais"
    );
    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

// ── Attester un appareil qui rejoint ────────────────────────────────────────

/// Les réglages Android du Fairphone 5 : la racine de Google, notre paquet,
/// l'empreinte de la build de débogage — de quoi que l'annuaire ESSAIE de
/// vérifier une chaîne, et la refuse quand elle ne remonte pas.
fn reglages_android_du_fp5() -> (Vec<u8>, Attestations<'static>) {
    let (case_reelle, google) = capture_android();
    let racines: &'static [Vec<u8>] = Box::leak(vec![google].into_boxed_slice());
    let mut signataire = [0_u8; 32];
    for (place, paire) in signataire.iter_mut().zip(
        "5ea316f1b50f2ce54b8225aba85ff5cc8238a710b8fae44b4f3a195aadeb5f68"
            .as_bytes()
            .chunks(2),
    ) {
        *place = u8::from_str_radix(std::str::from_utf8(paire).expect("ascii"), 16)
            .expect("hexadécimal");
    }
    let android = Some(ConfigAndroid {
        racines,
        paquet: "org.airdesktop.servicelocator",
        signataire,
    });
    (
        case_reelle,
        Attestations {
            apple: None,
            android,
        },
    )
}

/// Un appareil déjà enrôlé apporte la clé d'un nouvel appareil, et rend
/// l'identifiant que l'annuaire lui a attribué.
async fn apporter_une_cle(
    client: &mut ams_quic_client::Client,
    flux: u64,
    nouvelle: &asl_cle::CleSecreteAppareil,
) -> (Vec<u8>, Option<Identifiant>) {
    let (statut, rendu) = poster(
        client,
        flux,
        b"/v1/appareils",
        &nouvelle.publique().octets(),
        b"application/octet-stream",
    )
    .await;
    let appareil = (statut == b"201")
        .then(|| Identifiant::analyser(&valeur_json(&rendu, "appareil")).expect("un identifiant"));
    (statut, appareil)
}

/// Le nouvel appareil prouve sa clé ET présente sa chaîne, d'un même défi :
/// `GET /v1/defi` sur `flux`, puis `POST /v1/attestation` sur le suivant.
async fn attester(
    client: &mut ams_quic_client::Client,
    flux: u64,
    appareil: Identifiant,
    secrete: &asl_cle::CleSecreteAppareil,
    plateforme: PlateformeAttestation,
    chaine: &[u8],
) -> Vec<u8> {
    let defi = tirer_le_defi(client, flux).await;
    let preuve = secrete
        .signer(appareil, &defi, &liaison_du_client(client))
        .expect("l'appareil signe");
    let objet = asl_api::corps::AttestationDAppareil {
        appareil,
        preuve: preuve.octets(),
        plateforme,
        attestation: chaine,
    };
    let mut tampon = vec![0_u8; asl_api::corps::ATTESTATION_CORPS_MAX];
    let n = objet.encoder(&mut tampon).expect("un corps bien formé");
    let (statut, _) = poster(
        client,
        flux.saturating_add(4),
        b"/v1/attestation",
        &tampon[..n],
        b"application/octet-stream",
    )
    .await;
    statut
}

/// Ce que `GET /v1/appareils` dit de cet appareil, depuis cette connexion.
async fn attestation_rendue(
    client: &mut ams_quic_client::Client,
    flux: u64,
    appareil: Identifiant,
) -> asl_api::corps::AttestationRendue {
    ams_quic_client::envoyer_une_requete(client, flux, 17, b"/v1/appareils", None, b"").await;
    let rendu = ams_quic_client::attendre_la_reponse(client, flux).await;
    assert_eq!(
        champ(&champs(client.recu(flux)), b":status"),
        Some(&b"200"[..])
    );
    let texte = String::from_utf8_lossy(&rendu).into_owned();
    let objets = texte
        .strip_prefix('[')
        .and_then(|reste| reste.strip_suffix(']'))
        .unwrap_or_else(|| panic!("une liste : {texte}"));
    // Les objets sont séparés par `},{` ; chacun se relit avec le décodeur
    // des liaisons.
    objets
        .split("},{")
        .map(|morceau| {
            let mut entier = String::new();
            if !morceau.starts_with('{') {
                entier.push('{');
            }
            entier.push_str(morceau);
            if !morceau.ends_with('}') {
                entier.push('}');
            }
            let lu = asl_api::corps::AppareilRendu::decoder(entier.as_bytes())
                .unwrap_or_else(|faute| panic!("{entier} : {faute}"));
            (lu.appareil, lu.attestation)
        })
        .find(|(quel, _)| *quel == appareil)
        .unwrap_or_else(|| panic!("{appareil} absent de {texte}"))
        .1
}

#[tokio::test]
async fn un_appareil_qui_rejoint_prouve_sa_cle_et_presente_sa_chaine_sous_une_posture_facultative()
{
    // ── CE QUE CET ESSAI PROUVE ─────────────────────────────────────────────
    //
    // `protocole.md` §2.2, « Attester un appareil qui rejoint » : l'ancien
    // appareil apporte la clé (`POST /v1/appareils`, `201`, `aucune`) ; le
    // nouveau, sur SA connexion, tire un défi puis `POST /v1/attestation`
    // avec sa preuve et sa chaîne. Sous une posture facultative, une chaîne
    // que l'annuaire ne peut pas prouver — celle du Fairphone 5, amputée de
    // ce que le harnais ne sait pas porter — rend `204` quand même :
    // l'appareil reste `aucune`, la connexion est authentifiée, le journal
    // dit le refus. Une preuve nue passe aussi. Une signature fausse, un
    // appareil révoqué : `401`, le même.
    let (autorite, racine, chaine, cle) = materiel("rejoindre-facultative");
    let (base, fichier) = entrepot("rejoindre-facultative");
    let bail = asl_proto::Bail::nouveau(10, 30).expect("un bail");
    let (case_reelle, attestations) = reglages_android_du_fp5();
    let (adresse, dire_stop, tache) = lever_complet(
        &chaine,
        &cle,
        base,
        bail,
        asl_auth::Politique::AttestationFacultative,
        attestations,
        None,
    )
    .await;

    // L'ancien appareil : un compte, sa connexion authentifiée.
    let mut ancien = connecter(&racine, adresse).await;
    let (_compte, _appareil_ancien, _secrete_ancien) = creer_un_compte(&mut ancien, 0, 0xA1).await;

    // Le nouveau : sa connexion, son défi AVANT sa clé — l'ordre du Keystore.
    let mut nouveau = connecter(&racine, adresse).await;
    let _defi = tirer_le_defi(&mut nouveau, 0).await;
    let secrete_nouveau =
        asl_cle::CleSecreteAppareil::depuis_entropie([0xB1; 32]).expect("un scalaire valide");

    // L'ancien apporte la clé : `201`, et l'appareil entre `aucune`.
    let (statut, appareil) = apporter_une_cle(&mut ancien, 8, &secrete_nouveau).await;
    assert_eq!(statut, b"201");
    let appareil = appareil.expect("un identifiant");
    assert_eq!(
        attestation_rendue(&mut ancien, 12, appareil).await,
        asl_api::corps::AttestationRendue::Aucune
    );

    // Le nouveau prouve et présente sa chaîne, sur la connexion tenue depuis
    // le défi — le défi fixe du banc rend le second tirage égal au premier.
    assert_eq!(
        attester(
            &mut nouveau,
            4,
            appareil,
            &secrete_nouveau,
            PlateformeAttestation::Android,
            &case_reelle
        )
        .await,
        b"204",
        "posture facultative : la chaîne refusée ne ferme pas la porte"
    );
    // La connexion est celle de l'appareil : il lit son compte, et se voit
    // `aucune` — la chaîne n'a rien prouvé.
    assert_eq!(
        attestation_rendue(&mut nouveau, 12, appareil).await,
        asl_api::corps::AttestationRendue::Aucune
    );
    {
        let journal = JOURNAL.lock().expect("le journal n'est pas empoisonné");
        assert!(
            journal
                .iter()
                .any(|ligne| ligne.starts_with("attestation refusée : Android, ")),
            "le journal dit pourquoi la chaîne n'a pas été acceptée"
        );
        assert!(
            journal.iter().any(|ligne| ligne
                == &format!(
                    "appareil {appareil} : chaîne refusée, posture facultative : reste sans preuve"
                )),
            "et ce qu'il en est advenu"
        );
    }

    // Une preuve nue sur ce verbe vaut `POST /v1/defi` : `204`.
    let mut encore = connecter(&racine, adresse).await;
    assert_eq!(
        attester(
            &mut encore,
            0,
            appareil,
            &secrete_nouveau,
            PlateformeAttestation::Aucune,
            &[]
        )
        .await,
        b"204"
    );

    // Une signature d'une autre clé : `401`, et le défi est dépensé — la
    // même preuve refaite sans défi rend encore `401`.
    let mut intrus = connecter(&racine, adresse).await;
    let autre = asl_cle::CleSecreteAppareil::depuis_entropie([0xC1; 32]).expect("un scalaire");
    assert_eq!(
        attester(
            &mut intrus,
            0,
            appareil,
            &autre,
            PlateformeAttestation::Android,
            &case_reelle
        )
        .await,
        b"401"
    );

    // Révoqué par l'ancien : sa preuve, nue ou avec chaîne, rend `401`.
    let cible = format!("/v1/appareils/{}", appareil.texte());
    ams_quic_client::envoyer_une_requete(&mut ancien, 16, 16, cible.as_bytes(), None, b"").await;
    let _ = ams_quic_client::attendre_la_reponse(&mut ancien, 16).await;
    assert_eq!(
        champ(&champs(ancien.recu(16)), b":status"),
        Some(&b"204"[..]),
        "révoqué"
    );
    let mut revoque = connecter(&racine, adresse).await;
    assert_eq!(
        attester(
            &mut revoque,
            0,
            appareil,
            &secrete_nouveau,
            PlateformeAttestation::Android,
            &case_reelle
        )
        .await,
        b"401",
        "un appareil révoqué ne s'atteste plus"
    );
    assert_eq!(
        prouver_l_appareil(&mut revoque, appareil, &secrete_nouveau, 8).await,
        b"401",
        "et sa preuve nue non plus"
    );

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}

#[tokio::test]
async fn sous_une_posture_exigee_un_appareil_apporte_est_attendu_jusqu_a_sa_chaine() {
    // ── CE QUE CET ESSAI PROUVE ─────────────────────────────────────────────
    //
    // La table des postures de `protocole.md` §2.2 : sous `required`,
    // `POST /v1/appareils` écrit `attendue` là où il refusait ; la preuve nue
    // du nouvel appareil rend `401`, comme une clé révoquée ; sa chaîne
    // refusée rend `403`, et il reste `attendue` — visible dans Appareils,
    // révocable. Un appareil `aucune` d'hier, sur cette racine, reste servi :
    // la posture qualifie l'entrée, jamais ce qui est déjà entré.
    let (autorite, racine, chaine, cle) = materiel("rejoindre-exigee");
    let (base, fichier) = entrepot("rejoindre-exigee");
    // L'ancien appareil est entré `aucune` sous une posture d'hier : on le
    // range à la main, puisque `POST /v1/comptes` ne l'admettrait plus.
    let compte = Identifiant::depuis_entropie(Genre::Utilisateur, [0xA2; 16]);
    let appareil_ancien = Identifiant::depuis_entropie(Genre::Appareil, [0xA3; 16]);
    let secrete_ancien =
        asl_cle::CleSecreteAppareil::depuis_entropie([0xA4; 32]).expect("un scalaire valide");
    base.creer_compte(compte, asl_registre::Provenance::Ici, None)
        .expect("le compte");
    base.creer_appareil(
        appareil_ancien,
        asl_registre::Provenance::Ici,
        compte,
        secrete_ancien.publique().octets(),
        asl_registre::Attestation::Aucune,
    )
    .expect("l'appareil d'hier");
    let bail = asl_proto::Bail::nouveau(10, 30).expect("un bail");
    let (case_reelle, attestations) = reglages_android_du_fp5();
    let (adresse, dire_stop, tache) = lever_complet(
        &chaine,
        &cle,
        base,
        bail,
        asl_auth::Politique::AttestationExigee,
        attestations,
        None,
    )
    .await;

    let mut ancien = connecter(&racine, adresse).await;
    assert_eq!(
        prouver_l_appareil(&mut ancien, appareil_ancien, &secrete_ancien, 0).await,
        b"204",
        "un appareil `aucune` d'hier reste servi"
    );

    let mut nouveau = connecter(&racine, adresse).await;
    let _defi = tirer_le_defi(&mut nouveau, 0).await;
    let secrete_nouveau =
        asl_cle::CleSecreteAppareil::depuis_entropie([0xB2; 32]).expect("un scalaire valide");

    // Apporté : `201`, et `attendue` — pas refusé.
    let (statut, appareil) = apporter_une_cle(&mut ancien, 8, &secrete_nouveau).await;
    assert_eq!(
        statut, b"201",
        "sous `required`, la clé est apportée quand même"
    );
    let appareil = appareil.expect("un identifiant");
    assert_eq!(
        attestation_rendue(&mut ancien, 12, appareil).await,
        asl_api::corps::AttestationRendue::Attendue
    );

    // Sa preuve nue : `401`, il n'est pas entré — par `/v1/defi` comme par
    // `/v1/attestation` sans chaîne.
    let mut nu = connecter(&racine, adresse).await;
    assert_eq!(
        prouver_l_appareil(&mut nu, appareil, &secrete_nouveau, 0).await,
        b"401"
    );
    assert_eq!(
        attester(
            &mut nu,
            8,
            appareil,
            &secrete_nouveau,
            PlateformeAttestation::Aucune,
            &[]
        )
        .await,
        b"401"
    );

    // Sa chaîne, que l'annuaire ne peut pas prouver : `403`, il reste
    // `attendue`, et la connexion n'est pas authentifiée.
    assert_eq!(
        attester(
            &mut nouveau,
            4,
            appareil,
            &secrete_nouveau,
            PlateformeAttestation::Android,
            &case_reelle
        )
        .await,
        b"403"
    );
    ams_quic_client::envoyer_une_requete(&mut nouveau, 12, 17, b"/v1/appareils", None, b"").await;
    let _ = ams_quic_client::attendre_la_reponse(&mut nouveau, 12).await;
    assert_eq!(
        champ(&champs(nouveau.recu(12)), b":status"),
        Some(&b"401"[..]),
        "la connexion du nouveau n'est pas authentifiée"
    );
    assert_eq!(
        attestation_rendue(&mut ancien, 16, appareil).await,
        asl_api::corps::AttestationRendue::Attendue,
        "il reste attendu — visible, et révocable"
    );
    {
        let journal = JOURNAL.lock().expect("le journal n'est pas empoisonné");
        assert!(
            journal.iter().any(|ligne| ligne
                == &format!("appareil {appareil} : chaîne refusée, posture exigée : refusé")),
            "le journal dit le refus"
        );
    }

    let _ = dire_stop.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&fichier);
}
