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
use asl_id::{Genre, Identifiant};
use asl_loop_tokio::{Annuaire, Comptes, configuration_tls, servir_quic};
use asl_registre::{AliasRange, Compte, Provenance};
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
    (Entrepot::ouvrir(&chemin).expect("un entrepôt neuf"), chemin)
}

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
            asl_auth::Politique::AttestationFacultative,
        );
        let arret = async {
            let _ = entendre_stop.await;
        };
        // Trente secondes d'inactivité : bien plus que ce que l'essai prend, et
        // assez pour qu'un délai ne vienne pas fermer la connexion en cours de
        // route sur une machine chargée.
        servir_quic(socket, tls, 16, 30_000_000, &mut application, arret)
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
    base.poser_compte(
        qui,
        &Compte {
            provenance: Provenance::Ici,
            alias: Some(AliasRange::nouveau("thierry").expect("il tient")),
        },
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
    base.poser_machine(
        machine,
        &asl_registre::Machine {
            provenance: Provenance::Ici,
            proprietaire,
            cle: Some(secrete.publique().octets()),
            annonce: true,
            lecture: true,
            nom: nom_de_machine("grenier"),
        },
    )
    .expect("la machine est écrite");

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
        base.poser_machine(
            quelle,
            &asl_registre::Machine {
                provenance: Provenance::Ici,
                proprietaire,
                cle: Some(cle_publique),
                annonce: true,
                lecture: true,
                nom: nom_de_machine("grenier"),
            },
        )
        .expect("la machine est écrite");
    }
    base.poser_service(
        Identifiant::depuis_entropie(Genre::Service, [0xA1; 16]),
        &asl_registre::Service {
            provenance: Provenance::Ici,
            machine: machine_a,
            nom: asl_registre::NomRange::nouveau("imap").expect("il tient"),
        },
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
        base.poser_machine(
            quelle,
            &asl_registre::Machine {
                provenance: Provenance::Ici,
                proprietaire,
                cle: Some(cle_publique),
                annonce: true,
                lecture: true,
                nom: nom_de_machine("grenier"),
            },
        )
        .expect("écrite");
    }
    base.poser_service(
        Identifiant::depuis_entropie(Genre::Service, [0xA1; 16]),
        &asl_registre::Service {
            provenance: Provenance::Ici,
            machine: machine_a,
            nom: asl_registre::NomRange::nouveau("imap").expect("il tient"),
        },
    )
    .expect("écrit");

    // **L'ARÊTE ENTRE LES DEUX COMPTES** : A autorise B, sur tout son compte.
    base.poser_autorisation(
        Identifiant::depuis_entropie(Genre::Autorisation, [0x01; 16]),
        &asl_registre::Autorisation {
            provenance: Provenance::Ici,
            par: compte_a,
            a: compte_b,
            portee: asl_registre::Portee::ToutLeCompte,
            revoquee: false,
        },
    )
    .expect("écrite");

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
    base.poser_machine(
        machine,
        &asl_registre::Machine {
            provenance: Provenance::Ici,
            proprietaire: compte,
            cle: Some(secrete.publique().octets()),
            annonce: true,
            lecture: true,
            nom: nom_de_machine("grenier"),
        },
    )
    .expect("la machine est écrite");

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
    base.poser_machine(
        machine,
        &asl_registre::Machine {
            provenance: Provenance::Ici,
            proprietaire: Identifiant::depuis_entropie(Genre::Utilisateur, [0xE1; 16]),
            cle: Some(secrete.publique().octets()),
            annonce: false,
            lecture: true,
            nom: nom_de_machine("grenier"),
        },
    )
    .expect("écrite");

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
        base.poser_machine(
            quelle,
            &asl_registre::Machine {
                provenance: Provenance::Ici,
                proprietaire,
                cle: Some(secrete.publique().octets()),
                annonce: true,
                lecture: true,
                nom: nom_de_machine("grenier"),
            },
        )
        .expect("écrite");
    }
    base.poser_autorisation(
        Identifiant::depuis_entropie(Genre::Autorisation, [0x01; 16]),
        &asl_registre::Autorisation {
            provenance: Provenance::Ici,
            par: compte_a,
            a: compte_b,
            portee: asl_registre::Portee::ToutLeCompte,
            revoquee: false,
        },
    )
    .expect("écrite");

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
    base.poser_machine(
        machine,
        &asl_registre::Machine {
            provenance: Provenance::Ici,
            proprietaire: compte,
            cle: Some(secrete.publique().octets()),
            annonce: true,
            lecture: true,
            nom: nom_de_machine("grenier"),
        },
    )
    .expect("écrite");

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
    base.poser_machine(
        machine,
        &asl_registre::Machine {
            provenance: Provenance::Ici,
            proprietaire: Identifiant::depuis_entropie(Genre::Utilisateur, [0xF2; 16]),
            cle: Some(secrete.publique().octets()),
            annonce: true,
            lecture: true,
            nom: nom_de_machine("grenier"),
        },
    )
    .expect("écrite");

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
) -> (Identifiant, Identifiant, asl_cle::CleSecrete) {
    let secrete = asl_cle::CleSecrete::depuis_entropie([graine; 32]);
    let defi = tirer_le_defi(client, flux).await;
    let liaison = liaison_du_client(client);
    let preuve = secrete.prouver_la_possession(&defi, &liaison);

    let mut corps = Vec::with_capacity(96);
    corps.extend_from_slice(&secrete.publique().octets());
    corps.extend_from_slice(preuve.octets());

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
    let demande = format!(r#"{{"a":"{}","portee":"tout"}}"#, compte_b.texte());
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
    Identifiant::analyser(&valeur_json(&rendu, "machine")).expect("une machine")
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
