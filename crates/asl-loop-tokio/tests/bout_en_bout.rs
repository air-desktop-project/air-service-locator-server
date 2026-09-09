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
    let liaison = asl_loop_tokio::liaison_du_certificat(chaine).expect("un certificat de tête");
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
        let mut application = Annuaire::new(&entrepot, liaison, &tirer, &nommer);
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
    // `/v1/expositions` SE ROUTE et sert `GET` : la réponse doit donc être le
    // `501` d'une ressource qui n'a pas encore d'entrepôt — et non un `404`,
    // qui dirait que la cible n'existe pas.
    ams_quic_client::envoyer_une_requete(&mut client, 0, 17, b"/v1/expositions", None, b"").await;
    // **ELLE NE REND QUE LE CORPS** : le harnais jette les en-têtes après les
    // avoir validés. Elle sert donc à ATTENDRE, et le flux brut se lit à côté.
    let corps = ams_quic_client::attendre_la_reponse(&mut client, 0).await;
    let brut = client.recu(0).to_vec();

    let champs = champs(&brut);
    assert_eq!(
        champ(&champs, b":status"),
        Some(&b"501"[..]),
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
        corps.windows(3).any(|f| f == b"501"),
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
            cle: secrete.publique().octets(),
            annonce: true,
            lecture: true,
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
    // Le client lie sa signature au certificat qu'il a VÉRIFIÉ — ici, la
    // racine n'en porte qu'un, celui du serveur de banc.
    let liaison = asl_loop_tokio::liaison_du_certificat(&chaine).expect("un certificat de tête");
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
    chaine: &[u8],
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

    let liaison = asl_loop_tokio::liaison_du_certificat(chaine).expect("un certificat de tête");
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
                cle: cle_publique,
                annonce: true,
                lecture: true,
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
    authentifier(&mut client, &chaine, machine_b, &secrete_b, 0, 4).await;

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
                cle: cle_publique,
                annonce: true,
                lecture: true,
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
    authentifier(&mut client, &chaine, machine_b, &secrete_b, 0, 4).await;

    ams_quic_client::envoyer_une_requete(&mut client, 8, 17, cible.as_bytes(), None, b"").await;
    let _ = ams_quic_client::attendre_la_reponse(&mut client, 8).await;
    let apres = champs(client.recu(8));
    assert_eq!(
        champ(&apres, b":status"),
        Some(&b"501"[..]),
        "l'autorisation ouvre l'accès ; il n'y a simplement rien à servir tant \
         qu'aucune annonce n'est rangée : {apres:?}"
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
            cle: secrete.publique().octets(),
            annonce: true,
            lecture: true,
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
    authentifier(&mut client, &chaine, machine, &secrete, 0, 4).await;

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
            cle: secrete.publique().octets(),
            annonce: false,
            lecture: true,
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
    authentifier(&mut client, &chaine, machine, &secrete, 0, 4).await;

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
