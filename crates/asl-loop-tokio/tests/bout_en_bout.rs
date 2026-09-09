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
use asl_loop_tokio::{Annuaire, Comptes, configuration_tls, servir_quic};

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

/// Lance l'écoute sur une socket éphémère, et rend son adresse et de quoi
/// l'arrêter.
async fn lever(
    chaine: &[u8],
    cle: &[u8],
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
        let mut application = Annuaire::new();
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
    let (adresse, dire_stop, tache) = lever(&chaine, &cle).await;

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
}

#[tokio::test]
async fn une_cible_inconnue_revient_en_404_et_non_en_501() {
    // **LES DEUX REFUS DOIVENT SE DISTINGUER SUR LE FIL**, et pas seulement dans
    // un essai unitaire : `404` dit « cette cible ne désigne rien », `501` dit
    // « elle désigne quelque chose que je ne sais pas encore servir ». Les
    // confondre ferait chercher une faute d'URL là où il n'y en a pas.
    let (autorite, racine, chaine, cle) = materiel("inconnue");
    let (adresse, dire_stop, tache) = lever(&chaine, &cle).await;

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
}
