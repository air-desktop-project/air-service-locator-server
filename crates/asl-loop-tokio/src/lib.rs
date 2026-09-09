//! La boucle d'entrées-sorties sur tokio : sockets, horloge, et rien qui décide.
//!
//! # Pourquoi le moteur est dans le NOM de la crate
//!
//! Il n'y a AUCUNE abstraction d'exécution ici, et ce n'est pas un oubli. Le jour
//! où ce service tournera sur le stack Air, il aura une deuxième boucle — écrite
//! contre `air-async`, dans une autre crate — qui pilotera LA MÊME machine à
//! états. Rien à adapter, rien à maintenir entre les deux, et la logique du
//! service n'est écrite qu'une fois.
//!
//! Une couche d'abstraction, elle, devrait être maintenue pour les deux, et
//! finirait par ne convenir à aucun.
//!
//! # CE QUI A ÉTÉ REPRIS D'`air-mail-server`, ET CE QUI NE L'A PAS ÉTÉ
//!
//! La pile QUIC et HTTP/3 est reprise ENTIÈRE et sans une ligne modifiée :
//! `ams-proto-quic`, `ams-quic-crypto`, `ams-quic`, `ams-quic-tls`,
//! `ams-proto-h3`, `ams-h3`. C'est possible parce qu'aucune ne fait
//! d'entrée-sortie : `ams-quic` annonce en tête de son manifeste « la machine de
//! connexion QUIC, **sans entrée-sortie** ».
//!
//! **`ams-loop-tokio` n'est PAS reprise**, et c'est ce qui justifie cette crate.
//! Son `serve_quic` est générique par sa forme, mais il est tissé avec
//! `ams-guard` — le garde anti-abus du serveur de courrier — et avec sa notion
//! de source. Le reprendre ferait entrer ici les décisions d'un autre produit.
//!
//! **`ams-quic-client` non plus.** Malgré son nom, ce n'est pas une bibliothèque
//! cliente : elle expose un `atelier()` qui crée un répertoire temporaire, un
//! `materiel()` qui fabrique des certificats, des identifiants de connexion
//! fixes, et une constante qui annonce qu'elle EXIGE openssl. C'est un harnais
//! d'essai — et c'est comme tel qu'on l'emploie, en dépendance de
//! développement, pour éprouver cette boucle de bout en bout.
//!
//! # LES TROIS PIÈCES
//!
//! | Module | Ce qu'il fait |
//! |---|---|
//! | [`quic`] | La socket, la carte des connexions, la boucle, l'extinction. |
//! | [`pont`] | Marie `ams_h3::Transport` et `ams_quic_tls::Connection`. |
//! | [`h3`] | Présente `asl-session` à `ams-h3`, connexion par connexion. |
//! | [`privileges`] | Le refus de tourner en root (C8). |
//! | [`sonde`] | La joignabilité, mesurée — et seulement là où c'est SÛR. |
//! | [`vivier`] | L'état VIVANT des annonces — en mémoire, jamais sur disque. |
//!
//! # CE QUI MANQUE ENCORE
//!
//! L'entrepôt. `asl-session` route et refuse correctement ; tout ce qui se route
//! rend `501`, parce qu'aucune ressource de cette API ne se sert sans état.

pub mod h3;
pub mod pont;
pub mod privileges;
pub mod quic;
pub mod sonde;
pub mod vivier;

pub use h3::Annuaire;
pub use pont::Pont;
pub use privileges::{EstRoot, refuser_root};
pub use quic::{
    Application, Comptes, GRACE_EXTINCTION_US, SansApplication, maintenant, servir_quic,
};
pub use vivier::Vivier;

/// Monte la configuration TLS d'un annuaire, ALPN comprise.
///
/// # POURQUOI CETTE FONCTION EXISTE, ALORS QU'`ams-tls` FAIT DÉJÀ LE GROS
///
/// `ams_tls::quic_server_config` monte tout **sauf l'ALPN**, et le dit : « le
/// protocole applicatif est une décision de la couche du dessus ». Pour ce
/// produit, cette décision est déjà prise et il n'y en a qu'une — **nous ne
/// parlons que HTTP/3**.
///
/// Une configuration sans ALPN se construit, démarre, et échoue à la première
/// poignée de main : le client propose `h3`, le serveur n'offre rien, et §3.1 de
/// RFC 9114 impose l'échec. L'erreur arrive alors loin du fichier où l'oubli a
/// eu lieu.
///
/// **Ce qu'on ne peut pas exprimer ne peut pas être faux** : il n'y a pas de
/// paramètre, donc pas d'oubli possible.
///
/// # Errors
///
/// Chaîne illisible ou vide, clé illisible, ou clé qui ne correspond pas au
/// certificat de tête.
pub fn configuration_tls(
    chaine_pem: &[u8],
    cle_pem: &[u8],
) -> Result<rustls::ServerConfig, ams_tls::MaterialError> {
    let mut configuration = ams_tls::quic_server_config(chaine_pem, cle_pem)?;
    configuration.alpn_protocols = ams_tls::alpn_h3();
    Ok(configuration)
}

/// L'empreinte du certificat de tête, comme liaison de canal.
///
/// # POURQUOI CELUI DE TÊTE, ET POURQUOI CETTE FONCTION EXISTE
///
/// Une chaîne PEM porte le certificat du serveur **en premier**, puis ses
/// intermédiaires (§4.4.2 de RFC 8446). C'est le premier qui identifie ce
/// serveur-ci ; lier à un intermédiaire lierait à tous ceux qu'il a signés,
/// c'est-à-dire à rien de particulier.
///
/// La convention vit ici plutôt que chez l'appelant parce que **le client doit
/// appliquer la même**, et qu'une convention écrite deux fois finit par
/// différer. Voir `asl_cle::LiaisonDeCanal` pour ce que cette liaison ferme et
/// ce qu'elle ne ferme pas.
///
/// Rend `None` si la chaîne ne porte aucun certificat lisible — ce qui n'arrive
/// pas après [`configuration_tls`], qui l'aurait déjà refusée.
#[must_use]
pub fn liaison_du_certificat(chaine_pem: &[u8]) -> Option<asl_cle::LiaisonDeCanal> {
    use rustls::pki_types::pem::PemObject as _;

    let premier = rustls::pki_types::CertificateDer::pem_slice_iter(chaine_pem)
        .next()?
        .ok()?;
    Some(asl_cle::liaison_depuis_certificat(&premier))
}
