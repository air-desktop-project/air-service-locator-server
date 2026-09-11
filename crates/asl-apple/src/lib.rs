//! Ce qu'une attestation App Attest PROUVE.
//!
//! `asl-attest` dit ce que les octets CONTIENNENT. Cette crate dit s'ils
//! prouvent qu'une clé vit dans le matériel sécurisé d'un appareil d'Apple —
//! et, si oui, LAQUELLE.
//!
//! # CE QU'ELLE VÉRIFIE, DANS L'ORDRE, ET POURQUOI CET ORDRE
//!
//! La documentation d'Apple énumère neuf pas. Ils sont tous là ; ils ne sont
//! pas dans son ordre. **Ce qui ne demande que les octets d'`authData` passe en
//! premier**, avant la chaîne :
//!
//!   1. la grammaire ;
//!   2. le drapeau ATTESTE est levé — sinon il n'y a pas de clé à certifier ;
//!   3. le compteur est à zéro — une attestation est la PREMIÈRE signature ;
//!   4. l'`aaguid` est celui de l'environnement attendu ;
//!   5. le `rpIdHash` est l'empreinte de l'identifiant d'app attendu ;
//!   6. la chaîne `x5c` remonte à la racine, à l'instant donné ;
//!   7. la feuille porte une clé P-256 et le nonce d'Apple ;
//!   8. le nonce est `SHA-256(authData ‖ SHA-256(défi))` ;
//!   9. l'identifiant de clé est `SHA-256(clé publique de la feuille)`.
//!
//! L'ordre n'a AUCUN effet sur ce qui est accepté : tout doit passer. Il a un
//! effet sur ce qui est DIT quand quelque chose échoue, et sur ce que les
//! essais peuvent fabriquer. Un essai qui veut voir le pas 3 refuser n'a qu'à
//! changer un octet d'`authData` ; s'il fallait d'abord passer le pas 8, il
//! devrait aussi signer une feuille dont le nonce couvre cet octet changé.
//!
//! # LA RACINE EST UN PARAMÈTRE
//!
//! [`RACINE_APPLE`] est la vraie, telle qu'Apple la publie. Mais [`verifier`]
//! prend la racine en argument, parce qu'une attestation réelle ne peut pas
//! servir d'essai : personne ici n'a la clé d'Apple, et on ne pourrait donc en
//! fabriquer qu'une — la bonne. Les refus demandent des certificats qu'Apple ne
//! signera jamais. Les essais signent donc les leurs, sous leur propre racine.
//!
//! # CE QUE CETTE CRATE NE SAIT PAS
//!
//! **AUCUNE CAPTURE RÉELLE N'A ÉTÉ LUE.** La forme de l'extension, la courbe de
//! la feuille, la présence ou non d'un `extendedKeyUsage`, l'ordre des
//! certificats dans `x5c` : tout vient de la documentation. Ce qui est éprouvé
//! ici est que la vérification fait ce qu'elle dit sur une chaîne fabriquée
//! d'après cette documentation. **Le premier iPhone tranchera**, et jusque-là
//! `--attestation exigee` refuserait peut-être des appareils légitimes.

#![no_std]

mod signature;
pub mod x509;

use core::time::Duration;

use asl_attest::{DonneesAuth, ObjetAttestation};
use rustls_pki_types::{CertificateDer, UnixTime};
use sha2::{Digest, Sha256};
use webpki::{
    EndEntityCert, ExtendedKeyUsageValidator, KeyPurposeIdIter, anchor_from_trusted_cert,
};

pub use x509::POINT_OCTETS;

/// La racine d'Apple pour App Attest, en DER, telle que publiée à
/// <https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem>.
///
/// `CN=Apple App Attestation Root CA, O=Apple Inc., ST=California`, P-384,
/// valable jusqu'au 15 mars 2045. Empreinte SHA-256 :
/// `1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932` — un
/// essai la recalcule, pour qu'un octet changé ici ne passe pas inaperçu.
pub const RACINE_APPLE: &[u8] = include_bytes!("apple-app-attestation-root-ca.der");

/// La taille d'un condensat SHA-256, et donc d'un nonce, d'un identifiant de
/// clé, d'une empreinte d'app.
pub const CONDENSAT_OCTETS: usize = 32;

/// L'`aaguid` d'une attestation de production.
pub const AAGUID_PRODUCTION: &[u8; 16] = b"appattest\0\0\0\0\0\0\0";

/// L'`aaguid` d'une attestation de développement — Xcode, TestFlight.
pub const AAGUID_DEVELOPPEMENT: &[u8; 16] = b"appattestdevelop";

/// L'environnement d'où l'attestation doit venir.
///
/// **Ce n'est pas une nuance.** Une attestation de développement vient d'une
/// app signée par un certificat de développeur, sur un appareil enrôlé dans
/// une équipe — n'importe quelle équipe. Accepter les deux en production
/// reviendrait à accepter l'app de n'importe qui.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environnement {
    /// L'App Store, ou une distribution d'entreprise.
    Production,
    /// Xcode et TestFlight.
    Developpement,
}

impl Environnement {
    /// L'`aaguid` que cet environnement écrit dans `authData`.
    #[must_use]
    pub const fn aaguid(self) -> &'static [u8; 16] {
        match self {
            Self::Production => AAGUID_PRODUCTION,
            Self::Developpement => AAGUID_DEVELOPPEMENT,
        }
    }
}

/// Ce que le serveur SAIT, et à quoi l'attestation doit correspondre.
#[derive(Debug, Clone, Copy)]
pub struct Attendu<'a> {
    /// La racine, en DER. [`RACINE_APPLE`] en production.
    pub racine: &'a [u8],
    /// Le défi que le serveur a émis, et que l'appareil a dû couvrir.
    pub defi: &'a [u8],
    /// L'identifiant d'app : `<équipe>.<bundle>`, tel qu'Apple le forme.
    pub identifiant_app: &'a str,
    /// L'environnement attendu.
    pub environnement: Environnement,
    /// L'instant, en secondes depuis l'époque — la validité des certificats
    /// s'apprécie à cet instant, et à aucun autre.
    pub maintenant: u64,
}

/// Ce que l'attestation certifie, une fois tout vérifié.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Certifie {
    /// La clé publique P-256 de l'appareil, point non compressé.
    pub cle: [u8; POINT_OCTETS],
    /// Son identifiant : `SHA-256(cle)`. C'est ce que l'appareil enverra
    /// avec chaque assertion.
    pub identifiant: [u8; CONDENSAT_OCTETS],
}

/// Pourquoi une attestation ne prouve rien.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refus {
    /// Les octets ne forment pas une attestation.
    Grammaire(asl_attest::Erreur),
    /// Le drapeau ATTESTE n'est pas levé : rien à certifier.
    PasDeCleAttestee,
    /// Le compteur n'est pas à zéro.
    Compteur {
        /// Ce qu'il vaut.
        compteur: u32,
    },
    /// L'`aaguid` n'est pas celui de l'environnement attendu.
    Environnement,
    /// Le `rpIdHash` n'est pas l'empreinte de l'identifiant d'app attendu.
    App,
    /// `x5c` est vide : aucun certificat, donc rien à remonter.
    ChaineVide,
    /// La racine donnée n'est pas un certificat.
    RacineIllisible,
    /// La feuille n'est pas un certificat que `webpki` accepte de lire.
    FeuilleIllisible,
    /// La chaîne ne remonte pas à la racine, à cet instant.
    Chaine(webpki::Error),
    /// La feuille est bien signée mais n'a pas la forme de RFC 5280 là où
    /// `webpki` ne regarde pas.
    CertificatIllisible,
    /// La clé de la feuille n'est pas un point P-256.
    CleInattendue,
    /// La feuille ne porte pas l'extension d'Apple.
    NonceAbsent,
    /// Le nonce ne couvre pas ces `authData` et ce défi.
    NonceDifferent,
    /// L'identifiant de clé n'est pas l'empreinte de la clé de la feuille.
    IdentifiantDifferent,
}

impl From<asl_attest::Erreur> for Refus {
    fn from(erreur: asl_attest::Erreur) -> Self {
        Self::Grammaire(erreur)
    }
}

impl core::fmt::Display for Refus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Grammaire(erreur) => write!(f, "attestation illisible : {erreur}"),
            Self::PasDeCleAttestee => write!(f, "aucune clé attestée"),
            Self::Compteur { compteur } => write!(f, "compteur à {compteur}, zéro attendu"),
            Self::Environnement => write!(f, "aaguid d'un autre environnement"),
            Self::App => write!(f, "empreinte d'une autre app"),
            Self::ChaineVide => write!(f, "chaîne de certificats vide"),
            Self::RacineIllisible => write!(f, "racine illisible"),
            Self::FeuilleIllisible => write!(f, "feuille illisible"),
            Self::Chaine(erreur) => write!(f, "chaîne refusée : {erreur}"),
            Self::CertificatIllisible => write!(f, "feuille sans la forme de RFC 5280"),
            Self::CleInattendue => write!(f, "clé de la feuille hors de P-256"),
            Self::NonceAbsent => write!(f, "extension d'Apple absente de la feuille"),
            Self::NonceDifferent => write!(f, "nonce d'un autre défi ou d'autres données"),
            Self::IdentifiantDifferent => write!(f, "identifiant d'une autre clé"),
        }
    }
}

/// `webpki` exige de dire quel `extendedKeyUsage` on attend. **Aucun.**
///
/// Les feuilles d'App Attest ne sont ni des serveurs ni des clients TLS, et
/// la documentation d'Apple ne leur prête aucun `extendedKeyUsage`. En
/// l'absence de capture, exiger quoi que ce soit serait deviner ; on n'exige
/// rien, et la chaîne reste vérifiée pour tout le reste.
struct SansExigence;

impl ExtendedKeyUsageValidator for SansExigence {
    fn validate(&self, _: KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        Ok(())
    }
}

/// Vérifie une attestation, et rend ce qu'elle certifie.
///
/// # Erreurs
///
/// Un [`Refus`] nommé, au premier pas qui échoue.
pub fn verifier(objet: &[u8], attendu: &Attendu<'_>) -> Result<Certifie, Refus> {
    let objet = ObjetAttestation::lire(objet)?;
    let cle_attestee = donnees_coherentes(&objet.auth, attendu)?;

    let feuille_der = *objet.chaine().first().ok_or(Refus::ChaineVide)?;
    remonter_la_chaine(feuille_der, objet.chaine().get(1..).unwrap_or(&[]), attendu)?;

    let feuille = x509::lire(feuille_der)?;
    let nonce = feuille.nonce.ok_or(Refus::NonceAbsent)?;
    let attendu_nonce = Sha256::new()
        .chain_update(objet.donnees_auth)
        .chain_update(Sha256::digest(attendu.defi))
        .finalize();
    if nonce != attendu_nonce.as_slice() {
        return Err(Refus::NonceDifferent);
    }

    let identifiant = Sha256::digest(feuille.cle);
    if cle_attestee != identifiant.as_slice() {
        return Err(Refus::IdentifiantDifferent);
    }

    let mut cle = [0_u8; POINT_OCTETS];
    cle.copy_from_slice(feuille.cle);
    Ok(Certifie {
        cle,
        identifiant: identifiant.into(),
    })
}

/// Les pas 2 à 5 : ce qu'`authData` doit dire, avant toute cryptographie.
/// Rend l'identifiant de clé attesté.
fn donnees_coherentes<'a>(
    auth: &DonneesAuth<'a>,
    attendu: &Attendu<'_>,
) -> Result<&'a [u8], Refus> {
    let cle = auth.cle.ok_or(Refus::PasDeCleAttestee)?;
    if auth.compteur != 0 {
        return Err(Refus::Compteur {
            compteur: auth.compteur,
        });
    }
    if cle.aaguid != attendu.environnement.aaguid() {
        return Err(Refus::Environnement);
    }
    if auth.empreinte_app != Sha256::digest(attendu.identifiant_app.as_bytes()).as_slice() {
        return Err(Refus::App);
    }
    Ok(cle.identifiant)
}

/// Le pas 6 : `webpki` remonte de la feuille à la racine, à l'instant donné.
fn remonter_la_chaine(
    feuille: &[u8],
    intermediaires: &[&[u8]],
    attendu: &Attendu<'_>,
) -> Result<(), Refus> {
    let racine = CertificateDer::from(attendu.racine);
    let ancre = anchor_from_trusted_cert(&racine).map_err(|_| Refus::RacineIllisible)?;
    let ancres = [ancre];

    let feuille = CertificateDer::from(feuille);
    let feuille = EndEntityCert::try_from(&feuille).map_err(|_| Refus::FeuilleIllisible)?;

    // Au plus trois intermédiaires : Apple en met un. Sans tas, une borne.
    let mut tampon: [CertificateDer<'_>; 3] = [
        CertificateDer::from(&[][..]),
        CertificateDer::from(&[][..]),
        CertificateDer::from(&[][..]),
    ];
    let combien = intermediaires.len().min(tampon.len());
    for (case, der) in tampon.iter_mut().zip(intermediaires) {
        *case = CertificateDer::from(*der);
    }
    let intermediaires = tampon.get(..combien).unwrap_or(&[]);

    feuille
        .verify_for_usage(
            &signature::ALGORITHMES,
            &ancres,
            intermediaires,
            UnixTime::since_unix_epoch(Duration::from_secs(attendu.maintenant)),
            SansExigence,
            None,
            None,
        )
        .map(|_| ())
        .map_err(Refus::Chaine)
}
