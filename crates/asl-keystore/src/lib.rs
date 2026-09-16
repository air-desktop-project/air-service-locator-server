//! Ce qu'une attestation de clé Android PROUVE.
//!
//! Le Keystore d'Android sait attester une clé qu'il a générée : il émet une
//! chaîne de certificats dont la feuille porte la clé publique et une extension
//! (`1.3.6.1.4.1.11129.2.1.17`, la `KeyDescription`) qui dit où la clé vit, sous
//! quel démarrage, pour quelle app, et contre quel défi. La chaîne remonte à
//! la racine du fabricant du matériel — Google pour un Android certifié,
//! GrapheneOS pour les siens. Cette crate dit si une telle chaîne prouve que
//! **la clé qu'on enrôle vit dans le matériel d'un appareil sain, tenue par
//! notre app** — et rien n'est appelé pour le dire (C19) : la racine est un
//! fichier que l'exploitant épingle (`--android-roots`).
//!
//! # CE QU'ELLE VÉRIFIE, DANS L'ORDRE, ET POURQUOI CET ORDRE
//!
//!   1. la case du fil se découpe en certificats ([`case`]) ;
//!   2. la chaîne remonte à l'une des racines épinglées, à l'instant donné
//!      (`rustls-webpki`, avec les vérificateurs de `signature.rs`) ;
//!   3. la feuille porte une clé P-256 et la `KeyDescription` ([`x509`]) ;
//!   4. la `KeyDescription` se lit ([`description`]) ;
//!   5. la clé de la feuille EST la clé qu'on enrôle ;
//!   6. `attestationChallenge` est le défi attendu —
//!      `SHA-256(asl_cle::message_d_attestation_de_cle(défi, liaison))`, SANS
//!      la clé : il est posé à la génération, avant qu'elle existe, et c'est
//!      le certificat qui la porte (point 5) ;
//!   7. `attestationSecurityLevel` ET `keymasterSecurityLevel` sont matériels
//!      (TEE ou StrongBox) ;
//!   8. `rootOfTrust`, côté matériel : démarrage `Verified`, bootloader
//!      verrouillé ;
//!   9. `origin`, côté matériel : `GENERATED` — la clé est née là, personne ne
//!      l'a importée ;
//!  10. `attestationApplicationId` porte NOTRE paquet ET NOTRE empreinte de
//!      signature.
//!
//! **La chaîne d'abord**, contrairement à `asl-apple` : ici tout ce qu'on lit
//! est DANS la feuille, et lire une feuille que personne n'a signée ne dirait
//! rien. L'ordre n'a aucun effet sur ce qui est accepté — tout doit passer — ;
//! il a un effet sur ce qui est DIT quand quelque chose échoue.
//!
//! # CE QUI EST RENDU, PAS JUGÉ
//!
//! Le niveau de correctif (`osPatchLevel`, `vendorPatchLevel`,
//! `bootPatchLevel`) et la version d'Android sont dans le [`Verdict`], et
//! aucune politique ne les juge encore : `protocole.md` §2.1 la remet à après
//! la capture, et la capture est là — c'est une décision à prendre à part. La
//! liste de révocation de Google (`attestation/status`) n'est pas consultée :
//! ce serait un tiers appelé.
//!
//! # LES RACINES SONT UN PARAMÈTRE, ET LA CAPTURE RÉELLE EST UN ESSAI
//!
//! Les essais fabriquent leur propre chaîne sous leur propre racine, comme
//! `asl-apple` — Google ne signera jamais une feuille au défi faux, et c'est
//! ainsi que chaque refus est éprouvé. **Mais ici, une chaîne réelle a été
//! lue** : celle du Fairphone 5 du 2026-09-16, sous la racine de Google, et
//! c'est un essai de cette crate. Ce que la documentation disait de la forme a
//! été confronté à ce qu'un appareil envoie.

#![no_std]

extern crate alloc;

pub mod case;
pub mod der;
pub mod description;
mod signature;
pub mod x509;

use alloc::vec::Vec;
use core::time::Duration;

use rustls_pki_types::{CertificateDer, UnixTime};
use webpki::{
    EndEntityCert, ExtendedKeyUsageValidator, KeyPurposeIdIter, anchor_from_trusted_cert,
};

pub use description::{Demarrage, Description, Niveau, Origine};
pub use x509::POINT_OCTETS;

/// La taille d'une clé d'appareil sur le fil : un point P-256 compressé.
pub const CLE_OCTETS: usize = 33;

/// La taille d'un condensat SHA-256 : le défi attendu, l'empreinte de
/// signature.
pub const CONDENSAT_OCTETS: usize = 32;

/// Ce que le serveur SAIT, et à quoi l'attestation doit correspondre.
#[derive(Debug, Clone, Copy)]
pub struct Attendu<'a> {
    /// Les racines épinglées, en DER — au moins une. La chaîne doit remonter
    /// à l'une d'elles.
    pub racines: &'a [&'a [u8]],
    /// Le défi que la clé a dû recevoir à sa génération :
    /// `SHA-256(message_d_attestation_de_cle(défi, liaison))` — sans la clé,
    /// que le certificat porte.
    pub defi: &'a [u8],
    /// La clé qu'on enrôle, P-256 compressée, telle que le fil la porte.
    pub cle: &'a [u8; CLE_OCTETS],
    /// Le nom de notre paquet Android, `org.airdesktop.servicelocator`.
    pub paquet: &'a str,
    /// L'empreinte SHA-256 du certificat qui signe notre build.
    pub empreinte: &'a [u8; CONDENSAT_OCTETS],
    /// L'instant, en secondes depuis l'époque — la validité des certificats
    /// s'apprécie à cet instant, et à aucun autre.
    pub maintenant: u64,
}

/// Ce que l'attestation certifie, une fois tout vérifié.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// La clé publique P-256 de l'appareil, point non compressé — celle du
    /// fil, décompressée par la feuille.
    pub cle: [u8; POINT_OCTETS],
    /// Où l'attestation a été produite.
    pub niveau_attestation: Niveau,
    /// Où la clé vit.
    pub niveau_keymaster: Niveau,
    /// La version du schéma de `KeyDescription`.
    pub version: u64,
    /// La version de KeyMint/Keymaster.
    pub version_keymaster: u64,
    /// `osVersion`, si le matériel ou Android l'a dit.
    pub version_os: Option<u64>,
    /// `osPatchLevel` — RENDU, PAS JUGÉ : la politique reste à écrire.
    pub correctif_os: Option<u64>,
    /// `vendorPatchLevel`.
    pub correctif_fabricant: Option<u64>,
    /// `bootPatchLevel`.
    pub correctif_demarrage: Option<u64>,
    /// Le `versionCode` de la build de notre app qui tient la clé.
    pub version_du_paquet: u64,
}

/// Pourquoi une attestation ne prouve rien.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refus {
    /// La case du fil ne se découpe pas.
    Case(case::Faute),
    /// Aucune racine épinglée : rien à quoi remonter.
    SansRacine,
    /// Une racine donnée n'est pas un certificat.
    RacineIllisible,
    /// La feuille n'est pas un certificat que `webpki` accepte de lire.
    FeuilleIllisible,
    /// La chaîne ne remonte à aucune racine, à cet instant.
    Chaine(webpki::Error),
    /// La feuille est bien signée mais n'a pas la forme de RFC 5280 là où
    /// `webpki` ne regarde pas.
    CertificatIllisible,
    /// La clé de la feuille n'est pas un point P-256.
    CleInattendue,
    /// La feuille ne porte pas l'extension d'attestation.
    DescriptionAbsente,
    /// L'extension est là, mais ne se lit pas.
    DescriptionIllisible(description::Faute),
    /// La clé de la feuille n'est pas celle qu'on enrôle.
    CleDifferente,
    /// `attestationChallenge` n'est pas le défi attendu.
    DefiDifferent,
    /// L'attestation elle-même n'a pas été produite dans du matériel.
    AttestationLogicielle(Niveau),
    /// La clé ne vit pas dans du matériel.
    CleLogicielle(Niveau),
    /// Le matériel ne dit rien du démarrage.
    RacineDeConfianceAbsente,
    /// Le démarrage n'est pas `Verified`.
    DemarrageNonVerifie(Demarrage),
    /// Le bootloader est déverrouillé.
    AppareilDeverrouille,
    /// Le matériel ne dit pas d'où vient la clé.
    OrigineAbsente,
    /// La clé n'a pas été générée là : importée, dérivée…
    OrigineInattendue(Origine),
    /// Aucun `attestationApplicationId` : on ne sait pas quelle app tient la
    /// clé.
    ApplicationAbsente,
    /// Aucun des paquets n'est le nôtre.
    AutrePaquet,
    /// Aucune des empreintes de signature n'est la nôtre — une autre build,
    /// ou une app qui se fait passer pour la nôtre.
    AutreSignataire,
}

impl From<case::Faute> for Refus {
    fn from(faute: case::Faute) -> Self {
        Self::Case(faute)
    }
}

impl From<description::Faute> for Refus {
    fn from(faute: description::Faute) -> Self {
        Self::DescriptionIllisible(faute)
    }
}

impl core::fmt::Display for Refus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Case(faute) => write!(f, "case illisible : {faute}"),
            Self::SansRacine => f.write_str("aucune racine épinglée"),
            Self::RacineIllisible => f.write_str("racine illisible"),
            Self::FeuilleIllisible => f.write_str("feuille illisible"),
            Self::Chaine(erreur) => write!(f, "chaîne refusée : {erreur}"),
            Self::CertificatIllisible => f.write_str("feuille sans la forme de RFC 5280"),
            Self::CleInattendue => f.write_str("clé de la feuille hors de P-256"),
            Self::DescriptionAbsente => f.write_str("extension d'attestation absente"),
            Self::DescriptionIllisible(faute) => write!(f, "KeyDescription illisible : {faute}"),
            Self::CleDifferente => f.write_str("clé de la feuille différente de la clé enrôlée"),
            Self::DefiDifferent => f.write_str("défi d'attestation différent du défi attendu"),
            Self::AttestationLogicielle(niveau) => {
                write!(f, "attestation produite hors du matériel ({niveau})")
            }
            Self::CleLogicielle(niveau) => write!(f, "clé hors du matériel ({niveau})"),
            Self::RacineDeConfianceAbsente => f.write_str("rootOfTrust absent côté matériel"),
            Self::DemarrageNonVerifie(etat) => write!(f, "démarrage {etat}, vérifié attendu"),
            Self::AppareilDeverrouille => f.write_str("bootloader déverrouillé"),
            Self::OrigineAbsente => f.write_str("origine de la clé absente côté matériel"),
            Self::OrigineInattendue(origine) => {
                write!(f, "clé {origine}, générée attendue")
            }
            Self::ApplicationAbsente => f.write_str("attestationApplicationId absent"),
            Self::AutrePaquet => f.write_str("clé tenue par un autre paquet"),
            Self::AutreSignataire => f.write_str("app signée par un autre certificat"),
        }
    }
}

/// `webpki` exige de dire quel `extendedKeyUsage` on attend. **Aucun.**
///
/// La feuille du Keystore n'en porte pas (capture du 2026-09-16 : `keyUsage`
/// `digitalSignature` seul), ni les intermédiaires de TEE. On n'exige rien, et
/// la chaîne reste vérifiée pour tout le reste.
struct SansExigence;

impl ExtendedKeyUsageValidator for SansExigence {
    fn validate(&self, _: KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        Ok(())
    }
}

/// Vérifie une case d'attestation, et rend ce qu'elle certifie.
///
/// # Erreurs
///
/// Un [`Refus`] nommé, au premier pas qui échoue.
pub fn verifier(case: &[u8], attendu: &Attendu<'_>) -> Result<Verdict, Refus> {
    let chaine = case::decouper(case)?;
    remonter_la_chaine(chaine.feuille, &chaine.intermediaires, attendu)?;

    let feuille = x509::lire(chaine.feuille)?;
    let description = description::lire(feuille.description.ok_or(Refus::DescriptionAbsente)?)?;

    let mut cle = [0_u8; POINT_OCTETS];
    cle.copy_from_slice(feuille.cle);
    if x509::compresser(&cle) != *attendu.cle {
        return Err(Refus::CleDifferente);
    }
    if description.defi != attendu.defi {
        return Err(Refus::DefiDifferent);
    }
    if !description.niveau_attestation.est_materiel() {
        return Err(Refus::AttestationLogicielle(description.niveau_attestation));
    }
    if !description.niveau_keymaster.est_materiel() {
        return Err(Refus::CleLogicielle(description.niveau_keymaster));
    }

    // **CÔTÉ MATÉRIEL, ET SEULEMENT LÀ.** Ce qu'Android écrit dans
    // `softwareEnforced`, un Android modifié peut l'écrire aussi ; ce que le
    // TEE écrit dans `teeEnforced`, lui seul le signe.
    let materiel = &description.materiel;
    let racine = materiel
        .racine_de_confiance
        .ok_or(Refus::RacineDeConfianceAbsente)?;
    if racine.demarrage != Demarrage::Verifie {
        return Err(Refus::DemarrageNonVerifie(racine.demarrage));
    }
    if !racine.verrouille {
        return Err(Refus::AppareilDeverrouille);
    }
    let origine = materiel.origine.ok_or(Refus::OrigineAbsente)?;
    if origine != Origine::Generee {
        return Err(Refus::OrigineInattendue(origine));
    }

    // `attestationApplicationId` est écrit par Android (`softwareEnforced`),
    // jamais par le TEE : c'est le seul champ jugé qu'on lit côté logiciel, et
    // c'est inhérent au schéma. Ce qu'il prouve tient à ce que le démarrage
    // vérifié ci-dessus garantit l'Android qui l'a écrit.
    let application = description
        .logiciel
        .application
        .as_ref()
        .or(materiel.application.as_ref())
        .ok_or(Refus::ApplicationAbsente)?;
    let paquet = application
        .paquets
        .iter()
        .find(|paquet| paquet.nom == attendu.paquet.as_bytes())
        .ok_or(Refus::AutrePaquet)?;
    if !application
        .empreintes
        .iter()
        .any(|empreinte| *empreinte == attendu.empreinte)
    {
        return Err(Refus::AutreSignataire);
    }

    let logiciel = &description.logiciel;
    Ok(Verdict {
        cle,
        niveau_attestation: description.niveau_attestation,
        niveau_keymaster: description.niveau_keymaster,
        version: description.version,
        version_keymaster: description.version_keymaster,
        version_os: materiel.version_os.or(logiciel.version_os),
        correctif_os: materiel.correctif_os.or(logiciel.correctif_os),
        correctif_fabricant: materiel
            .correctif_fabricant
            .or(logiciel.correctif_fabricant),
        correctif_demarrage: materiel
            .correctif_demarrage
            .or(logiciel.correctif_demarrage),
        version_du_paquet: paquet.version,
    })
}

/// Le pas 2 : `webpki` remonte de la feuille à l'une des racines, à l'instant
/// donné.
fn remonter_la_chaine(
    feuille: &[u8],
    intermediaires: &[&[u8]],
    attendu: &Attendu<'_>,
) -> Result<(), Refus> {
    if attendu.racines.is_empty() {
        return Err(Refus::SansRacine);
    }
    let racines: Vec<CertificateDer<'_>> = attendu
        .racines
        .iter()
        .map(|der| CertificateDer::from(*der))
        .collect();
    let ancres = racines
        .iter()
        .map(anchor_from_trusted_cert)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Refus::RacineIllisible)?;

    let feuille = CertificateDer::from(feuille);
    let feuille = EndEntityCert::try_from(&feuille).map_err(|_| Refus::FeuilleIllisible)?;
    let intermediaires: Vec<CertificateDer<'_>> = intermediaires
        .iter()
        .map(|der| CertificateDer::from(*der))
        .collect();

    feuille
        .verify_for_usage(
            &signature::ALGORITHMES,
            &ancres,
            &intermediaires,
            UnixTime::since_unix_epoch(Duration::from_secs(attendu.maintenant)),
            SansExigence,
            None,
            None,
        )
        .map(|_| ())
        .map_err(Refus::Chaine)
}
