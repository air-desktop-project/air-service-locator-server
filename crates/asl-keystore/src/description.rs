//! La `KeyDescription` : ce que le Keystore dit de la clé qu'il atteste.
//!
//! # LE SCHÉMA, TEL QUE LA CAPTURE L'A MONTRÉ
//!
//! La documentation d'Android (« Key and ID Attestation ») donne ce schéma,
//! versionné (1, 2, 3, 4, 100, 200, 300, 400…) ; la chaîne réelle du Fairphone
//! 5 (2026-09-16, `docs/attestation/captures/keystore-fp5-2026-09-16/`) est en
//! version 3, et c'est elle qui a fixé ce lecteur :
//!
//! ```text
//! KeyDescription ::= SEQUENCE {
//!     attestationVersion         INTEGER,
//!     attestationSecurityLevel   ENUMERATED { Software(0), TrustedEnvironment(1), StrongBox(2) },
//!     keymasterVersion           INTEGER,
//!     keymasterSecurityLevel     ENUMERATED,
//!     attestationChallenge       OCTET STRING,
//!     uniqueId                   OCTET STRING,
//!     softwareEnforced           AuthorizationList,
//!     teeEnforced                AuthorizationList,
//! }
//! AuthorizationList ::= SEQUENCE {
//!     purpose                    [1]   EXPLICIT SET OF INTEGER OPTIONAL,
//!     algorithm                  [2]   EXPLICIT INTEGER OPTIONAL,
//!     keySize                    [3]   EXPLICIT INTEGER OPTIONAL,
//!     digest                     [5]   EXPLICIT SET OF INTEGER OPTIONAL,
//!     ecCurve                    [10]  EXPLICIT INTEGER OPTIONAL,
//!     noAuthRequired             [503] EXPLICIT NULL OPTIONAL,
//!     creationDateTime           [701] EXPLICIT INTEGER OPTIONAL,
//!     origin                     [702] EXPLICIT INTEGER OPTIONAL,
//!     rootOfTrust                [704] EXPLICIT RootOfTrust OPTIONAL,
//!     osVersion                  [705] EXPLICIT INTEGER OPTIONAL,
//!     osPatchLevel               [706] EXPLICIT INTEGER OPTIONAL,
//!     attestationApplicationId   [709] EXPLICIT OCTET STRING OPTIONAL,
//!     vendorPatchLevel           [718] EXPLICIT INTEGER OPTIONAL,
//!     bootPatchLevel             [719] EXPLICIT INTEGER OPTIONAL,
//!     …                          — et une trentaine d'autres, SAUTÉS
//! }
//! RootOfTrust ::= SEQUENCE {
//!     verifiedBootKey            OCTET STRING,
//!     deviceLocked               BOOLEAN,
//!     verifiedBootState          ENUMERATED { Verified(0), SelfSigned(1), Unverified(2), Failed(3) },
//!     verifiedBootHash           OCTET STRING,
//! }
//! ```
//!
//! `attestationApplicationId` est lui-même un DER dans l'OCTET STRING :
//!
//! ```text
//! AttestationApplicationId ::= SEQUENCE {
//!     packageInfos   SET OF SEQUENCE { packageName OCTET STRING, version INTEGER },
//!     signatureDigests SET OF OCTET STRING,
//! }
//! ```
//!
//! # LES BALISES INCONNUES SONT SAUTÉES, PAS REFUSÉES
//!
//! Le schéma bouge à chaque version d'Android — `[724] moduleHash` est arrivé
//! avec la 400. Un lecteur qui refuserait ce qu'il ne connaît pas refuserait le
//! prochain téléphone. Ce qu'on ne lit pas est compté ([`ListeAutorisations::sautees`])
//! et ne pèse en rien sur le verdict : la politique ne porte que sur ce qu'on
//! lit, et ce qu'on lit est vérifié strictement.
//!
//! **Ce que ce lecteur ne juge pas.** Il rend ce que l'extension DIT ; c'est
//! [`crate::verifier`] qui décide ce qui est acceptable. Le niveau de sécurité
//! d'une clé « logicielle » est lu et rendu comme les autres.

use alloc::vec::Vec;

use crate::der::{self, Balise, Classe, ENSEMBLE, ENTIER, ENUMERE, NUL, OCTETS, SEQUENCE};

/// Un niveau de sécurité (`SecurityLevel`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Niveau {
    /// `Software(0)` : la clé vit dans Android, pas dans du matériel.
    Logiciel,
    /// `TrustedEnvironment(1)` : le TEE.
    EnvironnementDeConfiance,
    /// `StrongBox(2)` : un élément sécurisé à part.
    StrongBox,
    /// Une valeur que ce lecteur ne connaît pas — rendue, jamais tenue pour
    /// matérielle.
    Autre(u64),
}

impl Niveau {
    const fn depuis(valeur: u64) -> Self {
        match valeur {
            0 => Self::Logiciel,
            1 => Self::EnvironnementDeConfiance,
            2 => Self::StrongBox,
            autre => Self::Autre(autre),
        }
    }

    /// La clé vit-elle dans du matériel — TEE ou StrongBox ?
    #[must_use]
    pub const fn est_materiel(self) -> bool {
        matches!(self, Self::EnvironnementDeConfiance | Self::StrongBox)
    }
}

impl core::fmt::Display for Niveau {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Logiciel => f.write_str("logiciel"),
            Self::EnvironnementDeConfiance => f.write_str("TEE"),
            Self::StrongBox => f.write_str("StrongBox"),
            Self::Autre(valeur) => write!(f, "inconnu ({valeur})"),
        }
    }
}

/// L'état du démarrage vérifié (`VerifiedBootState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Demarrage {
    /// `Verified(0)` : la chaîne de démarrage est celle du fabricant.
    Verifie,
    /// `SelfSigned(1)` : signée par une clé de l'utilisateur — un système
    /// alternatif, verrouillé sous sa propre clé.
    AutoSigne,
    /// `Unverified(2)` : bootloader déverrouillé.
    NonVerifie,
    /// `Failed(3)` : la vérification a échoué.
    Echec,
    /// Une valeur inconnue.
    Autre(u64),
}

impl Demarrage {
    const fn depuis(valeur: u64) -> Self {
        match valeur {
            0 => Self::Verifie,
            1 => Self::AutoSigne,
            2 => Self::NonVerifie,
            3 => Self::Echec,
            autre => Self::Autre(autre),
        }
    }
}

impl core::fmt::Display for Demarrage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Verifie => f.write_str("vérifié"),
            Self::AutoSigne => f.write_str("auto-signé"),
            Self::NonVerifie => f.write_str("non vérifié"),
            Self::Echec => f.write_str("en échec"),
            Self::Autre(valeur) => write!(f, "inconnu ({valeur})"),
        }
    }
}

/// D'où vient la clé (`KeyOrigin`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origine {
    /// `GENERATED(0)` : née dans le matériel, jamais sortie.
    Generee,
    /// `DERIVED(1)`.
    Derivee,
    /// `IMPORTED(2)` : entrée depuis l'extérieur — quelqu'un d'autre l'a.
    Importee,
    /// `RESERVED(3)`.
    Reservee,
    /// `SECURELY_IMPORTED(4)`.
    ImporteeSurement,
    /// Une valeur inconnue.
    Autre(u64),
}

impl Origine {
    const fn depuis(valeur: u64) -> Self {
        match valeur {
            0 => Self::Generee,
            1 => Self::Derivee,
            2 => Self::Importee,
            3 => Self::Reservee,
            4 => Self::ImporteeSurement,
            autre => Self::Autre(autre),
        }
    }
}

impl core::fmt::Display for Origine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Generee => f.write_str("générée"),
            Self::Derivee => f.write_str("dérivée"),
            Self::Importee => f.write_str("importée"),
            Self::Reservee => f.write_str("réservée"),
            Self::ImporteeSurement => f.write_str("importée sûrement"),
            Self::Autre(valeur) => write!(f, "inconnue ({valeur})"),
        }
    }
}

/// `RootOfTrust` : l'état du démarrage au moment où la clé a été attestée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RacineDeConfiance<'a> {
    /// `verifiedBootKey` : l'empreinte de la clé qui a vérifié le démarrage.
    pub cle_de_demarrage: &'a [u8],
    /// `deviceLocked` : le bootloader est verrouillé.
    pub verrouille: bool,
    /// `verifiedBootState`.
    pub demarrage: Demarrage,
    /// `verifiedBootHash` : l'empreinte de la partition de démarrage.
    pub empreinte_de_demarrage: &'a [u8],
}

/// Un paquet d'`attestationApplicationId` : son nom et sa version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Paquet<'a> {
    /// `packageName`, tel quel — de l'ASCII, en pratique.
    pub nom: &'a [u8],
    /// `version` : le `versionCode` de la build.
    pub version: u64,
}

/// `AttestationApplicationId` : l'application qui détient la clé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Application<'a> {
    /// Les paquets — un, en pratique ; plusieurs s'ils partagent un UID.
    pub paquets: Vec<Paquet<'a>>,
    /// Les empreintes SHA-256 des certificats de signature de l'app.
    pub empreintes: Vec<&'a [u8]>,
}

/// `AuthorizationList` : ce qu'un étage — Android ou le matériel — dit de la
/// clé. Chaque champ est optionnel dans le schéma, et absent s'il ne l'a pas
/// écrit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListeAutorisations<'a> {
    /// `purpose` `[1]` : `SIGN(2)`, `VERIFY(3)`…
    pub finalites: Option<Vec<u64>>,
    /// `algorithm` `[2]` : `EC(3)`, `RSA(1)`…
    pub algorithme: Option<u64>,
    /// `keySize` `[3]`, en bits.
    pub taille_de_cle: Option<u64>,
    /// `digest` `[5]` : `SHA-256(4)`…
    pub condensats: Option<Vec<u64>>,
    /// `ecCurve` `[10]` : `P-256(1)`…
    pub courbe: Option<u64>,
    /// `noAuthRequired` `[503]` : la clé s'emploie sans authentification de
    /// l'utilisateur.
    pub sans_authentification: bool,
    /// `creationDateTime` `[701]`, en millisecondes depuis l'époque.
    pub creation: Option<u64>,
    /// `origin` `[702]`.
    pub origine: Option<Origine>,
    /// `rootOfTrust` `[704]`.
    pub racine_de_confiance: Option<RacineDeConfiance<'a>>,
    /// `osVersion` `[705]` : `AAMMPP`, 150000 pour Android 15.
    pub version_os: Option<u64>,
    /// `osPatchLevel` `[706]` : `AAAAMM`, 202608 pour août 2026.
    pub correctif_os: Option<u64>,
    /// `attestationApplicationId` `[709]`.
    pub application: Option<Application<'a>>,
    /// `vendorPatchLevel` `[718]` : `AAAAMMJJ`.
    pub correctif_fabricant: Option<u64>,
    /// `bootPatchLevel` `[719]` : `AAAAMMJJ`.
    pub correctif_demarrage: Option<u64>,
    /// Combien de balises ce lecteur a rencontrées sans les connaître.
    pub sautees: u32,
}

/// La `KeyDescription` entière.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Description<'a> {
    /// `attestationVersion` : la version du schéma.
    pub version: u64,
    /// `attestationSecurityLevel` : qui a produit CETTE attestation.
    pub niveau_attestation: Niveau,
    /// `keymasterVersion`.
    pub version_keymaster: u64,
    /// `keymasterSecurityLevel` : où la clé vit.
    pub niveau_keymaster: Niveau,
    /// `attestationChallenge` : ce que l'app a donné à `setAttestationChallenge`.
    pub defi: &'a [u8],
    /// `uniqueId` : vide, sauf attestation d'identifiant.
    pub identifiant_unique: &'a [u8],
    /// `softwareEnforced` : ce qu'Android dit.
    pub logiciel: ListeAutorisations<'a>,
    /// `teeEnforced` : ce que le matériel dit.
    pub materiel: ListeAutorisations<'a>,
}

/// Ce qui empêche de lire une `KeyDescription`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Faute {
    /// Un élément DER mal formé, tronqué, ou d'une autre balise que celle
    /// qu'attend le schéma à cet endroit.
    Der(der::Faute),
    /// Des octets suivent la fin d'une séquence dont le schéma dit tout.
    Surplus,
    /// Un champ optionnel écrit deux fois.
    Doublon(u32),
    /// Une balise d'`AuthorizationList` qui n'est pas `[n] EXPLICIT`.
    BaliseInattendue,
}

impl From<der::Faute> for Faute {
    fn from(faute: der::Faute) -> Self {
        Self::Der(faute)
    }
}

impl core::fmt::Display for Faute {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Der(faute) => write!(f, "DER : {faute:?}"),
            Self::Surplus => f.write_str("des octets suivent une séquence close"),
            Self::Doublon(numero) => write!(f, "balise [{numero}] écrite deux fois"),
            Self::BaliseInattendue => f.write_str("balise qui n'est pas [n] EXPLICIT"),
        }
    }
}

/// Lit une `KeyDescription` depuis le contenu de l'extension.
///
/// Tout ce qui est rendu est une tranche de `octets`, ou un entier lu d'elle.
///
/// # Erreurs
///
/// Une [`Faute`] nommée.
pub fn lire(octets: &[u8]) -> Result<Description<'_>, Faute> {
    let (contenu, apres) = der::attendu(octets, SEQUENCE)?;
    if !apres.is_empty() {
        return Err(Faute::Surplus);
    }
    let (version, reste) = der::attendu(contenu, ENTIER)?;
    let (niveau_attestation, reste) = der::attendu(reste, ENUMERE)?;
    let (version_keymaster, reste) = der::attendu(reste, ENTIER)?;
    let (niveau_keymaster, reste) = der::attendu(reste, ENUMERE)?;
    let (defi, reste) = der::attendu(reste, OCTETS)?;
    let (identifiant_unique, reste) = der::attendu(reste, OCTETS)?;
    let (logiciel, reste) = der::attendu(reste, SEQUENCE)?;
    let (materiel, reste) = der::attendu(reste, SEQUENCE)?;
    if !reste.is_empty() {
        return Err(Faute::Surplus);
    }
    Ok(Description {
        version: der::entier(version)?,
        niveau_attestation: Niveau::depuis(der::entier(niveau_attestation)?),
        version_keymaster: der::entier(version_keymaster)?,
        niveau_keymaster: Niveau::depuis(der::entier(niveau_keymaster)?),
        defi,
        identifiant_unique,
        logiciel: liste(logiciel)?,
        materiel: liste(materiel)?,
    })
}

/// Pose un champ optionnel, une fois.
fn poser<T>(place: &mut Option<T>, valeur: T, numero: u32) -> Result<(), Faute> {
    if place.is_some() {
        return Err(Faute::Doublon(numero));
    }
    *place = Some(valeur);
    Ok(())
}

/// L'unique INTEGER que porte un `[n] EXPLICIT INTEGER`.
fn entier_seul(explicite: &[u8]) -> Result<u64, Faute> {
    let (contenu, reste) = der::attendu(explicite, ENTIER)?;
    if !reste.is_empty() {
        return Err(Faute::Surplus);
    }
    Ok(der::entier(contenu)?)
}

/// Les INTEGER d'un `[n] EXPLICIT SET OF INTEGER`.
fn entiers(explicite: &[u8]) -> Result<Vec<u64>, Faute> {
    let (mut ensemble, reste) = der::attendu(explicite, ENSEMBLE)?;
    if !reste.is_empty() {
        return Err(Faute::Surplus);
    }
    let mut valeurs = Vec::new();
    while !ensemble.is_empty() {
        let (contenu, suite) = der::attendu(ensemble, ENTIER)?;
        valeurs.push(der::entier(contenu)?);
        ensemble = suite;
    }
    Ok(valeurs)
}

/// Le NULL d'un `[n] EXPLICIT NULL`.
fn nul(explicite: &[u8]) -> Result<(), Faute> {
    let (contenu, reste) = der::attendu(explicite, NUL)?;
    if !contenu.is_empty() || !reste.is_empty() {
        return Err(Faute::Surplus);
    }
    Ok(())
}

/// Lit une `AuthorizationList`.
fn liste(contenu: &[u8]) -> Result<ListeAutorisations<'_>, Faute> {
    let mut lue = ListeAutorisations::default();
    let mut reste = contenu;
    while !reste.is_empty() {
        let (element, suite) = der::element(reste)?;
        reste = suite;
        let Balise {
            classe: Classe::Contextuelle,
            construite: true,
            numero,
        } = element.balise
        else {
            return Err(Faute::BaliseInattendue);
        };
        let explicite = element.contenu;
        match numero {
            1 => poser(&mut lue.finalites, entiers(explicite)?, numero)?,
            2 => poser(&mut lue.algorithme, entier_seul(explicite)?, numero)?,
            3 => poser(&mut lue.taille_de_cle, entier_seul(explicite)?, numero)?,
            5 => poser(&mut lue.condensats, entiers(explicite)?, numero)?,
            10 => poser(&mut lue.courbe, entier_seul(explicite)?, numero)?,
            503 => {
                nul(explicite)?;
                if lue.sans_authentification {
                    return Err(Faute::Doublon(numero));
                }
                lue.sans_authentification = true;
            }
            701 => poser(&mut lue.creation, entier_seul(explicite)?, numero)?,
            702 => poser(
                &mut lue.origine,
                Origine::depuis(entier_seul(explicite)?),
                numero,
            )?,
            704 => poser(
                &mut lue.racine_de_confiance,
                racine_de_confiance(explicite)?,
                numero,
            )?,
            705 => poser(&mut lue.version_os, entier_seul(explicite)?, numero)?,
            706 => poser(&mut lue.correctif_os, entier_seul(explicite)?, numero)?,
            709 => poser(&mut lue.application, application(explicite)?, numero)?,
            718 => poser(
                &mut lue.correctif_fabricant,
                entier_seul(explicite)?,
                numero,
            )?,
            719 => poser(
                &mut lue.correctif_demarrage,
                entier_seul(explicite)?,
                numero,
            )?,
            _ => lue.sautees = lue.sautees.saturating_add(1),
        }
    }
    Ok(lue)
}

/// Lit un `[704] EXPLICIT RootOfTrust`.
fn racine_de_confiance(explicite: &[u8]) -> Result<RacineDeConfiance<'_>, Faute> {
    let (sequence, reste) = der::attendu(explicite, SEQUENCE)?;
    if !reste.is_empty() {
        return Err(Faute::Surplus);
    }
    let (cle_de_demarrage, reste) = der::attendu(sequence, OCTETS)?;
    let (verrouille, reste) = der::attendu(reste, der::BOOLEEN)?;
    let (demarrage, reste) = der::attendu(reste, ENUMERE)?;
    let (empreinte_de_demarrage, reste) = der::attendu(reste, OCTETS)?;
    if !reste.is_empty() {
        return Err(Faute::Surplus);
    }
    Ok(RacineDeConfiance {
        cle_de_demarrage,
        verrouille: der::booleen(verrouille)?,
        demarrage: Demarrage::depuis(der::entier(demarrage)?),
        empreinte_de_demarrage,
    })
}

/// Lit un `[709] EXPLICIT OCTET STRING`, et le DER qu'il enveloppe.
fn application(explicite: &[u8]) -> Result<Application<'_>, Faute> {
    let (enveloppe, reste) = der::attendu(explicite, OCTETS)?;
    if !reste.is_empty() {
        return Err(Faute::Surplus);
    }
    let (sequence, reste) = der::attendu(enveloppe, SEQUENCE)?;
    if !reste.is_empty() {
        return Err(Faute::Surplus);
    }
    let (mut paquets_der, reste) = der::attendu(sequence, ENSEMBLE)?;
    let (mut empreintes_der, reste) = der::attendu(reste, ENSEMBLE)?;
    if !reste.is_empty() {
        return Err(Faute::Surplus);
    }
    let mut paquets = Vec::new();
    while !paquets_der.is_empty() {
        let (paquet, suite) = der::attendu(paquets_der, SEQUENCE)?;
        paquets_der = suite;
        let (nom, reste) = der::attendu(paquet, OCTETS)?;
        let (version, reste) = der::attendu(reste, ENTIER)?;
        if !reste.is_empty() {
            return Err(Faute::Surplus);
        }
        paquets.push(Paquet {
            nom,
            version: der::entier(version)?,
        });
    }
    let mut empreintes = Vec::new();
    while !empreintes_der.is_empty() {
        let (empreinte, suite) = der::attendu(empreintes_der, OCTETS)?;
        empreintes_der = suite;
        empreintes.push(empreinte);
    }
    Ok(Application {
        paquets,
        empreintes,
    })
}
