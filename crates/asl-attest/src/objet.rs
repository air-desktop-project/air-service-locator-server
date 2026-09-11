//! L'objet d'attestation d'App Attest, et les données d'authentificateur
//! qu'il porte.
//!
//! # LA FORME, ET RIEN QUE LA FORME
//!
//! Ce module dit ce que les octets CONTIENNENT. Il ne dit pas si la chaîne de
//! certificats remonte à Apple, si le défi est le bon, si la clé est celle
//! qu'on attend : ces questions sont à l'étage au-dessus, et elles ne se posent
//! que sur un objet déjà lu.
//!
//! Le partage est littéral : tout ce qui est ici se décide sans rien savoir du
//! monde, et tout ce qui demande de savoir quelque chose n'y est pas.
//!
//! # LA FORME, D'APRÈS LA DOCUMENTATION D'APPLE
//!
//! ```text
//! {
//!   "fmt":      "apple-appattest",
//!   "attStmt":  { "x5c": [ cert, intermédiaire ], "receipt": … },
//!   "authData": <octets>
//! }
//! ```
//!
//! et, dans `authData`, la disposition de WebAuthn :
//!
//! ```text
//! empreinte de l'app   32 octets
//! drapeaux              1 octet
//! compteur              4 octets, gros-boutien
//! ── si le drapeau ATTESTE est levé ──
//! aaguid               16 octets
//! longueur de l'id      2 octets, gros-boutien
//! identifiant de clé    (cette longueur)
//! clé publique COSE     tout le reste
//! ```
//!
//! # CE QUE JE N'AI PAS
//!
//! **AUCUNE CAPTURE RÉELLE.** Cette disposition vient de la documentation, pas
//! d'un objet qu'un iPhone m'aurait donné. Les essais qui suivent éprouvent que
//! le lecteur lit ce qu'il croit lire — ils n'éprouvent pas que c'est bien ce
//! qu'Apple envoie. Tant que ce dépôt n'aura pas vu une attestation réelle, la
//! politique ne peut pas passer à `exigee`.

use crate::{Erreur, Lecteur};

/// La seule valeur de `fmt` que ce lecteur sert.
pub const FORMAT: &str = "apple-appattest";

/// La taille de l'empreinte de l'app, en octets.
pub const EMPREINTE_OCTETS: usize = 32;

/// La taille d'un `aaguid`, en octets.
pub const AAGUID_OCTETS: usize = 16;

/// Ce que `authData` mesure au minimum : empreinte, drapeaux, compteur.
pub const AUTH_MINIMUM: usize = 37;

/// Le plus de certificats qu'une chaîne `x5c` puisse porter ici.
///
/// Apple en envoie deux. Quatre laisse de la marge ; sans borne, il faudrait un
/// tas pour les tenir, et cette crate n'en a pas.
pub const X5C_MAX: usize = 4;

/// Le drapeau de présence de l'utilisateur.
pub const DRAPEAU_PRESENCE: u8 = 0x01;
/// Le drapeau de vérification de l'utilisateur.
pub const DRAPEAU_VERIFIE: u8 = 0x04;
/// Le drapeau qui annonce des données de clé attestée.
pub const DRAPEAU_ATTESTE: u8 = 0x40;
/// Le drapeau qui annonce des extensions derrière la clé.
pub const DRAPEAU_EXTENSIONS: u8 = 0x80;

/// Un champ de l'objet, nommé pour qu'un refus dise lequel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Champ {
    /// `fmt`.
    Format,
    /// `attStmt`.
    Declaration,
    /// `authData`.
    DonneesAuth,
    /// `attStmt.x5c`.
    Chaine,
    /// `attStmt.receipt`.
    Recu,
}

impl Champ {
    /// Le nom tel qu'il est écrit sur le fil.
    #[must_use]
    pub const fn nom(self) -> &'static str {
        match self {
            Self::Format => "fmt",
            Self::Declaration => "attStmt",
            Self::DonneesAuth => "authData",
            Self::Chaine => "x5c",
            Self::Recu => "receipt",
        }
    }
}

/// Les données de clé attestée, quand le drapeau [`DRAPEAU_ATTESTE`] est levé.
///
/// Tout est EMPRUNTÉ aux octets d'origine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleAttestee<'a> {
    /// L'`aaguid`, exactement [`AAGUID_OCTETS`] octets.
    ///
    /// Apple y écrit `appattest` ou `appattestdevelop` ; **dire lequel est
    /// acceptable n'est pas une question de forme**, et ne se tranche pas ici.
    pub aaguid: &'a [u8],
    /// L'identifiant de la clé, que la vérification comparera à l'empreinte de
    /// la clé publique du certificat.
    pub identifiant: &'a [u8],
    /// La clé publique, encodée en COSE. Elle n'est pas décodée ici : c'est
    /// celle du CERTIFICAT qui signe, et cette copie-ci ne sert à rien tant que
    /// personne ne l'a comparée.
    pub cle_cose: &'a [u8],
}

/// Les données d'authentificateur, lues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DonneesAuth<'a> {
    /// L'empreinte de l'identifiant d'app, exactement [`EMPREINTE_OCTETS`]
    /// octets.
    pub empreinte_app: &'a [u8],
    /// Les drapeaux, bruts.
    pub drapeaux: u8,
    /// Le compteur de signatures.
    pub compteur: u32,
    /// La clé attestée, si le drapeau la promet.
    pub cle: Option<CleAttestee<'a>>,
}

impl DonneesAuth<'_> {
    /// Le drapeau [`DRAPEAU_ATTESTE`] est-il levé ?
    #[must_use]
    pub const fn atteste(&self) -> bool {
        self.drapeaux & DRAPEAU_ATTESTE != 0
    }

    /// Le drapeau [`DRAPEAU_PRESENCE`] est-il levé ?
    #[must_use]
    pub const fn presence(&self) -> bool {
        self.drapeaux & DRAPEAU_PRESENCE != 0
    }

    /// Le drapeau [`DRAPEAU_VERIFIE`] est-il levé ?
    #[must_use]
    pub const fn verifie(&self) -> bool {
        self.drapeaux & DRAPEAU_VERIFIE != 0
    }

    /// Le drapeau [`DRAPEAU_EXTENSIONS`] est-il levé ?
    #[must_use]
    pub const fn extensions(&self) -> bool {
        self.drapeaux & DRAPEAU_EXTENSIONS != 0
    }
}

/// L'objet d'attestation entier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjetAttestation<'a> {
    /// La chaîne de certificats, DER brut, dans l'ordre où elle est venue.
    ///
    /// **LE PREMIER EST CELUI DE LA CLÉ**, les suivants mènent vers la racine.
    chaine: [&'a [u8]; X5C_MAX],
    /// Combien de [`Self::chaine`] sont réellement remplis.
    combien: usize,
    /// Le reçu, s'il y en a un. Il n'est pas lu : il se présente à Apple, et
    /// rien ici ne sait le faire.
    pub recu: Option<&'a [u8]>,
    /// Les octets bruts de `authData`.
    ///
    /// **ON LES GARDE TELS QUELS** parce que le nonce se calcule dessus : les
    /// relire depuis la structure donnerait d'autres octets, et donc un autre
    /// nonce.
    pub donnees_auth: &'a [u8],
    /// Ce que ces octets portent.
    pub auth: DonneesAuth<'a>,
}

impl<'a> ObjetAttestation<'a> {
    /// La chaîne de certificats, DER brut.
    #[must_use]
    pub fn chaine(&self) -> &[&'a [u8]] {
        self.chaine.get(..self.combien).unwrap_or(&[])
    }

    /// Lit un objet d'attestation, et rien de plus : des octets en trop
    /// derrière lui sont un refus.
    ///
    /// # Erreurs
    ///
    /// Toute [`Erreur`] de grammaire, et les fautes de forme de l'objet.
    pub fn lire(octets: &'a [u8]) -> Result<Self, Erreur> {
        let mut lecteur = Lecteur::nouveau(octets);
        let objet = Self::depuis(&mut lecteur)?;
        lecteur.rien_de_plus()?;
        Ok(objet)
    }

    /// Lit un objet d'attestation depuis un curseur déjà posé.
    ///
    /// # Erreurs
    ///
    /// Toute [`Erreur`] de grammaire, et les fautes de forme de l'objet.
    pub fn depuis(lecteur: &mut Lecteur<'a>) -> Result<Self, Erreur> {
        let couples = lecteur.carte()?;
        let mut format = None;
        let mut declaration = None;
        let mut donnees_auth = None;
        for _ in 0..couples {
            match lecteur.texte()? {
                "fmt" => poser(&mut format, lecteur.texte()?, Champ::Format)?,
                "attStmt" => poser(
                    &mut declaration,
                    lire_declaration(lecteur)?,
                    Champ::Declaration,
                )?,
                "authData" => poser(&mut donnees_auth, lecteur.octets()?, Champ::DonneesAuth)?,
                _ => lecteur.sauter()?,
            }
        }
        let format = format.ok_or(Erreur::ChampManquant {
            champ: Champ::Format,
        })?;
        if format != FORMAT {
            return Err(Erreur::FormatInconnu);
        }
        let (chaine, combien, recu) = declaration.ok_or(Erreur::ChampManquant {
            champ: Champ::Declaration,
        })?;
        let donnees_auth = donnees_auth.ok_or(Erreur::ChampManquant {
            champ: Champ::DonneesAuth,
        })?;
        let auth = lire_auth(donnees_auth)?;
        Ok(Self {
            chaine,
            combien,
            recu,
            donnees_auth,
            auth,
        })
    }
}

/// Range une valeur une fois, et refuse la seconde.
///
/// **UN CHAMP EN DOUBLE N'EST PAS UNE CURIOSITÉ.** C'est la place exacte où
/// l'on met un `authData` que le lecteur prendra et un autre que le
/// vérificateur prendrait.
fn poser<T>(ou: &mut Option<T>, valeur: T, champ: Champ) -> Result<(), Erreur> {
    if ou.is_some() {
        return Err(Erreur::ChampEnDouble { champ });
    }
    *ou = Some(valeur);
    Ok(())
}

/// Lit `attStmt` : la chaîne, son compte, et le reçu.
type Declaration<'a> = ([&'a [u8]; X5C_MAX], usize, Option<&'a [u8]>);

fn lire_declaration<'a>(lecteur: &mut Lecteur<'a>) -> Result<Declaration<'a>, Erreur> {
    let couples = lecteur.carte()?;
    let mut chaine: Option<([&'a [u8]; X5C_MAX], usize)> = None;
    let mut recu = None;
    for _ in 0..couples {
        match lecteur.texte()? {
            "x5c" => poser(&mut chaine, lire_chaine(lecteur)?, Champ::Chaine)?,
            "receipt" => poser(&mut recu, lecteur.octets()?, Champ::Recu)?,
            _ => lecteur.sauter()?,
        }
    }
    let (chaine, combien) = chaine.ok_or(Erreur::ChampManquant {
        champ: Champ::Chaine,
    })?;
    Ok((chaine, combien, recu))
}

/// Lit `x5c` : un tableau de certificats DER.
fn lire_chaine<'a>(lecteur: &mut Lecteur<'a>) -> Result<([&'a [u8]; X5C_MAX], usize), Erreur> {
    let combien = lecteur.tableau()?;
    if combien > X5C_MAX {
        return Err(Erreur::TropDeCertificats { annonces: combien });
    }
    let mut chaine: [&'a [u8]; X5C_MAX] = [&[]; X5C_MAX];
    for case in chaine.iter_mut().take(combien) {
        *case = lecteur.octets()?;
    }
    Ok((chaine, combien))
}

/// Lit la disposition de `authData`.
fn lire_auth(octets: &[u8]) -> Result<DonneesAuth<'_>, Erreur> {
    let empreinte_app = tailler(octets, 0, EMPREINTE_OCTETS)?;
    let drapeaux = *octets
        .get(EMPREINTE_OCTETS)
        .ok_or(Erreur::AuthDataTronque {
            octets: octets.len(),
        })?;
    let compteur = entier_be(tailler(octets, 33, 4)?);
    let atteste = drapeaux & DRAPEAU_ATTESTE != 0;
    if !atteste {
        // **SANS LE DRAPEAU, IL N'Y A RIEN DERRIÈRE LE COMPTEUR.** Des octets
        // de plus ne seraient lus par personne, et c'est exactement la place où
        // l'on glisse ce qu'un second lecteur, lui, lirait.
        if octets.len() > AUTH_MINIMUM {
            return Err(Erreur::DonneesEnTrop {
                position: AUTH_MINIMUM,
            });
        }
        return Ok(DonneesAuth {
            empreinte_app,
            drapeaux,
            compteur,
            cle: None,
        });
    }
    let aaguid = tailler(octets, AUTH_MINIMUM, AAGUID_OCTETS)?;
    let apres_aaguid = AUTH_MINIMUM.saturating_add(AAGUID_OCTETS);
    let longueur = entier_be(tailler(octets, apres_aaguid, 2)?);
    let longueur = usize::try_from(longueur).unwrap_or(usize::MAX);
    let debut_id = apres_aaguid.saturating_add(2);
    let identifiant = tailler(octets, debut_id, longueur)?;
    // `tailler` vient de garantir cette borne : le reste EXISTE, fût-il vide.
    let cle_cose = octets
        .get(debut_id.saturating_add(longueur)..)
        .unwrap_or(&[]);
    Ok(DonneesAuth {
        empreinte_app,
        drapeaux,
        compteur,
        cle: Some(CleAttestee {
            aaguid,
            identifiant,
            cle_cose,
        }),
    })
}

/// Découpe `combien` octets à partir de `debut`, ou refuse.
fn tailler(octets: &[u8], debut: usize, combien: usize) -> Result<&[u8], Erreur> {
    octets
        .get(debut..debut.saturating_add(combien))
        .ok_or(Erreur::AuthDataTronque {
            octets: octets.len(),
        })
}

/// Un entier gros-boutien, sur au plus quatre octets.
fn entier_be(tranche: &[u8]) -> u32 {
    let mut valeur = 0_u32;
    for octet in tranche {
        valeur = valeur.wrapping_shl(8) | u32::from(*octet);
    }
    valeur
}
