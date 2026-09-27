//! Les corps de l'inscription des annuaires locaux (`docs/protocole.md` §2.2,
//! §3 ter ; `docs/annuaires.md` §2 ter, §4.1) : ce qu'une application
//! déclare, ce qu'un administrateur tranche, où un domaine est confié — et ce
//! que l'annuaire en rend.
//!
//! La preuve qu'un annuaire local apporte en se présentant — code, clé,
//! signature — n'est pas du JSON : elle a la forme de celle d'un enrôlement,
//! et `asl-session` la lit comme elle.

use asl_id::{Genre, Identifiant};
use asl_proto::Erreur;
use asl_proto::cadrage::{Ecrivain, Lecteur};

use crate::corps::CORPS_MAX;

/// Le champ qui porte une adresse déclarée.
const CHAMP_ADRESSE: &str = "adresse";

/// Le champ qui porte une décision.
const CHAMP_ACCEPTE: &str = "accepte";

/// Le champ qui porte un annuaire.
const CHAMP_ANNUAIRE: &str = "annuaire";

/// Refuse un corps plus long que ce que l'annuaire lit.
const fn borner(octets: &[u8]) -> Result<(), Erreur> {
    if octets.len() > CORPS_MAX {
        return Err(Erreur::MessageTropLong {
            obtenue: octets.len(),
        });
    }
    Ok(())
}

/// Lit `{"<champ>": ` et rend le lecteur placé sur la valeur.
fn ouvrir<'a>(octets: &'a [u8], champ: &str) -> Result<Lecteur<'a>, Erreur> {
    borner(octets)?;
    let mut lecteur = Lecteur::nouveau(octets);
    lecteur.attendre(b'{', "un objet")?;
    let position = lecteur.position();
    if lecteur.chaine()? != champ {
        return Err(Erreur::ChampInconnu { position });
    }
    lecteur.attendre(b':', "deux-points")?;
    Ok(lecteur)
}

/// Lit `}` et la fin du corps.
fn fermer(lecteur: &mut Lecteur<'_>) -> Result<(), Erreur> {
    lecteur.attendre(b'}', "la fin de l'objet")?;
    lecteur.fin()
}

// ── Déclarer un annuaire, ou son second membre ──────────────────────────────

/// Le corps de `POST /v1/annuaires` et de `POST /v1/annuaires/{n}/membres` :
/// `{"adresse": "hôte:port"}`. **La forme de l'adresse** se juge dans
/// `asl-registre` (`Adresse::nouvelle`) ; ici, une chaîne ASCII sans
/// échappement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclarationDAnnuaire<'a> {
    /// L'adresse déclarée, telle que reçue.
    pub adresse: &'a str,
}

impl<'a> DeclarationDAnnuaire<'a> {
    /// Décode une déclaration.
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage.
    pub fn decoder(octets: &'a [u8]) -> Result<Self, Erreur> {
        let mut lecteur = ouvrir(octets, CHAMP_ADRESSE)?;
        let adresse = lecteur.chaine()?;
        fermer(&mut lecteur)?;
        Ok(Self { adresse })
    }
}

// ── Trancher une inscription ────────────────────────────────────────────────

/// Le corps de `POST /v1/inscriptions/{n}/decision` : `{"accepte": true}` ou
/// `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionDInscription {
    /// Accepter, ou refuser.
    pub accepte: bool,
}

impl DecisionDInscription {
    /// Décode une décision.
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage, plus [`Erreur::JsonAttendu`] quand la valeur n'est
    /// ni `true` ni `false`.
    pub fn decoder(octets: &[u8]) -> Result<Self, Erreur> {
        let mut lecteur = ouvrir(octets, CHAMP_ACCEPTE)?;
        lecteur.sauter_blancs();
        let position = lecteur.position();
        let accepte = if lecteur.mot("true") {
            true
        } else if lecteur.mot("false") {
            false
        } else {
            return Err(Erreur::JsonAttendu {
                position,
                attendu: "true ou false",
            });
        };
        fermer(&mut lecteur)?;
        Ok(Self { accepte })
    }
}

// ── Confier un domaine ──────────────────────────────────────────────────────

/// Le corps de `PUT /v1/domaines/{d}/hebergeur` : `{"annuaire": "n-…"}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hebergeur {
    /// L'annuaire — son titulaire.
    pub annuaire: Identifiant,
}

impl Hebergeur {
    /// Décode un hébergeur.
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage, plus [`Erreur::IdentifiantInvalide`] quand ce n'est
    /// pas un `n-…`.
    pub fn decoder(octets: &[u8]) -> Result<Self, Erreur> {
        let mut lecteur = ouvrir(octets, CHAMP_ANNUAIRE)?;
        let position = lecteur.position();
        let annuaire = Identifiant::analyser_genre(Genre::Annuaire, lecteur.chaine()?)
            .map_err(|_| Erreur::IdentifiantInvalide { position })?;
        fermer(&mut lecteur)?;
        Ok(Self { annuaire })
    }
}

// ── Ce que l'annuaire rend ──────────────────────────────────────────────────

/// Une inscription telle que l'annuaire la rend — à son propriétaire
/// (`GET /v1/annuaires`), aux administrateurs (`GET /v1/inscriptions`), à
/// l'annuaire qui se présente (`POST /v1/annuaires/inscription`,
/// `POST /v1/annuaires/etat`).
///
/// **Les champs absents ne s'écrivent pas** : une déclaration dont le code
/// attend n'a pas de membre, un membre titulaire n'a pas d'autre annuaire que
/// lui-même — il l'écrit quand même, pour qu'un lecteur n'ait pas à le
/// déduire.
///
/// L'adresse se réémet sans échappement : elle est de l'ASCII imprimable sans
/// `"` ni `\` — `asl-registre` le vérifie à la pose et à la relecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InscriptionRendue<'a> {
    /// Le membre, s'il s'est présenté.
    pub membre: Option<Identifiant>,
    /// L'annuaire — son titulaire —, s'il est connu.
    pub annuaire: Option<Identifiant>,
    /// Le propriétaire, pour les administrateurs.
    pub proprietaire: Option<Identifiant>,
    /// L'état : `attendue`, `en attente`, `acceptée`, `refusée`, `retirée`.
    pub etat: &'a str,
    /// L'adresse déclarée.
    pub adresse: &'a str,
    /// Jusqu'à quand le code se présente, pour une déclaration attendue.
    pub expire_a: Option<u64>,
}

impl InscriptionRendue<'_> {
    /// Encode l'inscription en JSON.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`] si `sortie` ne suffit pas.
    pub fn encoder(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        let mut ecrivain = Ecrivain::nouveau(sortie);
        ecrivain.pousser(b"{");
        let mut premier = true;
        for (champ, valeur) in [
            ("membre", self.membre),
            ("annuaire", self.annuaire),
            ("proprietaire", self.proprietaire),
        ] {
            if let Some(quel) = valeur {
                if !premier {
                    ecrivain.pousser(b",");
                }
                premier = false;
                ecrivain.pousser(b"\"");
                ecrivain.pousser(champ.as_bytes());
                ecrivain.pousser(b"\":\"");
                ecrivain.pousser(quel.texte().as_str().as_bytes());
                ecrivain.pousser(b"\"");
            }
        }
        if !premier {
            ecrivain.pousser(b",");
        }
        ecrivain.pousser(b"\"etat\":\"");
        ecrivain.pousser(self.etat.as_bytes());
        ecrivain.pousser(b"\",\"adresse\":\"");
        ecrivain.pousser(self.adresse.as_bytes());
        ecrivain.pousser(b"\"");
        if let Some(quand) = self.expire_a {
            let mut chiffres = [0_u8; 20];
            ecrivain.pousser(b",\"expire_a\":");
            ecrivain.pousser(ecrire_un_entier(quand, &mut chiffres));
        }
        ecrivain.pousser(b"}");
        ecrivain.achever()
    }
}

/// Écrit un entier en décimal, sans allocation : vingt chiffres suffisent à
/// un `u64`.
fn ecrire_un_entier(valeur: u64, tampon: &mut [u8; 20]) -> &[u8] {
    let mut reste = valeur;
    let mut debut = tampon.len();
    for place in tampon.iter_mut().rev() {
        *place = b'0'.saturating_add(u8::try_from(reste % 10).unwrap_or(0));
        reste /= 10;
        debut = debut.saturating_sub(1);
        if reste == 0 {
            break;
        }
    }
    tampon.get(debut..).unwrap_or_default()
}
