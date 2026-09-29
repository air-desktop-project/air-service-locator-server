//! Les corps de `POST /v1/echo/jetons` (`docs/protocole.md` §3 quater,
//! décision 91) : ce que la machine qui veut sonder demande, et le jeton
//! qu'une racine lui rend.
//!
//! ```text
//! POST /v1/echo/jetons
//! {"machine":"m-…"}
//!
//! 200 {"jeton":"<386 chiffres hexadécimaux>","expire_a":1789217791000}
//! ```
//!
//! **La clé du sondeur n'est pas dans la demande** : c'est celle que la
//! connexion a prouvée, et la requête ne la dit pas (`protocole.md` §3). Le
//! jeton lui-même se lit et s'écrit par `asl-echo` — une seule grammaire.

use asl_echo::{JETON_HEX_OCTETS, Jeton};
use asl_id::{Genre, Identifiant};
use asl_proto::Erreur;
use asl_proto::cadrage::Ecrivain;

use crate::annuaire::{champ, ecrire_un_entier, fermer, ouvrir};

/// Le champ qui porte la machine visée.
const CHAMP_MACHINE: &str = "machine";

/// Le champ qui porte le jeton.
const CHAMP_JETON: &str = "jeton";

/// Le champ qui porte l'expiration.
const CHAMP_EXPIRE_A: &str = "expire_a";

/// Ce qu'une réponse occupe au plus : l'objet, le jeton, et un entier de
/// vingt chiffres.
pub const JETON_RENDU_MAX: usize = 32 + JETON_HEX_OCTETS + 20;

/// Le corps de `POST /v1/echo/jetons` : la machine qu'on veut sonder,
/// `{"machine":"m-…"}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DemandeDeJeton {
    /// La machine visée.
    pub machine: Identifiant,
}

impl DemandeDeJeton {
    /// Décode une demande.
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage, plus [`Erreur::IdentifiantInvalide`] quand ce n'est
    /// pas un `m-…`.
    pub fn decoder(octets: &[u8]) -> Result<Self, Erreur> {
        let mut lecteur = ouvrir(octets, CHAMP_MACHINE)?;
        lecteur.sauter_blancs();
        let position = lecteur.position();
        let machine = Identifiant::analyser_genre(Genre::Machine, lecteur.chaine()?)
            .map_err(|_| Erreur::IdentifiantInvalide { position })?;
        fermer(&mut lecteur)?;
        Ok(Self { machine })
    }

    /// Encode la demande en JSON.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`] si `sortie` ne suffit pas.
    pub fn encoder(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        let mut ecrivain = Ecrivain::nouveau(sortie);
        ecrivain.pousser(b"{\"machine\":\"");
        ecrivain.pousser(self.machine.texte().as_str().as_bytes());
        ecrivain.pousser(b"\"}");
        ecrivain.achever()
    }
}

/// La réponse de `POST /v1/echo/jetons` : le jeton, et son expiration dite
/// à part pour qui ne le lit pas.
///
/// **Les deux doivent s'accorder** : un `expire_a` qui ne serait pas celui
/// que le jeton porte est refusé à la lecture — deux lecteurs qui ne
/// regarderaient pas le même champ ne verraient pas la même expiration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JetonRendu {
    /// Le jeton, bien formé (pas encore cru : c'est l'écho qui le croit).
    pub jeton: Jeton,
}

impl JetonRendu {
    /// Décode une réponse.
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage ; [`Erreur::JsonAttendu`] quand le jeton ne se lit
    /// pas, ou quand `expire_a` n'est pas celle qu'il porte.
    pub fn decoder(octets: &[u8]) -> Result<Self, Erreur> {
        let mut lecteur = ouvrir(octets, CHAMP_JETON)?;
        lecteur.sauter_blancs();
        let position = lecteur.position();
        let jeton = Jeton::lire_hex(lecteur.chaine()?).map_err(|_| Erreur::JsonAttendu {
            position,
            attendu: "un jeton d'écho",
        })?;
        lecteur.attendre(b',', "une virgule")?;
        champ(&mut lecteur, CHAMP_EXPIRE_A)?;
        lecteur.sauter_blancs();
        let position = lecteur.position();
        if lecteur.entier()? != jeton.expire_a() {
            return Err(Erreur::JsonAttendu {
                position,
                attendu: "l'expiration que le jeton porte",
            });
        }
        fermer(&mut lecteur)?;
        Ok(Self { jeton })
    }

    /// Encode la réponse en JSON.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`] si `sortie` ne suffit pas.
    pub fn encoder(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        let mut chiffres = [0_u8; 20];
        let mut ecrivain = Ecrivain::nouveau(sortie);
        ecrivain.pousser(b"{\"jeton\":\"");
        ecrivain.pousser(self.jeton.hex().as_str().as_bytes());
        ecrivain.pousser(b"\",\"expire_a\":");
        ecrivain.pousser(ecrire_un_entier(self.jeton.expire_a(), &mut chiffres));
        ecrivain.pousser(b"}");
        ecrivain.achever()
    }
}
