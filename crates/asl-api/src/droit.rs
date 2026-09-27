//! Les droits sur le fil (`protocole.md` §2.2, `docs/modele.md` §2.13,
//! 2026-09-27) : ce qu'une application envoie pour accorder un droit à un
//! groupe, et ce que l'annuaire rend de ceux qu'on a accordés ou reçus.
//!
//! # LES NOMS DES DROITS SONT ICI, ET DANS `asl-registre`
//!
//! Cette grammaire lit des NOMS, et l'entrepôt range des BITS. Les deux listes
//! doivent dire la même chose, dans le même ordre : c'est la session, qui voit
//! les deux crates, qui le vérifie par un essai — une grammaire ne dépend pas
//! d'un format de disque.
//!
//! # L'ÉLÉMENT EST UN SEUL CHAMP, ET SON GENRE LE DÉSIGNE
//!
//! Pour la raison écrite sur la portée d'une autorisation : un domaine `d-…`,
//! une machine `m-…` ou un service `s-…`, et le préfixe dit lequel. **Pas un
//! compte** : l'élément « compte » n'existe que pour les autorisations
//! converties, et ne s'accorde plus que par le verbe de compatibilité.

use asl_id::{Genre, Identifiant};
use asl_proto::Erreur;
use asl_proto::cadrage::{Ecrivain, Lecteur};

use crate::corps::{CORPS_MAX, NOM_MACHINE_MAX};

/// Les quatre droits, dans l'ordre du fil — et dans celui des bits que
/// `asl-registre` range : le rang d'un nom ici est la place de son bit là.
pub const NOMS_DE_DROITS: [&str; 4] = ["administrer", "rattacher", "voir", "localiser"];

/// Les champs de `POST /v1/droits`.
const CHAMPS_DROIT: [&str; 4] = ["groupe", "element", "droits", "etiquette"];

/// Ce que `POST /v1/droits` demande.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DemandeDeDroit<'a> {
    /// Le groupe qui le recevra.
    pub groupe: Identifiant,
    /// Ce sur quoi il portera : un domaine, une machine ou un service.
    pub element: Identifiant,
    /// Ce qu'il permettra : un bit par droit, au rang de son nom dans
    /// [`NOMS_DE_DROITS`]. Jamais vide.
    pub droits: u8,
    /// Le libellé, aux règles d'un nom de machine.
    pub etiquette: &'a str,
}

/// Lit le tableau des droits : non vide, des noms connus, sans doublon.
fn lire_les_droits(lecteur: &mut Lecteur<'_>) -> Result<u8, Erreur> {
    lecteur.attendre(b'[', "un tableau")?;
    let mut droits = 0_u8;
    lecteur.sauter_blancs();
    // **UN DROIT AU MOINS** : un droit qui ne permet rien serait un droit
    // qu'on croit avoir accordé.
    if lecteur.regarder() == Some(b']') {
        return Err(Erreur::ChampManquant {
            nom: CHAMPS_DROIT[2],
        });
    }
    loop {
        let position = lecteur.position();
        let nom = lecteur.chaine()?;
        let rang = NOMS_DE_DROITS
            .iter()
            .position(|connu| *connu == nom)
            .ok_or(Erreur::ChampInconnu { position })?;
        let bit = 1_u8 << rang;
        if droits & bit != 0 {
            return Err(Erreur::ChampEnDouble { position });
        }
        droits |= bit;
        lecteur.sauter_blancs();
        match lecteur.regarder() {
            Some(b',') => lecteur.avancer(),
            Some(b']') => {
                lecteur.avancer();
                return Ok(droits);
            }
            _ => {
                return Err(Erreur::JsonAttendu {
                    position: lecteur.position(),
                    attendu: "une virgule ou la fin du tableau",
                });
            }
        }
    }
}

/// Lit l'élément : un domaine, une machine ou un service.
fn lire_l_element(texte: &str, position: usize) -> Result<Identifiant, Erreur> {
    [Genre::Domaine, Genre::Machine, Genre::Service]
        .into_iter()
        .find_map(|genre| Identifiant::analyser_genre(genre, texte).ok())
        .ok_or(Erreur::IdentifiantInvalide { position })
}

impl<'a> DemandeDeDroit<'a> {
    /// Décode une demande de droit.
    ///
    /// ```jsonc
    /// {"groupe": "e-…", "element": "d-…", "droits": ["voir", "localiser"], "etiquette": "Famille"}
    /// ```
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage, plus [`Erreur::IdentifiantInvalide`] pour un groupe
    /// qui n'en est pas un ou un élément d'un autre genre,
    /// [`Erreur::ChampInconnu`] pour un droit inconnu ou un tableau vide,
    /// [`Erreur::ChampEnDouble`] pour un droit répété, [`Erreur::NomVide`] et
    /// [`Erreur::NomTropLong`] pour l'étiquette.
    pub fn decoder(octets: &'a [u8]) -> Result<Self, Erreur> {
        if octets.len() > CORPS_MAX {
            return Err(Erreur::MessageTropLong {
                obtenue: octets.len(),
            });
        }
        let mut lecteur = Lecteur::nouveau(octets);
        lecteur.attendre(b'{', "un objet")?;

        let mut vus = 0_u8;
        let mut groupe = None;
        let mut element = None;
        let mut droits = None;
        let mut etiquette: Option<&'a str> = None;

        loop {
            let position_cle = lecteur.position();
            let cle = lecteur.chaine()?;
            let rang = CHAMPS_DROIT.iter().position(|champ| *champ == cle).ok_or(
                Erreur::ChampInconnu {
                    position: position_cle,
                },
            )?;
            let bit = 1_u8 << rang;
            if vus & bit != 0 {
                return Err(Erreur::ChampEnDouble {
                    position: position_cle,
                });
            }
            vus |= bit;
            lecteur.attendre(b':', "deux-points")?;
            match rang {
                0 => {
                    let position = lecteur.position();
                    groupe = Some(
                        Identifiant::analyser_genre(Genre::Ensemble, lecteur.chaine()?)
                            .map_err(|_| Erreur::IdentifiantInvalide { position })?,
                    );
                }
                1 => {
                    let position = lecteur.position();
                    element = Some(lire_l_element(lecteur.chaine()?, position)?);
                }
                2 => droits = Some(lire_les_droits(&mut lecteur)?),
                _ => {
                    let texte = lecteur.texte_libre()?;
                    if texte.is_empty() {
                        return Err(Erreur::NomVide);
                    }
                    if texte.len() > NOM_MACHINE_MAX {
                        return Err(Erreur::NomTropLong {
                            obtenue: texte.len(),
                        });
                    }
                    etiquette = Some(texte);
                }
            }
            lecteur.sauter_blancs();
            match lecteur.regarder() {
                Some(b',') => lecteur.avancer(),
                Some(b'}') => {
                    lecteur.avancer();
                    break;
                }
                _ => {
                    return Err(Erreur::JsonAttendu {
                        position: lecteur.position(),
                        attendu: "une virgule ou la fin de l'objet",
                    });
                }
            }
        }
        lecteur.fin()?;

        Ok(Self {
            groupe: groupe.ok_or(Erreur::ChampManquant {
                nom: CHAMPS_DROIT[0],
            })?,
            element: element.ok_or(Erreur::ChampManquant {
                nom: CHAMPS_DROIT[1],
            })?,
            droits: droits.ok_or(Erreur::ChampManquant {
                nom: CHAMPS_DROIT[2],
            })?,
            etiquette: etiquette.ok_or(Erreur::ChampManquant {
                nom: CHAMPS_DROIT[3],
            })?,
        })
    }

    /// Encode cette demande — pour les essais et les liaisons.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`].
    pub fn encoder(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        let mut ecrivain = Ecrivain::nouveau(sortie);
        ecrivain.pousser(b"{\"groupe\":\"");
        ecrivain.pousser(self.groupe.texte().as_str().as_bytes());
        ecrivain.pousser(b"\",\"element\":\"");
        ecrivain.pousser(self.element.texte().as_str().as_bytes());
        ecrivain.pousser(b"\",\"droits\":");
        ecrire_les_noms(&mut ecrivain, self.droits);
        ecrivain.pousser(b",\"etiquette\":\"");
        ecrivain.pousser(self.etiquette.as_bytes());
        ecrivain.pousser(b"\"}");
        ecrivain.achever()
    }
}

/// Écrit `["voir","localiser"]` : les noms des bits posés, dans l'ordre.
fn ecrire_les_noms(ecrivain: &mut Ecrivain<'_>, droits: u8) {
    ecrivain.pousser(b"[");
    let mut premier = true;
    for (rang, nom) in NOMS_DE_DROITS.iter().enumerate() {
        if droits & (1_u8 << rang) == 0 {
            continue;
        }
        if !premier {
            ecrivain.pousser(b",");
        }
        premier = false;
        ecrivain.pousser(b"\"");
        ecrivain.pousser(nom.as_bytes());
        ecrivain.pousser(b"\"");
    }
    ecrivain.pousser(b"]");
}

// ── Ce que l'annuaire rend ──────────────────────────────────────────────────

/// Un droit, tel que `GET /v1/droits` le rend.
///
/// # LES RETIRÉS SONT RENDUS, ET MARQUÉS
///
/// Comme les autorisations d'hier et les appareils révoqués : l'écran qu'on
/// regarde après avoir retiré un droit doit montrer ce qu'on a retiré.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DroitRendu<'a> {
    /// Son identifiant — celui qu'on passe à `DELETE /v1/droits/{g}`.
    pub droit: Identifiant,
    /// Le groupe qui le reçoit.
    pub groupe: Identifiant,
    /// Ce sur quoi il porte.
    pub element: Identifiant,
    /// Ce qu'il permet, un bit par droit au rang de [`NOMS_DE_DROITS`].
    pub droits: u8,
    /// Le libellé donné à l'octroi.
    pub etiquette: &'a str,
    /// Le compte qui l'a accordé.
    pub par: Identifiant,
    /// A-t-il été retiré ?
    pub retire: bool,
}

impl DroitRendu<'_> {
    /// Encode un droit.
    ///
    /// ```jsonc
    /// {"droit":"g-…","groupe":"e-…","element":"d-…","droits":["localiser"],"etiquette":"Famille","par":"u-…","retire":false}
    /// ```
    ///
    /// **L'étiquette se réémet sans échappement**, comme un nom de machine :
    /// `texte_libre` a refusé à l'entrée ce qu'il aurait fallu échapper.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`].
    pub fn encoder(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        let mut ecrivain = Ecrivain::nouveau(sortie);
        ecrivain.pousser(b"{\"droit\":\"");
        ecrivain.pousser(self.droit.texte().as_str().as_bytes());
        ecrivain.pousser(b"\",\"groupe\":\"");
        ecrivain.pousser(self.groupe.texte().as_str().as_bytes());
        ecrivain.pousser(b"\",\"element\":\"");
        ecrivain.pousser(self.element.texte().as_str().as_bytes());
        ecrivain.pousser(b"\",\"droits\":");
        ecrire_les_noms(&mut ecrivain, self.droits);
        ecrivain.pousser(b",\"etiquette\":\"");
        ecrivain.pousser(self.etiquette.as_bytes());
        ecrivain.pousser(b"\",\"par\":\"");
        ecrivain.pousser(self.par.texte().as_str().as_bytes());
        ecrivain.pousser(b"\",\"retire\":");
        ecrivain.pousser(if self.retire { b"true}" } else { b"false}" });
        ecrivain.achever()
    }
}
