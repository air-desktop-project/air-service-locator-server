//! Les groupes sur le fil (`protocole.md` §2.2, 2026-09-27) : ce qu'une
//! application envoie pour créer un groupe, changer son étiquette, y ajouter un
//! compte, et ce que l'annuaire lui rend ; et le corps de l'exploitant qui
//! nomme ou retire un administrateur des racines.
//!
//! # L'ÉTIQUETTE EST UN NOM DE MACHINE
//!
//! Mêmes règles, mêmes raisons (`docs/modele.md` §2.12) : du texte libre pour
//! l'humain — « Famille », « Bureau » —, entré par
//! [`asl_proto::cadrage::Lecteur::texte_libre`], qui refuse ce que le cadrage
//! JSON de ce dépôt ne sait pas porter, non vide, au plus
//! [`crate::corps::NOM_MACHINE_MAX`] octets. Il ne se compare pas : il n'a donc
//! pas à être normalisé, contrairement à l'alias de domaine.

use asl_id::{Genre, Identifiant};
use asl_proto::Erreur;
use asl_proto::cadrage::{Ecrivain, Lecteur};

use crate::corps::{CORPS_MAX, GENRE_EXPLOITANT, INVITATION_CORPS_OCTETS, NOM_MACHINE_MAX};

/// Le champ qui porte une étiquette.
const CHAMP_ETIQUETTE: &str = "etiquette";

/// Le champ qui porte un compte.
const CHAMP_COMPTE: &str = "compte";

/// Ce qu'un identifiant occupe en octets sur le fil : son genre, puis ses
/// seize octets — la forme de `POST /v1/defi`.
pub const IDENTIFIANT_OCTETS: usize = 17;

/// Le corps de `POST /v1/administrateurs` : le genre `o`, la signature de
/// l'exploitant, puis le compte nommé — celui de `POST /v1/invitations`, et
/// dix-sept octets de plus.
pub const NOMINATION_CORPS_OCTETS: usize = INVITATION_CORPS_OCTETS + IDENTIFIANT_OCTETS;

/// Refuse un corps trop long, avant d'y lire quoi que ce soit.
const fn borner(octets: &[u8]) -> Result<(), Erreur> {
    if octets.len() > CORPS_MAX {
        return Err(Erreur::MessageTropLong {
            obtenue: octets.len(),
        });
    }
    Ok(())
}

/// Lit `{"<champ>": <chaîne>}` et rend la chaîne, le lecteur à la fin.
fn un_seul_champ<'a>(octets: &'a [u8], champ: &str) -> Result<(Lecteur<'a>, usize), Erreur> {
    borner(octets)?;
    let mut lecteur = Lecteur::nouveau(octets);
    lecteur.attendre(b'{', "un objet")?;
    let position = lecteur.position();
    if lecteur.chaine()? != champ {
        return Err(Erreur::ChampInconnu { position });
    }
    lecteur.attendre(b':', "deux-points")?;
    let position = lecteur.position();
    Ok((lecteur, position))
}

// ── L'étiquette ─────────────────────────────────────────────────────────────

/// Le corps de `POST /v1/domaines/{d}/groupes` et de `PATCH /v1/groupes/{e}` :
/// une étiquette.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Etiquetage<'a> {
    /// L'étiquette.
    pub etiquette: &'a str,
}

impl<'a> Etiquetage<'a> {
    /// Décode `{"etiquette": "Famille"}`.
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage, plus [`Erreur::NomVide`] et [`Erreur::NomTropLong`].
    pub fn decoder(octets: &'a [u8]) -> Result<Self, Erreur> {
        let (mut lecteur, _) = un_seul_champ(octets, CHAMP_ETIQUETTE)?;
        let etiquette = lecteur.texte_libre()?;
        if etiquette.is_empty() {
            return Err(Erreur::NomVide);
        }
        if etiquette.len() > NOM_MACHINE_MAX {
            return Err(Erreur::NomTropLong {
                obtenue: etiquette.len(),
            });
        }
        lecteur.attendre(b'}', "la fin de l'objet")?;
        lecteur.fin()?;
        Ok(Self { etiquette })
    }
}

// ── Ajouter un compte ───────────────────────────────────────────────────────

/// Le corps de `POST /v1/groupes/{e}/membres`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Adhesion {
    /// Le compte à ajouter.
    pub compte: Identifiant,
}

impl Adhesion {
    /// Décode `{"compte": "u-…"}`.
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage, plus [`Erreur::IdentifiantInvalide`] quand ce n'est
    /// pas un `u-…`.
    pub fn decoder(octets: &[u8]) -> Result<Self, Erreur> {
        let (mut lecteur, position) = un_seul_champ(octets, CHAMP_COMPTE)?;
        let compte = Identifiant::analyser_genre(Genre::Utilisateur, lecteur.chaine()?)
            .map_err(|_| Erreur::IdentifiantInvalide { position })?;
        lecteur.attendre(b'}', "la fin de l'objet")?;
        lecteur.fin()?;
        Ok(Self { compte })
    }
}

// ── L'exploitant ────────────────────────────────────────────────────────────

/// Le corps de `POST /v1/administrateurs`, lu : la signature de l'exploitant
/// et le compte qu'il nomme. **La signature n'est pas jugée ici** — la clé vit
/// à l'étage 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nomination {
    /// Les soixante-quatre octets de la signature.
    pub signature: [u8; 64],
    /// Le compte nommé.
    pub compte: Identifiant,
}

impl Nomination {
    /// Lit `o ‖ signature ‖ u-…` : quatre-vingt-deux octets exactement.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::MessageTropLong`] sur un corps trop long,
    /// [`Erreur::JsonInattendu`] sur un corps trop court, [`Erreur::IdentifiantInvalide`] sur un autre genre que
    /// `o` en tête ou autre chose qu'un compte en queue.
    pub fn decoder(octets: &[u8]) -> Result<Self, Erreur> {
        let signature = signature_d_exploitant(octets, NOMINATION_CORPS_OCTETS)?;
        let queue = octets.get(INVITATION_CORPS_OCTETS..).unwrap_or_default();
        let compte =
            identifiant_brut(queue, Genre::Utilisateur).ok_or(Erreur::IdentifiantInvalide {
                position: INVITATION_CORPS_OCTETS,
            })?;
        Ok(Self { signature, compte })
    }
}

/// Lit `o ‖ signature` — le corps d'un retrait d'administrateur, qui nomme le
/// compte dans son chemin.
///
/// # Erreurs
///
/// Celles de [`Nomination::decoder`], pour soixante-cinq octets.
pub fn decoder_une_signature_d_exploitant(octets: &[u8]) -> Result<[u8; 64], Erreur> {
    signature_d_exploitant(octets, INVITATION_CORPS_OCTETS)
}

/// Le genre `o` en tête, puis la signature, sur un corps de cette longueur.
fn signature_d_exploitant(octets: &[u8], attendus: usize) -> Result<[u8; 64], Erreur> {
    if octets.len() > attendus {
        return Err(Erreur::MessageTropLong {
            obtenue: octets.len(),
        });
    }
    if octets.len() < attendus {
        return Err(Erreur::JsonInattendu {
            position: octets.len(),
        });
    }
    if octets.first() != Some(&GENRE_EXPLOITANT) {
        return Err(Erreur::IdentifiantInvalide { position: 0 });
    }
    let mut signature = [0_u8; 64];
    for (place, octet) in signature.iter_mut().zip(octets.iter().skip(1)) {
        *place = *octet;
    }
    Ok(signature)
}

/// Un identifiant en dix-sept octets — la lettre de son genre, puis ses seize
/// octets —, de ce genre exactement.
fn identifiant_brut(octets: &[u8], attendu: Genre) -> Option<Identifiant> {
    if octets.len() != IDENTIFIANT_OCTETS || octets.first() != Some(&attendu.prefixe()) {
        return None;
    }
    let mut seize = [0_u8; 16];
    for (place, octet) in seize.iter_mut().zip(octets.iter().skip(1)) {
        *place = *octet;
    }
    Some(Identifiant::depuis_entropie(attendu, seize))
}

// ── Ce que l'annuaire rend ──────────────────────────────────────────────────
//
// **L'ÉTIQUETTE SE RÉÉMET SANS ÉCHAPPEMENT**, comme un nom de machine : elle
// est entrée par `texte_libre`, qui a refusé à l'entrée ce qu'un encodeur JSON
// aurait à échapper.

/// Un groupe, tel que `GET /v1/groupes` et `GET /v1/groupes/{e}` le rendent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupeRendu<'a> {
    /// Son identifiant.
    pub groupe: Identifiant,
    /// Son domaine — rien pour un groupe personnel.
    pub domaine: Option<Identifiant>,
    /// Son étiquette, s'il en porte une.
    pub etiquette: Option<&'a str>,
    /// Sa sorte : `administrateurs`, `domaine`, `personnel`.
    pub sorte: &'a str,
}

impl GroupeRendu<'_> {
    /// Écrit les champs communs, sans l'accolade fermante.
    fn ecrire_les_champs(&self, ecrivain: &mut Ecrivain<'_>) {
        ecrivain.pousser(b"{\"groupe\":\"");
        ecrivain.pousser(self.groupe.texte().as_str().as_bytes());
        ecrivain.pousser(b"\",\"domaine\":");
        match self.domaine {
            Some(domaine) => {
                ecrivain.pousser(b"\"");
                ecrivain.pousser(domaine.texte().as_str().as_bytes());
                ecrivain.pousser(b"\"");
            }
            None => ecrivain.pousser(b"null"),
        }
        if let Some(etiquette) = self.etiquette {
            ecrivain.pousser(b",\"etiquette\":\"");
            ecrivain.pousser(etiquette.as_bytes());
            ecrivain.pousser(b"\"");
        }
        ecrivain.pousser(b",\"sorte\":\"");
        ecrivain.pousser(self.sorte.as_bytes());
        ecrivain.pousser(b"\"");
    }

    /// Écrit le groupe seul, fermé : ce que le détail d'un domaine liste.
    pub(crate) fn ecrire(&self, ecrivain: &mut Ecrivain<'_>) {
        self.ecrire_les_champs(ecrivain);
        ecrivain.pousser(b"}");
    }

    /// Encode un groupe de la liste : ses champs, puis `"membre"`.
    ///
    /// ```jsonc
    /// {"groupe":"e-…","domaine":"d-…","etiquette":"Famille","sorte":"domaine","membre":true}
    /// ```
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`].
    pub fn encoder_dans_la_liste(&self, membre: bool, sortie: &mut [u8]) -> Result<usize, Erreur> {
        let mut ecrivain = Ecrivain::nouveau(sortie);
        self.ecrire_les_champs(&mut ecrivain);
        ecrivain.pousser(if membre {
            b",\"membre\":true}".as_slice()
        } else {
            b",\"membre\":false}".as_slice()
        });
        ecrivain.achever()
    }

    /// Encode un groupe et ses membres : ses champs, puis `"membres":[…]`.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`].
    pub fn encoder_avec_ses_membres(
        &self,
        membres: &[Identifiant],
        sortie: &mut [u8],
    ) -> Result<usize, Erreur> {
        let mut ecrivain = Ecrivain::nouveau(sortie);
        self.ecrire_les_champs(&mut ecrivain);
        ecrivain.pousser(b",\"membres\":[");
        for (rang, membre) in membres.iter().enumerate() {
            if rang > 0 {
                ecrivain.pousser(b",");
            }
            ecrivain.pousser(b"\"");
            ecrivain.pousser(membre.texte().as_str().as_bytes());
            ecrivain.pousser(b"\"");
        }
        ecrivain.pousser(b"]}");
        ecrivain.achever()
    }
}
