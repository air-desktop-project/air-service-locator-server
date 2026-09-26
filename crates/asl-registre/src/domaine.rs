//! Les domaines (`docs/modele.md` §2.11, 2026-09-26) : le premier domaine d'un
//! compte, l'alias de domaine et sa clé de recherche, et les trois
//! enregistrements que l'entrepôt range — le domaine, son alias, le
//! rattachement d'une machine.
//!
//! # POURQUOI L'ALIAS SE VÉRIFIE ICI, ALORS QUE LES AUTRES TEXTES NE LE SONT PAS
//!
//! L'en-tête de la crate le dit : l'alphabet d'un alias de compte et d'un nom
//! de service n'est pas revérifié à la relecture, parce qu'il appartient à la
//! grammaire qui l'a admis. **L'alias de domaine est l'exception, pour deux
//! raisons.** Il se COMPARE — sa forme rangée doit être une et une seule, ou
//! deux écritures d'une même chaîne ne se trouveraient pas l'une l'autre. Et
//! il se RÉPLIQUE avec sa forme : une racine qui recevrait d'une autre un
//! alias non normalisé le rangerait tel quel, et la recherche divergerait
//! entre les deux. La règle vit donc une fois, ici, et la relecture d'un
//! enregistrement la reprend : un alias qui n'est pas dans sa forme canonique
//! n'est pas un alias.

use asl_id::{Genre, Identifiant};
use unicode_normalization::UnicodeNormalization as _;

use crate::plis::PLIS;
use crate::{
    Court, ESTAMPILLE_OCTETS, Estampille, Faute, IDENTIFIANT_OCTETS, PROVENANCE_OCTETS, Provenance,
    bourrage_nul, ecrire_identifiant, lire_identifiant, poser, poser_un,
};

// ── Le premier domaine ──────────────────────────────────────────────────────

/// Le séparateur de domaine du **premier domaine** d'un compte.
///
/// Le mot « domaine » a deux sens ici, et c'est malheureux : celui-ci est le
/// séparateur d'un condensat, comme `asl_cle::DOMAINE_IDENTITE_RACINE` ; le
/// domaine qu'il produit est un lieu où l'on range des machines.
pub const SEPARATEUR_PREMIER_DOMAINE: &[u8] = b"air-service-locator/v1/premier-domaine\x00";

/// Le premier domaine de ce compte.
///
/// # DÉDUIT, ET NON TIRÉ — POUR TOUS LES COMPTES
///
/// `docs/modele.md` §2.11 : les comptes d'avant les domaines reçoivent le
/// leur à la reprise de l'entrepôt, et chaque racine la fait de son côté ; un
/// identifiant tiré en donnerait deux. **Les comptes nouveaux le reçoivent de
/// la même façon** : chaque racine le fait naître en appliquant l'opération
/// `compte`, sous l'estampille du compte, et les deux arrivent au même
/// enregistrement octet pour octet, sans qu'une opération de plus voyage. Le
/// premier domaine d'un compte n'est jamais « à départager ».
///
/// Les seize premiers octets d'un SHA-256 à séparateur du compte : qui
/// connaît un `u-…` peut calculer ce `d-…`, et n'y apprend rien — un domaine
/// ne rend ni machine ni service à qui n'y a pas droit, et le `u-…` est déjà
/// public.
#[must_use]
pub fn premier_domaine(compte: Identifiant) -> Identifiant {
    use sha2::Digest as _;
    let mut condensat = sha2::Sha256::new();
    condensat.update(SEPARATEUR_PREMIER_DOMAINE);
    condensat.update(compte.octets());
    let entier = condensat.finalize();
    let mut seize = [0_u8; 16];
    poser(&mut seize, &entier);
    Identifiant::depuis_entropie(Genre::Domaine, seize)
}

// ── L'alias de domaine ──────────────────────────────────────────────────────

/// Ce qu'un alias de domaine occupe au plus, en octets UTF-8, APRÈS NFC.
pub const ALIAS_DE_DOMAINE_OCTETS_MAX: usize = 64;

/// Ce qu'une clé de recherche occupe au plus.
///
/// **Le pliage peut allonger** : un caractère de deux octets se plie parfois
/// en un de trois (`Ⱥ`, U+023A, en `ⱥ`, U+2C65), jamais davantage — l'essai
/// `un_pli_n_allonge_jamais_de_plus_d_un_octet` le tient sur toute la table.
/// Soixante-quatre octets de caractères de deux octets donnent donc au plus
/// quatre-vingt-seize ; cent vingt-huit laisse de la marge sans rien coûter.
pub const CLEF_DE_RECHERCHE_OCTETS_MAX: usize = 128;

/// Ce qu'un texte proposé comme alias peut faire AVANT le NFC.
///
/// La borne de soixante-quatre porte sur la forme rangée. Une forme
/// décomposée peut être plus longue et se recomposer en dessous ; on la
/// laisse entrer jusque-là, et c'est le résultat qui se mesure.
pub const ALIAS_DE_DOMAINE_BRUT_MAX: usize = 255;

/// La version d'Unicode du NFC et du pliage, épinglée (`docs/modele.md`
/// §2.11, 2026-09-26).
pub const UNICODE: (u8, u8, u8) = crate::plis::VERSION;

/// Un alias de domaine, **en forme normalisée NFC**, prêt à ranger.
///
/// Les règles sont celles du nom de machine (`docs/modele.md` §2.3) — non
/// vide, UTF-8, sans contrôle C0, DEL, C1, forceur de sens d'écriture ni
/// marque d'ordre des octets —, plus deux : pas de `"` ni de `\`, que la
/// grammaire JSON de l'API refuse déjà à l'entrée et qu'un pair ne doit pas
/// pouvoir faire entrer par la réplication ; et la forme NFC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AliasDeDomaine {
    /// La forme rangée.
    texte: Court<ALIAS_DE_DOMAINE_OCTETS_MAX>,
}

impl AliasDeDomaine {
    /// Normalise ce texte en NFC, le vérifie, et le range.
    ///
    /// # Errors
    ///
    /// [`Faute::Vide`] s'il ne porte rien, [`Faute::NonImprimable`] sur un
    /// caractère refusé (la position est celle du caractère dans la forme
    /// NFC, en octets), [`Faute::Longueur`] si la forme NFC dépasse
    /// [`ALIAS_DE_DOMAINE_OCTETS_MAX`] octets — ou si le texte brut dépasse
    /// [`ALIAS_DE_DOMAINE_BRUT_MAX`], avant même qu'on le normalise.
    pub fn nouveau(texte: &str) -> Result<Self, Faute> {
        let mut rangees = [0_u8; ALIAS_DE_DOMAINE_OCTETS_MAX];
        let longueur = normaliser(texte, &mut rangees)?;
        Ok(Self {
            texte: Court {
                octets: rangees,
                longueur,
            },
        })
    }

    /// Ce qu'il porte, en octets UTF-8.
    #[must_use]
    pub fn octets(&self) -> &[u8] {
        self.texte.octets()
    }

    /// Ce qu'il porte, en texte.
    #[must_use]
    pub fn texte(&self) -> &str {
        // Construit par `nouveau` ou relu par `lire`, qui l'ont tous deux
        // vérifié : c'est de l'UTF-8, et l'autre bras ne se prend pas.
        core::str::from_utf8(self.octets()).unwrap_or_default()
    }

    /// Sa clé de recherche : sa forme NFC, pliée.
    #[must_use]
    pub fn clef(&self) -> ClefDeRecherche {
        plier(self.texte())
    }

    /// Écrit cet alias. Occupe `1 + ALIAS_DE_DOMAINE_OCTETS_MAX`.
    fn ecrire(&self, sortie: &mut [u8]) {
        self.texte.ecrire(sortie);
    }

    /// Relit un alias rangé, et EXIGE sa forme canonique.
    ///
    /// **La relecture repasse par [`AliasDeDomaine::nouveau`]** et compare :
    /// un alias rangé qui ne serait pas son propre NFC, ou qui porterait un
    /// caractère refusé, n'est pas un alias — c'est une corruption, ou un pair
    /// qui a mal écrit.
    fn lire(octets: &[u8]) -> Result<Self, Faute> {
        let lu = Court::<ALIAS_DE_DOMAINE_OCTETS_MAX>::lire(octets)?;
        let texte = core::str::from_utf8(lu.octets()).map_err(|_| Faute::NonNormalise)?;
        let refait = Self::nouveau(texte).map_err(|_| Faute::NonNormalise)?;
        if refait.octets() == lu.octets() {
            Ok(refait)
        } else {
            Err(Faute::NonNormalise)
        }
    }
}

/// Une clé de recherche d'alias : le NFC plié. C'est ce que l'index range, et
/// ce qu'une recherche compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClefDeRecherche {
    /// Les octets, dont seuls les premiers comptent.
    octets: [u8; CLEF_DE_RECHERCHE_OCTETS_MAX],
    /// Combien en comptent.
    longueur: usize,
}

impl ClefDeRecherche {
    /// La clé de ce qu'on cherche.
    ///
    /// **La même normalisation qu'à la pose** : ce qu'on tape passe par
    /// [`AliasDeDomaine::nouveau`], puis se plie. Un texte qu'on n'aurait pas
    /// pu poser ne trouve rien — et le dit, plutôt que de chercher une forme
    /// qui ne peut pas exister.
    ///
    /// # Errors
    ///
    /// Celles d'[`AliasDeDomaine::nouveau`].
    pub fn de(texte: &str) -> Result<Self, Faute> {
        Ok(AliasDeDomaine::nouveau(texte)?.clef())
    }

    /// Ce qu'elle porte.
    #[must_use]
    pub fn octets(&self) -> &[u8] {
        self.octets.get(..self.longueur).unwrap_or_default()
    }
}

/// Ce caractère est-il refusé dans un alias de domaine ?
///
/// Les règles du nom de machine — contrôles C0 et DEL, C1, forceurs de sens
/// d'écriture, marque d'ordre des octets —, et les deux caractères que la
/// grammaire JSON de l'API refuse dans un texte libre.
const fn refuse(caractere: char) -> bool {
    matches!(
        caractere,
        '\u{0000}'..='\u{001F}'
            | '\u{007F}'..='\u{009F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
            | '"'
            | '\\'
    )
}

/// Met ce texte en NFC dans ce tableau, en vérifiant chaque caractère, et
/// rend la longueur écrite.
fn normaliser(texte: &str, sortie: &mut [u8; ALIAS_DE_DOMAINE_OCTETS_MAX]) -> Result<usize, Faute> {
    if texte.len() > ALIAS_DE_DOMAINE_BRUT_MAX {
        return Err(Faute::Longueur {
            annoncee: texte.len(),
            maximum: ALIAS_DE_DOMAINE_BRUT_MAX,
        });
    }
    let mut longueur = 0_usize;
    for caractere in texte.chars().nfc() {
        if refuse(caractere) {
            return Err(Faute::NonImprimable { position: longueur });
        }
        let mut tampon = [0_u8; 4];
        let encode = caractere.encode_utf8(&mut tampon).as_bytes();
        let fin = longueur.saturating_add(encode.len());
        // Au-delà, on continue de compter pour dire la longueur réelle.
        poser(sortie.get_mut(longueur..).unwrap_or_default(), encode);
        longueur = fin;
    }
    if longueur == 0 {
        return Err(Faute::Vide);
    }
    if longueur > ALIAS_DE_DOMAINE_OCTETS_MAX {
        return Err(Faute::Longueur {
            annoncee: longueur,
            maximum: ALIAS_DE_DOMAINE_OCTETS_MAX,
        });
    }
    Ok(longueur)
}

/// Plie ce texte, caractère par caractère, par le pliage SIMPLE d'Unicode.
///
/// Un caractère pour un caractère, la même table partout, sans dépendre d'une
/// langue : le `I` se plie en `i` ici comme à Istanbul, et deux racines qui
/// répondent à la même question répondent pareil (`docs/modele.md` §2.11).
fn plier(texte: &str) -> ClefDeRecherche {
    let mut clef = ClefDeRecherche {
        octets: [0_u8; CLEF_DE_RECHERCHE_OCTETS_MAX],
        longueur: 0,
    };
    for caractere in texte.chars() {
        let plie = plier_un(caractere);
        let mut tampon = [0_u8; 4];
        let encode = plie.encode_utf8(&mut tampon).as_bytes();
        poser(
            clef.octets.get_mut(clef.longueur..).unwrap_or_default(),
            encode,
        );
        // Borné par construction : un alias fait au plus soixante-quatre
        // octets, et le pliage allonge d'un octet au plus par caractère.
        clef.longueur = clef
            .longueur
            .saturating_add(encode.len())
            .min(CLEF_DE_RECHERCHE_OCTETS_MAX);
    }
    clef
}

/// Ce en quoi ce caractère se plie — lui-même, s'il ne se plie pas.
fn plier_un(caractere: char) -> char {
    let code = u32::from(caractere);
    match PLIS.binary_search_by_key(&code, |&(de, _)| de) {
        Ok(rang) => PLIS
            .get(rang)
            .and_then(|&(_, vers)| char::from_u32(vers))
            .unwrap_or(caractere),
        Err(_) => caractere,
    }
}

// ── Le domaine ──────────────────────────────────────────────────────────────

/// Ce qu'un domaine occupe.
pub const DOMAINE_OCTETS: usize =
    PROVENANCE_OCTETS + ESTAMPILLE_OCTETS + IDENTIFIANT_OCTETS + 1 + ESTAMPILLE_OCTETS;

/// Un domaine : un lieu où l'on range des machines (`docs/modele.md` §2.11).
///
/// # CE QUI N'EST PAS ICI, ET POURQUOI
///
/// L'alias vit à part ([`AliasDeDomaineRange`]) : il change, le plus récent
/// gagne, et il a donc sa propre estampille. Les machines aussi
/// ([`Rattachement`]) : le rattachement est UN champ de la machine, pas une
/// liste du domaine. Le domaine lui-même ne porte que ce qui ne change jamais
/// — qui le possède, et quand il est né — et la marque de sa suppression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Domaine {
    /// D'où vient cet enregistrement.
    pub provenance: Provenance,
    /// Sa naissance. **C'est elle qui départage les suppressions
    /// concurrentes** (`docs/replication.md` §3.2) : si elles laissaient le
    /// compte sans domaine, le plus petit reste.
    pub estampille: Estampille,
    /// Le compte qui le possède — un seul, toujours.
    pub proprietaire: Identifiant,
    /// Supprimé, et sous quelle estampille — ou vivant. La marque reste :
    /// elle refuse ce qui arriverait après pour lui, elle sert la règle des
    /// suppressions concurrentes, et un instantané la rejoue sous l'estampille
    /// de la suppression, pas sous celle de la naissance.
    pub supprime: Option<Estampille>,
}

impl Domaine {
    /// Écrit ce domaine.
    pub fn ecrire(&self, sortie: &mut [u8; DOMAINE_OCTETS]) {
        self.provenance
            .ecrire(sortie.get_mut(..PROVENANCE_OCTETS).unwrap_or_default());
        let apres_estampille = PROVENANCE_OCTETS.saturating_add(ESTAMPILLE_OCTETS);
        self.estampille.ecrire(
            sortie
                .get_mut(PROVENANCE_OCTETS..apres_estampille)
                .unwrap_or_default(),
        );
        ecrire_identifiant(
            self.proprietaire,
            sortie.get_mut(apres_estampille..).unwrap_or_default(),
        );
        let marque = sortie
            .get_mut(apres_estampille.saturating_add(IDENTIFIANT_OCTETS)..)
            .unwrap_or_default();
        match self.supprime {
            Some(quand) => {
                poser_un(marque, 1);
                quand.ecrire(marque.get_mut(1..).unwrap_or_default());
            }
            None => marque.fill(0),
        }
    }

    /// Relit un domaine.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas un domaine.
    pub fn lire(octets: &[u8; DOMAINE_OCTETS]) -> Result<Self, Faute> {
        let provenance = Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?;
        let apres_estampille = PROVENANCE_OCTETS.saturating_add(ESTAMPILLE_OCTETS);
        let estampille = Estampille::lire(
            octets
                .get(PROVENANCE_OCTETS..apres_estampille)
                .unwrap_or_default(),
        )?;
        let proprietaire = lire_identifiant(
            octets.get(apres_estampille..).unwrap_or_default(),
            Genre::Utilisateur,
        )?;
        let marque = octets
            .get(apres_estampille.saturating_add(IDENTIFIANT_OCTETS)..)
            .unwrap_or_default();
        let supprime = match marque.first().copied().unwrap_or(0) {
            0 => {
                if !bourrage_nul(marque.get(1..).unwrap_or_default()) {
                    return Err(Faute::Bourrage);
                }
                None
            }
            1 => Some(Estampille::lire(marque.get(1..).unwrap_or_default())?),
            lue => return Err(Faute::Etiquette { lue }),
        };
        Ok(Self {
            provenance,
            estampille,
            proprietaire,
            supprime,
        })
    }
}

// ── L'alias posé d'un domaine ───────────────────────────────────────────────

/// Ce qu'un alias posé occupe.
pub const ALIAS_DE_DOMAINE_RANGE_OCTETS: usize =
    PROVENANCE_OCTETS + ESTAMPILLE_OCTETS + 1 + 1 + ALIAS_DE_DOMAINE_OCTETS_MAX;

/// L'alias d'un domaine, ou son retrait, avec son estampille.
///
/// **Le plus récent gagne** (`docs/replication.md` §3.2) : l'alias de
/// domaine n'est pas unique, il se remplace comme un nom. Le retrait est une
/// écriture comme une autre — `alias: None` —, et il garde son estampille,
/// pour qu'une pose plus ancienne arrivée en retard ne ressuscite rien.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AliasDeDomaineRange {
    /// D'où vient cet enregistrement.
    pub provenance: Provenance,
    /// La dernière pose ou le dernier retrait.
    pub estampille: Estampille,
    /// L'alias, ou rien s'il a été retiré.
    pub alias: Option<AliasDeDomaine>,
}

impl AliasDeDomaineRange {
    /// Écrit cet alias posé.
    pub fn ecrire(&self, sortie: &mut [u8; ALIAS_DE_DOMAINE_RANGE_OCTETS]) {
        sortie.fill(0);
        self.provenance
            .ecrire(sortie.get_mut(..PROVENANCE_OCTETS).unwrap_or_default());
        let apres_estampille = PROVENANCE_OCTETS.saturating_add(ESTAMPILLE_OCTETS);
        self.estampille.ecrire(
            sortie
                .get_mut(PROVENANCE_OCTETS..apres_estampille)
                .unwrap_or_default(),
        );
        if let Some(alias) = &self.alias {
            let reste = sortie.get_mut(apres_estampille..).unwrap_or_default();
            poser_un(reste, 1);
            alias.ecrire(reste.get_mut(1..).unwrap_or_default());
        }
    }

    /// Relit un alias posé.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas un alias posé, et
    /// [`Faute::NonNormalise`] si l'alias n'est pas dans sa forme canonique.
    pub fn lire(octets: &[u8; ALIAS_DE_DOMAINE_RANGE_OCTETS]) -> Result<Self, Faute> {
        let provenance = Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?;
        let apres_estampille = PROVENANCE_OCTETS.saturating_add(ESTAMPILLE_OCTETS);
        let estampille = Estampille::lire(
            octets
                .get(PROVENANCE_OCTETS..apres_estampille)
                .unwrap_or_default(),
        )?;
        let reste = octets.get(apres_estampille..).unwrap_or_default();
        let alias = match reste.first().copied().unwrap_or(0) {
            0 => {
                if !bourrage_nul(reste.get(1..).unwrap_or_default()) {
                    return Err(Faute::Bourrage);
                }
                None
            }
            1 => Some(AliasDeDomaine::lire(reste.get(1..).unwrap_or_default())?),
            lue => return Err(Faute::Etiquette { lue }),
        };
        Ok(Self {
            provenance,
            estampille,
            alias,
        })
    }
}

// ── Le rattachement d'une machine ───────────────────────────────────────────

/// Ce qu'un rattachement occupe.
pub const RATTACHEMENT_OCTETS: usize =
    PROVENANCE_OCTETS + ESTAMPILLE_OCTETS + 1 + IDENTIFIANT_OCTETS;

/// Le domaine d'une machine, ou son absence, avec son estampille.
///
/// # UN CHAMP DE LA MACHINE, RANGÉ À PART
///
/// `docs/replication.md` §3.2 : « le rattachement d'une machine est UN champ
/// de la machine, et le dernier dit où elle est ». Il vit pourtant dans sa
/// propre table, comme la description d'un appareil : l'enregistrement de
/// machine a une taille que des bases réelles portent, et l'agrandir aurait
/// été une reprise de format pour un champ que la plupart des machines n'ont
/// pas. **Une machine sans rattachement rangé n'a pas de domaine**, et un
/// détachement est une écriture — `domaine: None` — qui garde son
/// estampille, pour qu'un rattachement plus ancien arrivé en retard ne la
/// remette pas où elle n'est plus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rattachement {
    /// D'où vient cet enregistrement.
    pub provenance: Provenance,
    /// Le dernier rattachement ou détachement.
    pub estampille: Estampille,
    /// Le domaine, ou rien.
    pub domaine: Option<Identifiant>,
}

impl Rattachement {
    /// Écrit ce rattachement.
    pub fn ecrire(&self, sortie: &mut [u8; RATTACHEMENT_OCTETS]) {
        sortie.fill(0);
        self.provenance
            .ecrire(sortie.get_mut(..PROVENANCE_OCTETS).unwrap_or_default());
        let apres_estampille = PROVENANCE_OCTETS.saturating_add(ESTAMPILLE_OCTETS);
        self.estampille.ecrire(
            sortie
                .get_mut(PROVENANCE_OCTETS..apres_estampille)
                .unwrap_or_default(),
        );
        if let Some(domaine) = self.domaine {
            let reste = sortie.get_mut(apres_estampille..).unwrap_or_default();
            poser_un(reste, 1);
            ecrire_identifiant(domaine, reste.get_mut(1..).unwrap_or_default());
        }
    }

    /// Relit un rattachement.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas un rattachement.
    pub fn lire(octets: &[u8; RATTACHEMENT_OCTETS]) -> Result<Self, Faute> {
        let provenance = Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?;
        let apres_estampille = PROVENANCE_OCTETS.saturating_add(ESTAMPILLE_OCTETS);
        let estampille = Estampille::lire(
            octets
                .get(PROVENANCE_OCTETS..apres_estampille)
                .unwrap_or_default(),
        )?;
        let reste = octets.get(apres_estampille..).unwrap_or_default();
        let domaine = match reste.first().copied().unwrap_or(0) {
            0 => {
                if !bourrage_nul(reste.get(1..).unwrap_or_default()) {
                    return Err(Faute::Bourrage);
                }
                None
            }
            1 => Some(lire_identifiant(
                reste.get(1..).unwrap_or_default(),
                Genre::Domaine,
            )?),
            lue => return Err(Faute::Etiquette { lue }),
        };
        Ok(Self {
            provenance,
            estampille,
            domaine,
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::string::String;

    use asl_id::{Genre, Identifiant};

    use super::{
        ALIAS_DE_DOMAINE_BRUT_MAX, ALIAS_DE_DOMAINE_OCTETS_MAX, ALIAS_DE_DOMAINE_RANGE_OCTETS,
        AliasDeDomaine, AliasDeDomaineRange, CLEF_DE_RECHERCHE_OCTETS_MAX, ClefDeRecherche,
        DOMAINE_OCTETS, Domaine, PLIS, RATTACHEMENT_OCTETS, Rattachement, UNICODE, plier_un,
        premier_domaine,
    };
    use crate::{
        ESTAMPILLE_OCTETS, Estampille, Faute, IDENTIFIANT_OCTETS, PROVENANCE_OCTETS, Provenance,
    };

    fn un(genre: Genre, graine: u8) -> Identifiant {
        Identifiant::depuis_entropie(genre, [graine; 16])
    }

    fn e(compteur: u64) -> Estampille {
        Estampille {
            compteur,
            racine: un(Genre::Annuaire, 0xEE),
        }
    }

    // ── Le premier domaine ──────────────────────────────────────────────────

    #[test]
    fn le_premier_domaine_se_deduit_du_compte_et_de_lui_seul() {
        let compte = un(Genre::Utilisateur, 1);
        let premier = premier_domaine(compte);
        assert_eq!(premier.genre(), Genre::Domaine);
        // Les deux racines font le même calcul, chacune de son côté.
        assert_eq!(premier_domaine(compte), premier);
        // Un autre compte, un autre domaine.
        assert_ne!(premier_domaine(un(Genre::Utilisateur, 2)), premier);
        // Et ce ne sont pas les octets du compte recopiés.
        assert_ne!(premier.octets(), compte.octets());
    }

    // ── L'alias ─────────────────────────────────────────────────────────────

    #[test]
    fn un_alias_se_range_en_nfc() {
        // « é » décomposé — e, puis l'accent aigu combinant — se range
        // composé : deux octets, pas trois.
        let decompose = "Maison \u{0065}\u{0301}t\u{0065}\u{0301}";
        let alias = AliasDeDomaine::nouveau(decompose).unwrap();
        assert_eq!(alias.texte(), "Maison été");
        assert_eq!(alias.octets(), "Maison été".as_bytes());
        assert_eq!(alias, AliasDeDomaine::nouveau("Maison été").unwrap());
    }

    #[test]
    fn un_alias_vide_ou_trop_long_est_refuse() {
        assert_eq!(AliasDeDomaine::nouveau(""), Err(Faute::Vide));
        let juste = "é".repeat(ALIAS_DE_DOMAINE_OCTETS_MAX / 2);
        assert!(AliasDeDomaine::nouveau(&juste).is_ok());
        let trop: String = "é".repeat(ALIAS_DE_DOMAINE_OCTETS_MAX / 2 + 1);
        assert_eq!(
            AliasDeDomaine::nouveau(&trop),
            Err(Faute::Longueur {
                annoncee: ALIAS_DE_DOMAINE_OCTETS_MAX + 2,
                maximum: ALIAS_DE_DOMAINE_OCTETS_MAX,
            })
        );
        // Une forme décomposée plus longue que soixante-quatre octets, qui se
        // recompose en dessous, entre : c'est la forme rangée qui se mesure.
        let decompose = "e\u{0301}".repeat(30);
        assert!(decompose.len() > ALIAS_DE_DOMAINE_OCTETS_MAX);
        assert_eq!(
            AliasDeDomaine::nouveau(&decompose).unwrap().octets().len(),
            60
        );
        // Mais le texte brut a sa propre borne, avant toute normalisation.
        let brut = "a".repeat(ALIAS_DE_DOMAINE_BRUT_MAX + 1);
        assert_eq!(
            AliasDeDomaine::nouveau(&brut),
            Err(Faute::Longueur {
                annoncee: ALIAS_DE_DOMAINE_BRUT_MAX + 1,
                maximum: ALIAS_DE_DOMAINE_BRUT_MAX,
            })
        );
    }

    #[test]
    fn un_caractere_refuse_est_nomme_par_sa_position() {
        for (texte, position) in [
            ("a\u{0000}", 1),
            ("ab\u{001F}", 2),
            ("\u{007F}", 0),
            ("é\u{0085}", 2),
            ("a\u{202E}b", 1),
            ("\u{2066}", 0),
            ("\u{FEFF}x", 0),
            ("a\"b", 1),
            ("a\\b", 1),
        ] {
            assert_eq!(
                AliasDeDomaine::nouveau(texte),
                Err(Faute::NonImprimable { position }),
                "{texte:?}"
            );
        }
    }

    #[test]
    fn la_recherche_plie_la_casse_sans_dependre_d_une_langue() {
        let maison = AliasDeDomaine::nouveau("Maison").unwrap();
        assert_eq!(maison.clef().octets(), b"maison");
        assert_eq!(ClefDeRecherche::de("MAISON").unwrap(), maison.clef());
        assert_eq!(ClefDeRecherche::de("maison").unwrap(), maison.clef());
        // Le signe Kelvin se plie en « k » : trois octets devenus un.
        assert_eq!(ClefDeRecherche::de("\u{212A}").unwrap().octets(), b"k");
        // Le « I » se plie en « i », pas en « ı » : pas de règle turque.
        assert_eq!(ClefDeRecherche::de("I").unwrap().octets(), b"i");
        // Un pli qui allonge : « Ⱥ » (deux octets) devient « ⱥ » (trois).
        assert_eq!(
            ClefDeRecherche::de("\u{023A}").unwrap().octets(),
            "\u{2C65}".as_bytes()
        );
        // Le pliage SIMPLE : « ß » reste « ß », il ne devient pas « ss ».
        assert_eq!(ClefDeRecherche::de("ß").unwrap().octets(), "ß".as_bytes());
        // La normalisation vient avant le pli : « É » décomposé trouve « é ».
        assert_eq!(
            ClefDeRecherche::de("E\u{0301}").unwrap(),
            ClefDeRecherche::de("é").unwrap()
        );
        // Ce qu'on n'aurait pas pu poser ne se cherche pas.
        assert_eq!(ClefDeRecherche::de(""), Err(Faute::Vide));
    }

    #[test]
    fn la_plus_longue_clef_tient_dans_son_tableau() {
        // Trente-deux « Ⱥ » : soixante-quatre octets rangés, quatre-vingt-seize
        // pliés.
        let alias = AliasDeDomaine::nouveau(&"\u{023A}".repeat(32)).unwrap();
        assert_eq!(alias.octets().len(), ALIAS_DE_DOMAINE_OCTETS_MAX);
        let clef = alias.clef();
        assert_eq!(clef.octets().len(), 96);
        assert!(clef.octets().len() <= CLEF_DE_RECHERCHE_OCTETS_MAX);
    }

    #[test]
    fn la_table_est_triee_et_n_allonge_jamais_de_plus_d_un_octet() {
        for paire in PLIS.windows(2) {
            assert!(paire[0].0 < paire[1].0, "{paire:?}");
        }
        for (de, vers) in PLIS {
            let de = char::from_u32(de).unwrap();
            let vers = char::from_u32(vers).unwrap();
            assert!(vers.len_utf8() <= de.len_utf8() + 1, "{de:?} → {vers:?}");
            assert_eq!(plier_un(de), vers);
        }
        // Un caractère qui ne se plie pas reste lui-même.
        assert_eq!(plier_un('a'), 'a');
        assert_eq!(plier_un('€'), '€');
    }

    #[test]
    fn la_version_d_unicode_est_la_meme_des_deux_cotes() {
        // Le NFC d'`unicode-normalization` et la table du pli : une seule
        // version, épinglée (`docs/modele.md` §2.11).
        assert_eq!(UNICODE, unicode_normalization::UNICODE_VERSION);
        assert_eq!(UNICODE, (17, 0, 0));
    }

    // ── Le domaine ──────────────────────────────────────────────────────────

    fn un_domaine(supprime: Option<Estampille>) -> Domaine {
        Domaine {
            provenance: Provenance::Annuaire(un(Genre::Annuaire, 9)),
            estampille: e(5),
            proprietaire: un(Genre::Utilisateur, 1),
            supprime,
        }
    }

    #[test]
    fn un_domaine_fait_l_aller_retour() {
        for supprime in [None, Some(e(9))] {
            let domaine = un_domaine(supprime);
            let mut octets = [0xFF_u8; DOMAINE_OCTETS];
            domaine.ecrire(&mut octets);
            assert_eq!(Domaine::lire(&octets), Ok(domaine));
        }
    }

    #[test]
    fn un_domaine_corrompu_est_refuse() {
        let mut octets = [0_u8; DOMAINE_OCTETS];
        un_domaine(Some(e(9))).ecrire(&mut octets);
        let marque = DOMAINE_OCTETS - 1 - ESTAMPILLE_OCTETS;
        let mut corrompu = octets;
        corrompu[marque] = 2;
        assert_eq!(Domaine::lire(&corrompu), Err(Faute::Etiquette { lue: 2 }));
        // « Vivant », mais une estampille derrière.
        let mut corrompu = octets;
        corrompu[marque] = 0;
        assert_eq!(Domaine::lire(&corrompu), Err(Faute::Bourrage));
        // Une estampille de suppression dont la racine n'est pas un annuaire.
        let mut corrompu = octets;
        corrompu[marque + 1 + 8] = b'u';
        assert_eq!(
            Domaine::lire(&corrompu),
            Err(Faute::Genre {
                attendu: Genre::Annuaire
            })
        );
        // Un propriétaire qui n'est pas un compte.
        let mut corrompu = octets;
        corrompu[PROVENANCE_OCTETS + ESTAMPILLE_OCTETS] = b'm';
        assert_eq!(
            Domaine::lire(&corrompu),
            Err(Faute::Genre {
                attendu: Genre::Utilisateur
            })
        );
        // Une estampille dont la racine n'est pas un annuaire.
        let mut corrompu = octets;
        corrompu[PROVENANCE_OCTETS + 8] = b'u';
        assert_eq!(
            Domaine::lire(&corrompu),
            Err(Faute::Genre {
                attendu: Genre::Annuaire
            })
        );
        // Une provenance inconnue.
        let mut corrompu = octets;
        corrompu[0] = 7;
        assert_eq!(Domaine::lire(&corrompu), Err(Faute::Etiquette { lue: 7 }));
    }

    // ── L'alias posé ────────────────────────────────────────────────────────

    #[test]
    fn un_alias_pose_ou_retire_fait_l_aller_retour() {
        for alias in [None, Some(AliasDeDomaine::nouveau("Maison été").unwrap())] {
            let range = AliasDeDomaineRange {
                provenance: Provenance::Ici,
                estampille: e(8),
                alias,
            };
            let mut octets = [0xFF_u8; ALIAS_DE_DOMAINE_RANGE_OCTETS];
            range.ecrire(&mut octets);
            assert_eq!(AliasDeDomaineRange::lire(&octets), Ok(range));
        }
    }

    #[test]
    fn un_alias_pose_corrompu_est_refuse() {
        let place = PROVENANCE_OCTETS + ESTAMPILLE_OCTETS;
        let pose = AliasDeDomaineRange {
            provenance: Provenance::Ici,
            estampille: e(8),
            alias: Some(AliasDeDomaine::nouveau("Maison").unwrap()),
        };
        let mut octets = [0_u8; ALIAS_DE_DOMAINE_RANGE_OCTETS];
        pose.ecrire(&mut octets);

        // Une présence qui n'est ni zéro ni un.
        let mut corrompu = octets;
        corrompu[place] = 3;
        assert_eq!(
            AliasDeDomaineRange::lire(&corrompu),
            Err(Faute::Etiquette { lue: 3 })
        );
        // « Rien », mais du texte derrière.
        let mut corrompu = octets;
        corrompu[place] = 0;
        assert_eq!(AliasDeDomaineRange::lire(&corrompu), Err(Faute::Bourrage));
        // Une longueur au-delà du tableau.
        let mut corrompu = octets;
        corrompu[place + 1] = 200;
        assert_eq!(
            AliasDeDomaineRange::lire(&corrompu),
            Err(Faute::Longueur {
                annoncee: 200,
                maximum: ALIAS_DE_DOMAINE_OCTETS_MAX,
            })
        );
        // Une forme qui n'est pas son NFC : « e » suivi de l'accent
        // combinant, rangé tel quel.
        let mut corrompu = [0_u8; ALIAS_DE_DOMAINE_RANGE_OCTETS];
        pose.ecrire(&mut corrompu);
        let decompose = "e\u{0301}".as_bytes();
        corrompu[place + 1] = u8::try_from(decompose.len()).unwrap();
        corrompu[place + 2..place + 2 + decompose.len()].copy_from_slice(decompose);
        corrompu[place + 2 + decompose.len()..].fill(0);
        assert_eq!(
            AliasDeDomaineRange::lire(&corrompu),
            Err(Faute::NonNormalise)
        );
        // Un caractère refusé, qu'un pair aurait fait entrer.
        let mut corrompu = octets;
        corrompu[place + 2] = b'"';
        assert_eq!(
            AliasDeDomaineRange::lire(&corrompu),
            Err(Faute::NonNormalise)
        );
        // De l'UTF-8 invalide.
        let mut corrompu = octets;
        corrompu[place + 2] = 0xFF;
        assert_eq!(
            AliasDeDomaineRange::lire(&corrompu),
            Err(Faute::NonNormalise)
        );
        // Une estampille corrompue.
        let mut corrompu = octets;
        corrompu[PROVENANCE_OCTETS + 8] = b'u';
        assert_eq!(
            AliasDeDomaineRange::lire(&corrompu),
            Err(Faute::Genre {
                attendu: Genre::Annuaire
            })
        );
        // Une provenance corrompue.
        let mut corrompu = octets;
        corrompu[0] = 7;
        assert_eq!(
            AliasDeDomaineRange::lire(&corrompu),
            Err(Faute::Etiquette { lue: 7 })
        );
    }

    // ── Le rattachement ─────────────────────────────────────────────────────

    #[test]
    fn un_rattachement_fait_l_aller_retour() {
        for domaine in [None, Some(un(Genre::Domaine, 4))] {
            let rattachement = Rattachement {
                provenance: Provenance::Ici,
                estampille: e(3),
                domaine,
            };
            let mut octets = [0xFF_u8; RATTACHEMENT_OCTETS];
            rattachement.ecrire(&mut octets);
            assert_eq!(Rattachement::lire(&octets), Ok(rattachement));
        }
    }

    #[test]
    fn un_rattachement_corrompu_est_refuse() {
        let place = PROVENANCE_OCTETS + ESTAMPILLE_OCTETS;
        let mut octets = [0_u8; RATTACHEMENT_OCTETS];
        Rattachement {
            provenance: Provenance::Ici,
            estampille: e(3),
            domaine: Some(un(Genre::Domaine, 4)),
        }
        .ecrire(&mut octets);

        let mut corrompu = octets;
        corrompu[place] = 2;
        assert_eq!(
            Rattachement::lire(&corrompu),
            Err(Faute::Etiquette { lue: 2 })
        );
        let mut corrompu = octets;
        corrompu[place] = 0;
        assert_eq!(Rattachement::lire(&corrompu), Err(Faute::Bourrage));
        let mut corrompu = octets;
        corrompu[place + 1] = b'u';
        assert_eq!(
            Rattachement::lire(&corrompu),
            Err(Faute::Genre {
                attendu: Genre::Domaine
            })
        );
        let mut corrompu = octets;
        corrompu[PROVENANCE_OCTETS + 8] = b'u';
        assert_eq!(
            Rattachement::lire(&corrompu),
            Err(Faute::Genre {
                attendu: Genre::Annuaire
            })
        );
        let mut corrompu = octets;
        corrompu[0] = 7;
        assert_eq!(
            Rattachement::lire(&corrompu),
            Err(Faute::Etiquette { lue: 7 })
        );
        // Et la taille est ce qu'on croit.
        assert_eq!(
            RATTACHEMENT_OCTETS,
            PROVENANCE_OCTETS + ESTAMPILLE_OCTETS + 1 + IDENTIFIANT_OCTETS
        );
    }
}
