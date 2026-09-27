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

// ── Les alias : du texte UTF-8, en NFC, SENSIBLE À LA CASSE ─────────────────

/// Ce qu'un alias de domaine occupe au plus, en octets UTF-8, APRÈS NFC.
pub const ALIAS_DE_DOMAINE_OCTETS_MAX: usize = 64;

/// Ce qu'un texte proposé comme alias de domaine peut faire AVANT le NFC.
///
/// La borne de soixante-quatre porte sur la forme rangée. Une forme
/// décomposée peut être plus longue et se recomposer en dessous ; on la
/// laisse entrer jusque-là, et c'est le résultat qui se mesure.
pub const ALIAS_DE_DOMAINE_BRUT_MAX: usize = 255;

/// Ce qu'un alias de machine occupe au plus, en octets UTF-8, APRÈS NFC :
/// la longueur d'un nom de domaine complet (RFC 1035 §2.3.4, deux cent
/// cinquante-trois caractères écrits), puisqu'il est fait pour pouvoir en
/// servir (`docs/modele.md` §2.3, 2026-09-27).
pub const ALIAS_DE_MACHINE_OCTETS_MAX: usize = 253;

/// Ce qu'un texte proposé comme alias de machine peut faire AVANT le NFC.
///
/// **Sous le corps d'une requête**, cinq cent douze octets
/// (`asl_api::corps::CORPS_MAX`) : `{"alias": "…"}` doit y tenir.
pub const ALIAS_DE_MACHINE_BRUT_MAX: usize = 480;

/// La version d'Unicode du NFC, épinglée (`docs/modele.md` §2.11) : celle
/// que la crate `unicode-normalization`, à version fixée, embarque.
///
/// **Il n'y a plus de table de pliage** (0.26.0, décision 45) : les alias
/// sont sensibles à la casse, et seul le NFC reste à épingler.
pub const UNICODE: (u8, u8, u8) = unicode_normalization::UNICODE_VERSION;

/// Un texte UTF-8 **en forme normalisée NFC**, d'au plus `N` octets rangés,
/// admis brut jusqu'à `BRUT` octets.
///
/// # UNE RÈGLE, TROIS ALIAS
///
/// L'alias de domaine, l'alias de machine et l'alias de compte sont trois
/// textes différents par leur borne et par ce qu'on en fait — le premier se
/// cherche, le deuxième sert de nom d'hôte, le troisième est unique —, et un
/// seul par leur forme : non vide, UTF-8, NFC, **sensible à la casse**, sans
/// contrôle C0, DEL, C1, forceur de sens d'écriture ni marque d'ordre des
/// octets, sans `"` ni `\` que la grammaire JSON de l'API refuse et qu'un pair
/// ne doit pas pouvoir faire entrer par la réplication. La règle vit une fois,
/// ici.
///
/// # SENSIBLE À LA CASSE, ET C'EST UNE DÉCISION
///
/// `docs/replication.md`, décision 45 (Thierry, 2026-09-27) : « Maison » et
/// « maison » sont deux alias. Le NFC reste — une même chaîne saisie
/// composée ou décomposée est une seule chaîne ; ce n'est pas une question de
/// casse, c'est une question d'écriture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AliasNfc<const N: usize, const BRUT: usize> {
    /// La forme rangée.
    texte: Court<N>,
}

/// Un alias de domaine, prêt à ranger.
pub type AliasDeDomaine = AliasNfc<ALIAS_DE_DOMAINE_OCTETS_MAX, ALIAS_DE_DOMAINE_BRUT_MAX>;

/// Un alias de machine, prêt à ranger.
pub type AliasDeMachine = AliasNfc<ALIAS_DE_MACHINE_OCTETS_MAX, ALIAS_DE_MACHINE_BRUT_MAX>;

impl<const N: usize, const BRUT: usize> AliasNfc<N, BRUT> {
    /// Normalise ce texte en NFC, le vérifie, et le range.
    ///
    /// # Errors
    ///
    /// [`Faute::Vide`] s'il ne porte rien, [`Faute::NonImprimable`] sur un
    /// caractère refusé (la position est celle du caractère dans la forme
    /// NFC, en octets), [`Faute::Longueur`] si la forme NFC dépasse `N`
    /// octets — ou si le texte brut dépasse `BRUT`, avant même qu'on le
    /// normalise.
    pub fn nouveau(texte: &str) -> Result<Self, Faute> {
        let mut rangees = [0_u8; N];
        let longueur = normaliser(texte, BRUT, &mut rangees)?;
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

    /// Écrit cet alias. Occupe `1 + N`.
    fn ecrire(&self, sortie: &mut [u8]) {
        self.texte.ecrire(sortie);
    }

    /// Relit un alias rangé, et EXIGE sa forme canonique.
    ///
    /// **La relecture repasse par [`AliasNfc::nouveau`]** et compare : un
    /// alias rangé qui ne serait pas son propre NFC, ou qui porterait un
    /// caractère refusé, n'est pas un alias — c'est une corruption, ou un pair
    /// qui a mal écrit.
    fn lire(octets: &[u8]) -> Result<Self, Faute> {
        let lu = Court::<N>::lire(octets)?;
        let texte = core::str::from_utf8(lu.octets()).map_err(|_| Faute::NonNormalise)?;
        let refait = Self::nouveau(texte).map_err(|_| Faute::NonNormalise)?;
        if refait.octets() == lu.octets() {
            Ok(refait)
        } else {
            Err(Faute::NonNormalise)
        }
    }
}

/// Ce caractère est-il refusé dans un alias ?
///
/// Les règles du nom de machine d'avant 0.26.0 — contrôles C0 et DEL, C1,
/// forceurs de sens d'écriture, marque d'ordre des octets —, et les deux
/// caractères que la grammaire JSON de l'API refuse dans un texte libre.
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
fn normaliser<const N: usize>(
    texte: &str,
    brut_max: usize,
    sortie: &mut [u8; N],
) -> Result<usize, Faute> {
    if texte.len() > brut_max {
        return Err(Faute::Longueur {
            annoncee: texte.len(),
            maximum: brut_max,
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
    if longueur > N {
        return Err(Faute::Longueur {
            annoncee: longueur,
            maximum: N,
        });
    }
    Ok(longueur)
}

// ── L'alias de compte ───────────────────────────────────────────────────────

/// Ce qu'un alias de compte fait au moins, en octets, après NFC.
pub const ALIAS_DE_COMPTE_OCTETS_MIN: usize = 3;

/// Ce qu'un texte proposé comme alias de compte peut faire AVANT le NFC.
pub const ALIAS_DE_COMPTE_BRUT_MAX: usize = 255;

/// Normalise et vérifie un alias de compte, et le rend prêt à ranger.
///
/// # UNIQUE, SENSIBLE À LA CASSE, ET QU'IL NE RESSEMBLE PAS À UN `u-…`
///
/// `docs/modele.md` §2.1 (0.26.0, décision 46) : la forme des autres alias —
/// UTF-8, NFC, sensible à la casse —, entre trois et trente-deux octets
/// rangés, **et un deuxième caractère qui n'est pas un tiret** : dans les
/// applications, un utilisateur tape soit un identifiant, soit un alias, dans
/// le même champ, et les deux formes ne doivent pas pouvoir se confondre.
/// **Il reste UNIQUE** : c'est par lui qu'on retrouve quelqu'un. « Thierry »
/// et « thierry » sont deux alias, que deux comptes peuvent tenir.
///
/// # Errors
///
/// Celles d'[`AliasNfc::nouveau`], et [`Faute::Forme`] pour un alias de
/// moins de trois octets ou dont le deuxième caractère est un tiret.
pub fn alias_de_compte(texte: &str) -> Result<crate::AliasRange, Faute> {
    let alias = AliasNfc::<{ crate::ALIAS_OCTETS_MAX }, ALIAS_DE_COMPTE_BRUT_MAX>::nouveau(texte)?;
    if alias.octets().len() < ALIAS_DE_COMPTE_OCTETS_MIN
        || alias.texte().chars().nth(1) == Some('-')
    {
        return Err(Faute::Forme);
    }
    Ok(alias.texte)
}

// ── Le nom de machine : un nom d'hôte ───────────────────────────────────────

/// Ce qu'un nom de machine fait au plus : une étiquette DNS (RFC 1123 §2.1).
pub const NOM_D_HOTE_OCTETS_MAX: usize = 63;

/// Vérifie qu'un nom de machine peut servir de nom d'hôte, et le rend en
/// minuscules.
///
/// # LA RÈGLE : UNE ÉTIQUETTE RFC 1123
///
/// `docs/modele.md` §2.3 (0.26.0, décision 47) : lettres ASCII, chiffres et
/// tiret, un à soixante-trois octets, ni tiret en tête ni tiret en queue.
/// C'est ce qu'accepte `hostname`, ce qu'un résolveur accepte comme
/// étiquette, et ce qu'on peut écrire devant un domaine sans l'encoder.
///
/// # RANGÉ EN MINUSCULES
///
/// Le DNS compare les noms sans casse (RFC 4343) : « Grenier » et
/// « grenier » sont le même hôte. Garder la casse saisie en comparant sans
/// elle ferait porter la règle à chaque lecteur ; **ranger une forme, une
/// seule**, la fait porter à l'écriture, une fois. L'alias de machine, lui,
/// garde la casse : c'est du texte choisi, pas un nom d'hôte.
///
/// # Errors
///
/// [`Faute::Vide`] pour un nom vide, [`Faute::Longueur`] au-delà de
/// soixante-trois octets, [`Faute::Forme`] pour tout le reste.
pub fn nom_d_hote(texte: &str) -> Result<crate::NomRange, Faute> {
    let octets = texte.as_bytes();
    if octets.is_empty() {
        return Err(Faute::Vide);
    }
    if octets.len() > NOM_D_HOTE_OCTETS_MAX {
        return Err(Faute::Longueur {
            annoncee: octets.len(),
            maximum: NOM_D_HOTE_OCTETS_MAX,
        });
    }
    let admis = octets
        .iter()
        .all(|octet| octet.is_ascii_alphanumeric() || *octet == b'-');
    if !admis || octets.first() == Some(&b'-') || octets.last() == Some(&b'-') {
        return Err(Faute::Forme);
    }
    let mut minuscules = [0_u8; crate::NOM_OCTETS_MAX];
    for (place, octet) in minuscules.iter_mut().zip(octets) {
        *place = octet.to_ascii_lowercase();
    }
    // De l'ASCII, et au plus soixante-trois octets : les deux se tiennent.
    crate::NomRange::nouveau(
        core::str::from_utf8(minuscules.get(..octets.len()).unwrap_or_default())
            .unwrap_or_default(),
    )
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

// ── L'alias posé d'un domaine, d'une machine ────────────────────────────────

/// Écrit une pose d'alias — provenance, estampille, puis l'alias ou rien —
/// dans cette sortie, qui a la taille de l'enregistrement.
fn ecrire_une_pose<const N: usize, const BRUT: usize>(
    provenance: Provenance,
    estampille: Estampille,
    alias: Option<&AliasNfc<N, BRUT>>,
    sortie: &mut [u8],
) {
    sortie.fill(0);
    provenance.ecrire(sortie.get_mut(..PROVENANCE_OCTETS).unwrap_or_default());
    let apres_estampille = PROVENANCE_OCTETS.saturating_add(ESTAMPILLE_OCTETS);
    estampille.ecrire(
        sortie
            .get_mut(PROVENANCE_OCTETS..apres_estampille)
            .unwrap_or_default(),
    );
    if let Some(alias) = alias {
        let reste = sortie.get_mut(apres_estampille..).unwrap_or_default();
        poser_un(reste, 1);
        alias.ecrire(reste.get_mut(1..).unwrap_or_default());
    }
}

/// Relit ce qu'[`ecrire_une_pose`] a écrit.
fn lire_une_pose<const N: usize, const BRUT: usize>(
    octets: &[u8],
) -> Result<(Provenance, Estampille, Option<AliasNfc<N, BRUT>>), Faute> {
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
        1 => Some(AliasNfc::lire(reste.get(1..).unwrap_or_default())?),
        lue => return Err(Faute::Etiquette { lue }),
    };
    Ok((provenance, estampille, alias))
}

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
        ecrire_une_pose(
            self.provenance,
            self.estampille,
            self.alias.as_ref(),
            sortie,
        );
    }

    /// Relit un alias posé.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas un alias posé, et
    /// [`Faute::NonNormalise`] si l'alias n'est pas dans sa forme canonique.
    pub fn lire(octets: &[u8; ALIAS_DE_DOMAINE_RANGE_OCTETS]) -> Result<Self, Faute> {
        let (provenance, estampille, alias) = lire_une_pose(octets)?;
        Ok(Self {
            provenance,
            estampille,
            alias,
        })
    }
}

/// Ce que l'alias posé d'une machine occupe.
pub const ALIAS_DE_MACHINE_RANGE_OCTETS: usize =
    PROVENANCE_OCTETS + ESTAMPILLE_OCTETS + 1 + 1 + ALIAS_DE_MACHINE_OCTETS_MAX;

/// L'alias d'une machine, ou son retrait, avec son estampille
/// (`docs/modele.md` §2.3, 0.26.0).
///
/// # UN CHAMP DE LA MACHINE, RANGÉ À PART — COMME LE RATTACHEMENT
///
/// L'enregistrement de machine a une taille que des bases réelles portent ;
/// l'agrandir aurait été une reprise de format pour un champ que la plupart
/// des machines n'ont pas. **Le plus récent gagne**, comme l'alias de
/// domaine : il n'est pas unique, il se remplace, et son retrait garde son
/// estampille.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AliasDeMachineRange {
    /// D'où vient cet enregistrement.
    pub provenance: Provenance,
    /// La dernière pose ou le dernier retrait.
    pub estampille: Estampille,
    /// L'alias, ou rien s'il a été retiré.
    pub alias: Option<AliasDeMachine>,
}

impl AliasDeMachineRange {
    /// Écrit cet alias posé.
    pub fn ecrire(&self, sortie: &mut [u8; ALIAS_DE_MACHINE_RANGE_OCTETS]) {
        ecrire_une_pose(
            self.provenance,
            self.estampille,
            self.alias.as_ref(),
            sortie,
        );
    }

    /// Relit un alias posé.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas un alias posé, et
    /// [`Faute::NonNormalise`] si l'alias n'est pas dans sa forme canonique.
    pub fn lire(octets: &[u8; ALIAS_DE_MACHINE_RANGE_OCTETS]) -> Result<Self, Faute> {
        let (provenance, estampille, alias) = lire_une_pose(octets)?;
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
        ALIAS_DE_MACHINE_BRUT_MAX, ALIAS_DE_MACHINE_OCTETS_MAX, ALIAS_DE_MACHINE_RANGE_OCTETS,
        AliasDeDomaine, AliasDeDomaineRange, AliasDeMachine, AliasDeMachineRange, DOMAINE_OCTETS,
        Domaine, RATTACHEMENT_OCTETS, Rattachement, UNICODE, alias_de_compte, nom_d_hote,
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
    fn un_alias_est_sensible_a_la_casse_mais_pas_a_l_ecriture() {
        // Décision 45 : « Maison » et « maison » sont deux alias.
        let maison = AliasDeDomaine::nouveau("Maison").unwrap();
        assert_ne!(maison, AliasDeDomaine::nouveau("maison").unwrap());
        assert_ne!(maison, AliasDeDomaine::nouveau("MAISON").unwrap());
        // Le « ſ » long n'est pas un « s » : aucun pli (le pliage de casse
        // l'aurait rabattu, le NFC le laisse).
        assert_eq!(
            AliasDeDomaine::nouveau("\u{017F}").unwrap().octets(),
            "\u{017F}".as_bytes()
        );
        // Mais le NFC reste : « É » décomposé est « É » composé.
        assert_eq!(
            AliasDeDomaine::nouveau("E\u{0301}").unwrap(),
            AliasDeDomaine::nouveau("É").unwrap()
        );
    }

    #[test]
    fn la_version_d_unicode_est_celle_du_nfc() {
        // Il ne reste que le NFC à épingler (`docs/modele.md` §2.11).
        assert_eq!(UNICODE, unicode_normalization::UNICODE_VERSION);
        assert_eq!(UNICODE, (17, 0, 0));
    }

    // ── L'alias de machine ──────────────────────────────────────────────────

    #[test]
    fn un_alias_de_machine_tient_un_nom_complet_et_rien_de_plus() {
        let fqdn = "a".repeat(ALIAS_DE_MACHINE_OCTETS_MAX);
        assert_eq!(
            AliasDeMachine::nouveau(&fqdn).unwrap().octets().len(),
            ALIAS_DE_MACHINE_OCTETS_MAX
        );
        let trop = "a".repeat(ALIAS_DE_MACHINE_OCTETS_MAX + 1);
        assert_eq!(
            AliasDeMachine::nouveau(&trop),
            Err(Faute::Longueur {
                annoncee: ALIAS_DE_MACHINE_OCTETS_MAX + 1,
                maximum: ALIAS_DE_MACHINE_OCTETS_MAX,
            })
        );
        let brut = "a".repeat(ALIAS_DE_MACHINE_BRUT_MAX + 1);
        assert_eq!(
            AliasDeMachine::nouveau(&brut),
            Err(Faute::Longueur {
                annoncee: ALIAS_DE_MACHINE_BRUT_MAX + 1,
                maximum: ALIAS_DE_MACHINE_BRUT_MAX,
            })
        );
        // Tout autre chose qu'un « nom.domaine » : c'est voulu.
        assert!(AliasDeMachine::nouveau("Le Grenier — serveur été").is_ok());
        assert_eq!(
            AliasDeMachine::nouveau("a\u{0000}"),
            Err(Faute::NonImprimable { position: 1 })
        );
    }

    #[test]
    fn un_alias_de_machine_pose_fait_l_aller_retour() {
        for alias in [
            None,
            Some(AliasDeMachine::nouveau("Grenier.Maison").unwrap()),
        ] {
            let pose = AliasDeMachineRange {
                provenance: Provenance::Annuaire(un(Genre::Annuaire, 9)),
                estampille: e(8),
                alias,
            };
            let mut octets = [0_u8; ALIAS_DE_MACHINE_RANGE_OCTETS];
            pose.ecrire(&mut octets);
            assert_eq!(AliasDeMachineRange::lire(&octets), Ok(pose));
        }
    }

    // ── L'alias de compte ───────────────────────────────────────────────────

    #[test]
    fn un_alias_de_compte_est_sensible_a_la_casse_et_ne_ressemble_pas_a_un_identifiant() {
        // Décision 46 : « Thierry » et « thierry » sont deux alias.
        let grand = alias_de_compte("Thierry").unwrap();
        let petit = alias_de_compte("thierry").unwrap();
        assert_ne!(grand, petit);
        // En NFC, et de l'UTF-8.
        assert_eq!(
            alias_de_compte("Ame\u{0301}lie").unwrap().octets(),
            "Amélie".as_bytes()
        );
        // Trop court, ou qui ressemble à un `u-…`.
        assert_eq!(alias_de_compte("ab"), Err(Faute::Forme));
        assert_eq!(alias_de_compte("u-thierry"), Err(Faute::Forme));
        assert_eq!(alias_de_compte("é-a"), Err(Faute::Forme));
        // Trente-deux octets rangés au plus.
        assert!(alias_de_compte(&"a".repeat(32)).is_ok());
        assert_eq!(
            alias_de_compte(&"a".repeat(33)),
            Err(Faute::Longueur {
                annoncee: 33,
                maximum: 32,
            })
        );
        assert_eq!(alias_de_compte(""), Err(Faute::Vide));
    }

    // ── Le nom de machine ───────────────────────────────────────────────────

    #[test]
    fn un_nom_de_machine_est_une_etiquette_d_hote_rangee_en_minuscules() {
        assert_eq!(nom_d_hote("grenier").unwrap().octets(), b"grenier");
        assert_eq!(
            nom_d_hote("Serveur-Cave2").unwrap().octets(),
            b"serveur-cave2"
        );
        assert_eq!(nom_d_hote(&"a".repeat(63)).unwrap().longueur(), 63);
        assert_eq!(nom_d_hote(""), Err(Faute::Vide));
        assert_eq!(
            nom_d_hote(&"a".repeat(64)),
            Err(Faute::Longueur {
                annoncee: 64,
                maximum: 63,
            })
        );
        for refuse in [
            "-grenier",
            "grenier-",
            "le grenier",
            "grenier.maison",
            "été",
            "a_b",
        ] {
            assert_eq!(nom_d_hote(refuse), Err(Faute::Forme), "{refuse:?}");
        }
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
