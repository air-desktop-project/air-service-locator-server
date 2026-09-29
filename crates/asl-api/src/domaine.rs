//! Les domaines sur le fil (`protocole.md` §2.2, 2026-09-26) : ce qu'une
//! application envoie pour créer un domaine, poser son alias, y rattacher une
//! machine, et ce que l'annuaire lui rend.
//!
//! # L'ALIAS ARRIVE BRUT, ET C'EST `asl-registre` QUI LE NORMALISE
//!
//! Un alias de domaine est du texte libre UTF-8 : il passe par
//! [`asl_proto::cadrage::Lecteur::texte_libre`], qui refuse ce que le cadrage
//! JSON de ce dépôt ne sait pas porter — `"`, `\`, les contrôles, les
//! forceurs de sens d'écriture. **Sa forme NFC et sa borne de soixante-quatre
//! octets vivent dans `asl-registre`**, une fois : la
//! même règle doit tenir à la pose, à la relecture et à la réplication, et
//! une seconde copie ici finirait par diverger. Cette grammaire-ci ne borne
//! que le texte BRUT, à [`ALIAS_BRUT_MAX`] octets, avant toute
//! normalisation.

use asl_id::{Genre, Identifiant};
use asl_proto::Erreur;
use asl_proto::cadrage::{Ecrivain, Lecteur};

use crate::corps::CORPS_MAX;

/// Ce que le texte brut d'un alias de domaine peut faire, au plus, en octets.
///
/// **Égal à `asl_registre::ALIAS_DE_DOMAINE_BRUT_MAX`**, et `asl-session` —
/// qui connaît les deux — tient l'égalité. La borne de la forme RANGÉE,
/// soixante-quatre octets après NFC, se mesure là-bas, sur le résultat.
pub const ALIAS_BRUT_MAX: usize = 255;

/// Le champ qui porte un alias de domaine.
const CHAMP_ALIAS: &str = "alias";

/// Le champ qui porte un domaine.
const CHAMP_DOMAINE: &str = "domaine";

/// Ce que `heberge_par` dit d'un domaine que les racines tiennent — le cas de
/// tout domaine qu'aucun annuaire local accepté n'héberge (0.27.0).
pub const HEBERGE_PAR_LES_RACINES: &str = "racines";

/// Les quatre droits qu'un propriétaire tient sur son domaine
/// (`modele.md` §2.13), dans l'ordre où ils s'écrivent.
pub const DROITS_DU_PROPRIETAIRE: [&str; 4] = ["administrer", "rattacher", "voir", "localiser"];

/// Ce qu'un membre du groupe d'administrateurs peut sur un domaine qu'il ne
/// possède pas : l'administrer, y ranger SES machines, et voir ce qui y est
/// rangé — `administrer` emporte `rattacher` et `voir` (`modele.md` §2.13,
/// 0.25.0). Ce qu'un compte peut vraiment sur un domaine est la RÉUNION de ses
/// droits, que l'étage 3 calcule ; ce tableau n'en est que le cas ordinaire.
pub const DROITS_D_UN_ADMINISTRATEUR: [&str; 3] = ["administrer", "rattacher", "voir"];

/// Ce qu'un administrateur des racines peut sur le domaine racine : les
/// quatre, comme le propriétaire d'un domaine ordinaire (0.39.0,
/// `replication.md` décision 88) — juger des inscriptions (`modele.md`
/// §2.12), y ranger SES machines, voir ce qui y est rangé, localiser. Rien de
/// cela ne descend dans les domaines du niveau 1.
pub const DROITS_SUR_LE_DOMAINE_RACINE: [&str; 4] = DROITS_DU_PROPRIETAIRE;

/// Lit un alias de domaine brut : une chaîne libre, non vide, au plus
/// [`ALIAS_BRUT_MAX`] octets.
fn lire_un_alias<'a>(lecteur: &mut Lecteur<'a>) -> Result<&'a str, Erreur> {
    lire_un_alias_jusqu_a(lecteur, ALIAS_BRUT_MAX)
}

/// Lit un alias brut d'au plus `brut_max` octets.
fn lire_un_alias_jusqu_a<'a>(
    lecteur: &mut Lecteur<'a>,
    brut_max: usize,
) -> Result<&'a str, Erreur> {
    let texte = lecteur.texte_libre()?;
    if texte.is_empty() {
        return Err(Erreur::NomVide);
    }
    if texte.len() > brut_max {
        return Err(Erreur::NomTropLong {
            obtenue: texte.len(),
        });
    }
    Ok(texte)
}

/// Refuse un corps trop long, avant d'y lire quoi que ce soit.
const fn borner(octets: &[u8]) -> Result<(), Erreur> {
    if octets.len() > CORPS_MAX {
        return Err(Erreur::MessageTropLong {
            obtenue: octets.len(),
        });
    }
    Ok(())
}

// ── Créer un domaine ────────────────────────────────────────────────────────

/// Le corps de `POST /v1/domaines` : un alias, facultatif.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreationDeDomaine<'a> {
    /// L'alias demandé d'emblée, brut, ou rien.
    pub alias: Option<&'a str>,
}

impl<'a> CreationDeDomaine<'a> {
    /// Décode une création de domaine.
    ///
    /// ```jsonc
    /// {}
    /// {"alias": "Maison"}
    /// ```
    ///
    /// **Un corps vide vaut `{}`** : créer un domaine sans alias est le cas
    /// courant, et exiger deux accolades pour ne rien dire serait une
    /// cérémonie.
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage, plus [`Erreur::NomVide`] et [`Erreur::NomTropLong`].
    pub fn decoder(octets: &'a [u8]) -> Result<Self, Erreur> {
        borner(octets)?;
        if octets.is_empty() {
            return Ok(Self { alias: None });
        }
        let mut lecteur = Lecteur::nouveau(octets);
        lecteur.attendre(b'{', "un objet")?;
        lecteur.sauter_blancs();
        if lecteur.regarder() == Some(b'}') {
            lecteur.avancer();
            lecteur.fin()?;
            return Ok(Self { alias: None });
        }
        let position = lecteur.position();
        if lecteur.chaine()? != CHAMP_ALIAS {
            return Err(Erreur::ChampInconnu { position });
        }
        lecteur.attendre(b':', "deux-points")?;
        let alias = lire_un_alias(&mut lecteur)?;
        lecteur.attendre(b'}', "la fin de l'objet")?;
        lecteur.fin()?;
        Ok(Self { alias: Some(alias) })
    }
}

// ── Poser l'alias d'un domaine ──────────────────────────────────────────────

/// Le corps de `PUT /v1/domaines/{d}/alias`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoseDAlias<'a> {
    /// L'alias demandé, brut.
    pub alias: &'a str,
}

impl<'a> PoseDAlias<'a> {
    /// Décode une pose d'alias : `{"alias": "Maison"}`.
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage, plus [`Erreur::NomVide`] et [`Erreur::NomTropLong`].
    pub fn decoder(octets: &'a [u8]) -> Result<Self, Erreur> {
        Self::decoder_jusqu_a(octets, ALIAS_BRUT_MAX)
    }

    /// Décode une pose d'alias dont le texte brut fait au plus `brut_max`
    /// octets : c'est le corps de `PUT /v1/machines/{m}/alias` aussi
    /// (0.26.0), dont l'alias est plus long qu'un alias de domaine.
    ///
    /// # Erreurs
    ///
    /// Celles de [`PoseDAlias::decoder`].
    pub fn decoder_jusqu_a(octets: &'a [u8], brut_max: usize) -> Result<Self, Erreur> {
        borner(octets)?;
        let mut lecteur = Lecteur::nouveau(octets);
        lecteur.attendre(b'{', "un objet")?;
        let position = lecteur.position();
        if lecteur.chaine()? != CHAMP_ALIAS {
            return Err(Erreur::ChampInconnu { position });
        }
        lecteur.attendre(b':', "deux-points")?;
        let alias = lire_un_alias_jusqu_a(&mut lecteur, brut_max)?;
        lecteur.attendre(b'}', "la fin de l'objet")?;
        lecteur.fin()?;
        Ok(Self { alias })
    }
}

// ── Rattacher une machine ───────────────────────────────────────────────────

/// Le corps de `PUT /v1/machines/{m}/domaine`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rattachement {
    /// Le domaine où ranger la machine.
    pub domaine: Identifiant,
}

impl Rattachement {
    /// Décode un rattachement : `{"domaine": "d-…"}`.
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage, plus [`Erreur::IdentifiantInvalide`] quand ce n'est
    /// pas un `d-…`.
    pub fn decoder(octets: &[u8]) -> Result<Self, Erreur> {
        borner(octets)?;
        let mut lecteur = Lecteur::nouveau(octets);
        lecteur.attendre(b'{', "un objet")?;
        let position = lecteur.position();
        if lecteur.chaine()? != CHAMP_DOMAINE {
            return Err(Erreur::ChampInconnu { position });
        }
        lecteur.attendre(b':', "deux-points")?;
        let position = lecteur.position();
        let domaine = Identifiant::analyser_genre(Genre::Domaine, lecteur.chaine()?)
            .map_err(|_| Erreur::IdentifiantInvalide { position })?;
        lecteur.attendre(b'}', "la fin de l'objet")?;
        lecteur.fin()?;
        Ok(Self { domaine })
    }
}

// ── Ce que l'annuaire rend ──────────────────────────────────────────────────
//
// **LES TEXTES SE RÉÉMETTENT SANS ÉCHAPPEMENT, ET C'EST SÛR** : un alias de
// domaine rangé ne porte ni `"`, ni `\`, ni contrôle — `asl-registre` le
// vérifie à la pose ET à la relecture, y compris de ce qu'un pair réplique —,
// et un nom de machine est entré par `texte_libre`. Ce sont précisément les
// caractères qu'un encodeur JSON aurait à échapper.

/// Un domaine tel que `GET /v1/domaines` le rend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomaineRendu<'a> {
    /// Son identifiant.
    pub domaine: Identifiant,
    /// Le compte qui le possède.
    pub proprietaire: Identifiant,
    /// L'annuaire local qui l'héberge effectivement — ou rien : les racines
    /// (0.27.0).
    pub heberge_par: Option<Identifiant>,
    /// Son alias, en NFC, s'il en a un.
    pub alias: Option<&'a str>,
    /// Ce que le demandeur peut sur lui — l'union de ses droits
    /// (`modele.md` §2.13).
    pub droits: &'a [&'a str],
    /// Sa sorte, **pour le seul domaine racine** : [`SORTE_DU_DOMAINE_RACINE`]
    /// (0.39.0, décision 88). Absente pour un domaine ordinaire. Avec les
    /// quatre droits, le domaine racine ne se distingue plus d'un domaine
    /// qu'on possède ; ce champ dit aux applications ce qu'il n'accepte pas —
    /// être confié à un annuaire local, être supprimé.
    pub sorte: Option<&'a str>,
}

/// La sorte du domaine racine, dans `GET /v1/domaines` et
/// `GET /v1/domaines/{d}` : `"sorte":"racine"`. **Une chaîne, et non un
/// booléen** : un décodeur déployé qui lit par clés l'ignore, là où un type
/// nouveau pourrait le faire échouer. Elle ne se confond pas avec la `sorte`
/// d'un groupe (`administrateurs`, `domaine`, `personnel`) : un autre objet,
/// et des valeurs disjointes.
pub const SORTE_DU_DOMAINE_RACINE: &str = "racine";

impl DomaineRendu<'_> {
    /// Encode un domaine rendu.
    ///
    /// ```jsonc
    /// {"domaine":"d-…","proprietaire":"u-…","alias":"Maison",
    ///  "heberge_par":"racines","droits":["administrer","rattacher","voir","localiser"]}
    /// ```
    ///
    /// `alias` est **absent**, pas `null`, quand il n'y en a pas : c'est la
    /// convention des objets de ce dépôt. `sorte` de même, et elle vient en
    /// dernier : `…,"droits":[…],"sorte":"racine"}` pour le seul domaine racine.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`].
    pub fn encoder(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        let mut ecrivain = Ecrivain::nouveau(sortie);
        self.ecrire_les_champs(&mut ecrivain);
        ecrivain.pousser(b"}");
        ecrivain.achever()
    }

    /// Écrit l'objet sans son accolade fermante — ce que
    /// [`DomaineDetaille`] complète.
    fn ecrire_les_champs(&self, ecrivain: &mut Ecrivain<'_>) {
        ecrivain.pousser(b"{\"domaine\":\"");
        ecrivain.pousser(self.domaine.texte().as_str().as_bytes());
        ecrivain.pousser(b"\",\"proprietaire\":\"");
        ecrivain.pousser(self.proprietaire.texte().as_str().as_bytes());
        ecrivain.pousser(b"\"");
        if let Some(alias) = self.alias {
            ecrivain.pousser(b",\"alias\":\"");
            ecrivain.pousser(alias.as_bytes());
            ecrivain.pousser(b"\"");
        }
        ecrivain.pousser(b",\"heberge_par\":\"");
        match self.heberge_par {
            Some(annuaire) => ecrivain.pousser(annuaire.texte().as_str().as_bytes()),
            None => ecrivain.pousser(HEBERGE_PAR_LES_RACINES.as_bytes()),
        }
        ecrivain.pousser(b"\",\"droits\":[");
        for (rang, droit) in self.droits.iter().enumerate() {
            if rang > 0 {
                ecrivain.pousser(b",");
            }
            ecrivain.pousser(b"\"");
            ecrivain.pousser(droit.as_bytes());
            ecrivain.pousser(b"\"");
        }
        ecrivain.pousser(b"]");
        if let Some(sorte) = self.sorte {
            ecrivain.pousser(b",\"sorte\":\"");
            ecrivain.pousser(sorte.as_bytes());
            ecrivain.pousser(b"\"");
        }
    }
}

/// Une machine rangée dans un domaine, telle que `GET /v1/domaines/{d}` la
/// rend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachineDeDomaine<'a> {
    /// La machine.
    pub machine: Identifiant,
    /// Son propriétaire — qui peut n'être pas celui du domaine.
    pub proprietaire: Identifiant,
    /// Son nom, quand le demandeur a droit de le voir ; absent sinon
    /// (`protocole.md` §2.2).
    pub nom: Option<&'a str>,
    /// Son alias, sous la même condition que le nom, et s'il en a un
    /// (0.26.0).
    pub alias: Option<&'a str>,
}

impl MachineDeDomaine<'_> {
    /// Encode une machine de domaine :
    /// `{"machine":"m-…","proprietaire":"u-…","nom":"grenier"}`.
    fn ecrire(&self, ecrivain: &mut Ecrivain<'_>) {
        ecrivain.pousser(b"{\"machine\":\"");
        ecrivain.pousser(self.machine.texte().as_str().as_bytes());
        ecrivain.pousser(b"\",\"proprietaire\":\"");
        ecrivain.pousser(self.proprietaire.texte().as_str().as_bytes());
        ecrivain.pousser(b"\"");
        if let Some(nom) = self.nom {
            ecrivain.pousser(b",\"nom\":\"");
            ecrivain.pousser(nom.as_bytes());
            ecrivain.pousser(b"\"");
        }
        if let Some(alias) = self.alias {
            ecrivain.pousser(b",\"alias\":\"");
            ecrivain.pousser(alias.as_bytes());
            ecrivain.pousser(b"\"");
        }
        ecrivain.pousser(b"}");
    }
}

/// Un domaine, ses groupes et ses machines, tels que `GET /v1/domaines/{d}`
/// les rend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomaineDetaille<'a> {
    /// Le domaine.
    pub domaine: DomaineRendu<'a>,
    /// Ses groupes, son groupe d'administrateurs compris (2026-09-27).
    pub groupes: &'a [crate::groupe::GroupeRendu<'a>],
    /// Les machines qui y sont rattachées.
    pub machines: &'a [MachineDeDomaine<'a>],
}

impl DomaineDetaille<'_> {
    /// Encode un domaine, ses groupes et ses machines : les champs de
    /// [`DomaineRendu`], puis `"groupes":[…]` et `"machines":[…]`.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`].
    pub fn encoder(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        let mut ecrivain = Ecrivain::nouveau(sortie);
        self.domaine.ecrire_les_champs(&mut ecrivain);
        ecrivain.pousser(b",\"groupes\":[");
        for (rang, groupe) in self.groupes.iter().enumerate() {
            if rang > 0 {
                ecrivain.pousser(b",");
            }
            groupe.ecrire(&mut ecrivain);
        }
        ecrivain.pousser(b"],\"machines\":[");
        for (rang, machine) in self.machines.iter().enumerate() {
            if rang > 0 {
                ecrivain.pousser(b",");
            }
            machine.ecrire(&mut ecrivain);
        }
        ecrivain.pousser(b"]}");
        ecrivain.achever()
    }
}

/// Un domaine trouvé par son alias : `{"domaine":"d-…","autorite":"racines"|"n-…"}`.
///
/// **Ni propriétaire, ni machine** (`protocole.md` §2.2) : savoir qu'un
/// domaine « Maison » existe n'ouvre rien.
///
/// # `autorite` SE LIT, ELLE NE S'ÉCRIT PAS EN DUR
///
/// Jusqu'à 0.28.0, ce champ valait toujours `racines`, même pour un domaine
/// confié à un annuaire local — or c'est précisément ce que la recherche
/// promet de dire : **qui fait autorité** (`protocole.md` §2.2). Il porte
/// désormais la même valeur que `heberge_par` de [`DomaineRendu`], lue par le
/// même chemin (`hebergeur_de_domaine`) : les deux verbes ne peuvent plus se
/// contredire sur un même domaine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomaineTrouve {
    /// Le domaine.
    pub domaine: Identifiant,
    /// L'annuaire local qui l'héberge, ou `None` pour les racines — comme
    /// [`DomaineRendu::heberge_par`].
    pub autorite: Option<Identifiant>,
}

impl DomaineTrouve {
    /// Encode un domaine trouvé.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`].
    pub fn encoder(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        let mut ecrivain = Ecrivain::nouveau(sortie);
        ecrivain.pousser(b"{\"domaine\":\"");
        ecrivain.pousser(self.domaine.texte().as_str().as_bytes());
        ecrivain.pousser(b"\",\"autorite\":\"");
        match self.autorite {
            Some(annuaire) => ecrivain.pousser(annuaire.texte().as_str().as_bytes()),
            None => ecrivain.pousser(HEBERGE_PAR_LES_RACINES.as_bytes()),
        }
        ecrivain.pousser(b"\"}");
        ecrivain.achever()
    }
}

// ── L'alias cherché, dans la chaîne de requête ──────────────────────────────

/// L'alias que porte `GET /v1/domaines?alias=…`, **tel qu'il est écrit** —
/// pourcent-encodé —, et déjà vérifié : il se décode.
///
/// # LE SEUL ENDROIT OÙ CE ROUTAGE DÉCODE UN POURCENT, ET POURQUOI
///
/// Le chemin refuse tout `%` (voir [`crate::resoudre`]) : un segment a une
/// seule écriture, et un encodage en ouvrirait deux. **Un alias de domaine
/// n'a pas le choix** — c'est de l'UTF-8 libre, « Maison été », et une URL
/// ne porte que de l'ASCII. Il arrive donc encodé, et se décode ici, octet
/// par octet ; ce qu'il décode est ensuite normalisé en NFC par
/// `asl-registre`, qui rend la même forme quelle que soit l'écriture reçue —
/// **la casse, elle, compte** (0.26.0, décision 45). Il sert aussi la
/// résolution d'un alias de compte en UTF-8 (`/v1/alias?alias=…`). Deux
/// écritures du même alias ne désignent donc jamais deux choses différentes :
/// elles cherchent la même.
///
/// **Il garde la forme encodée, pas le décodé** : la ressource est une
/// valeur qu'on copie, et deux cent cinquante-cinq octets de plus dans
/// chacune de ses variantes coûteraient à toutes les requêtes ce qu'une seule
/// demande. Le décodage se refait là où il sert, dans un tampon de
/// l'appelant ([`AliasCherche::decoder`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AliasCherche<'a> {
    /// La valeur de `alias=`, encodée, vérifiée.
    encode: &'a [u8],
}

/// Ce qu'un alias cherché occupe une fois décodé : c'est la taille du tampon
/// que [`AliasCherche::decoder`] demande.
pub type TamponDAlias = [u8; ALIAS_BRUT_MAX];

impl<'a> AliasCherche<'a> {
    /// Lit `alias=<pourcent-encodé>`, et rien d'autre.
    ///
    /// Chaque octet est soit `%HH` — deux chiffres hexadécimaux, dans l'une
    /// ou l'autre casse —, soit un caractère ASCII graphique qui n'est ni
    /// `%`, ni `&`, ni `+`, ni `=`, ni `#`. **`+` n'est pas une espace** : ce
    /// n'est pas un formulaire, et le lire comme tel donnerait deux écritures
    /// de l'espace. Le résultat doit être de l'UTF-8, non vide, au plus
    /// [`ALIAS_BRUT_MAX`] octets.
    ///
    /// # Erreurs
    ///
    /// [`crate::Erreur::RequeteInvalide`] pour tout le reste.
    pub(crate) fn depuis_requete(requete: &'a [u8]) -> Result<Self, crate::Erreur> {
        let encode = requete
            .strip_prefix(b"alias=")
            .ok_or(crate::Erreur::RequeteInvalide)?;
        let mut tampon = [0_u8; ALIAS_BRUT_MAX];
        decoder_dans(encode, &mut tampon)?;
        Ok(Self { encode })
    }

    /// Le texte décodé, dans ce tampon.
    ///
    /// Vérifié à la construction : le décodage ne peut plus échouer, et le
    /// repli sur le vide ne se prend pas.
    #[must_use]
    pub fn decoder<'t>(&self, tampon: &'t mut TamponDAlias) -> &'t str {
        decoder_dans(self.encode, tampon).unwrap_or_default()
    }
}

/// Décode ces octets pourcent-encodés dans ce tampon, et rend le texte.
fn decoder_dans<'t>(encode: &[u8], tampon: &'t mut TamponDAlias) -> Result<&'t str, crate::Erreur> {
    let mut longueur = 0_usize;
    let mut reste = encode;
    while let Some((&premier, suite)) = reste.split_first() {
        let (octet, apres) = if premier == b'%' {
            let haut = suite.first().copied().and_then(chiffre_hexadecimal);
            let bas = suite.get(1).copied().and_then(chiffre_hexadecimal);
            match (haut, bas) {
                (Some(haut), Some(bas)) => (
                    haut.saturating_mul(16).saturating_add(bas),
                    suite.get(2..).unwrap_or_default(),
                ),
                _ => return Err(crate::Erreur::RequeteInvalide),
            }
        } else if premier.is_ascii_graphic() && !b"%&+=#".contains(&premier) {
            (premier, suite)
        } else {
            return Err(crate::Erreur::RequeteInvalide);
        };
        let place = tampon
            .get_mut(longueur)
            .ok_or(crate::Erreur::RequeteInvalide)?;
        *place = octet;
        longueur = longueur.saturating_add(1);
        reste = apres;
    }
    if longueur == 0 {
        return Err(crate::Erreur::RequeteInvalide);
    }
    core::str::from_utf8(tampon.get(..longueur).unwrap_or_default())
        .map_err(|_| crate::Erreur::RequeteInvalide)
}

/// La valeur d'un chiffre hexadécimal, dans l'une ou l'autre casse.
const fn chiffre_hexadecimal(octet: u8) -> Option<u8> {
    match octet {
        b'0'..=b'9' => Some(octet.saturating_sub(b'0')),
        b'a'..=b'f' => Some(octet.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Some(octet.saturating_sub(b'A').saturating_add(10)),
        _ => None,
    }
}
