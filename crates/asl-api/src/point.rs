//! Le point de poussée : la FORME d'une URL qu'un appareil dépose, et que
//! l'annuaire appellera (`protocole.md` §2.2, « Le point de poussée »,
//! 2026-09-25).
//!
//! # LA FORME EST DÉJÀ UNE DÉFENSE
//!
//! C'est la première fois qu'une racine se connecte à une adresse qu'elle n'a
//! pas choisie. La défense qui compte se prend à l'envoi — le nom résolu, et
//! chaque adresse rendue jugée (`asl-reveil`). Celle-ci se prend à la dépose,
//! et elle ferme ce qui n'a aucune raison d'être : un autre schéma qu'`https`,
//! une adresse littérale (le certificat se vérifie contre un nom, et une
//! adresse est la forme la plus directe d'une requête détournée), un autre
//! port que 443, des identifiants, un fragment.
//!
//! # UN SEUL ANALYSEUR, À LA DÉPOSE ET À L'ENVOI
//!
//! L'envoi relit le point rangé avec [`UrlDePoussee::analyser`], la même
//! fonction : ce que la dépose a accepté est ce que l'envoi comprend, et un
//! point venu de l'autre racine — ou d'une base corrompue — passe par la même
//! porte avant qu'un seul nom ne soit résolu.
//!
//! # CE QUI N'EST PAS UN ANALYSEUR D'URL GÉNÉRAL, ET NE DOIT PAS LE DEVENIR
//!
//! RFC 3986 admet mille écritures que ce module refuse : un schéma en
//! majuscules, un port écrit `0443`, un hôte entre crochets, un pourcentage
//! dans l'hôte. **Refuser n'a aucun coût** : un distributeur UnifiedPush
//! rend une URL canonique, et un point refusé se voit au `400` de la dépose,
//! sous les yeux de l'application qui l'a fait.

use asl_proto::Erreur;

/// Ce qu'un point peut faire, en octets. Égal à
/// `asl_registre::POINT_OCTETS_MAX` — recopié plutôt qu'importé, pour la
/// raison écrite sur [`crate::corps::NOM_MACHINE_MAX`] ; `asl-session` tient
/// l'égalité.
pub const POINT_MAX: usize = 1024;

/// La clé publique du récepteur (RFC 8291) : un point P-256 non compressé.
pub const CLE_RECEPTEUR_OCTETS: usize = 65;

/// Le secret d'authentification du récepteur (RFC 8291).
pub const SECRET_RECEPTEUR_OCTETS: usize = 16;

/// Ce qu'un nom DNS peut faire, en octets (RFC 1035 §2.3.4).
const NOM_DNS_MAX: usize = 253;

/// Ce qu'une étiquette DNS peut faire, en octets.
const ETIQUETTE_MAX: usize = 63;

/// Un point de poussée dont la forme tient.
///
/// Il ne porte que des tranches du texte analysé : l'hôte, pour résoudre et
/// pour le SNI, et la cible de la requête — le chemin et sa requête, tels
/// quels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UrlDePoussee<'a> {
    /// L'URL entière.
    texte: &'a str,
    /// Le nom DNS, sans port.
    hote: &'a str,
    /// Ce qui suit l'autorité : `/…`, `?…`, ou rien.
    suite: &'a str,
}

impl<'a> UrlDePoussee<'a> {
    /// Analyse un point.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::PointRefuse`], avec la règle enfreinte.
    pub fn analyser(texte: &'a str) -> Result<Self, Erreur> {
        let refus = |regle| Err(Erreur::PointRefuse { regle });
        if texte.len() > POINT_MAX {
            return refus("1024 octets au plus");
        }
        // **DE L'ASCII GRAPHIQUE, ET RIEN D'AUTRE** : ni espace, ni contrôle,
        // ni octet au-delà de 0x7E. C'est ce qui rend chaque tranche plus bas
        // sûre à couper à l'octet.
        if !texte.bytes().all(|octet| octet.is_ascii_graphic()) {
            return refus("de l'ASCII imprimable, sans espace");
        }
        if texte.contains('#') {
            return refus("pas de fragment");
        }
        let Some(reste) = texte.strip_prefix("https://") else {
            return refus("https:// et rien d'autre");
        };
        let fin_autorite = reste.find(['/', '?']).unwrap_or(reste.len());
        let (autorite, suite) = reste.split_at(fin_autorite);
        if autorite.contains('@') {
            return refus("pas d'identifiants");
        }
        // Un hôte entre crochets est une adresse IPv6 littérale : refusé ici,
        // avant que le deux-points qu'elle porte ne passe pour un port.
        if autorite.starts_with('[') {
            return refus("un nom DNS, pas une adresse");
        }
        let hote = match autorite.split_once(':') {
            None => autorite,
            Some((hote, "443")) => hote,
            Some(_) => return refus("le port 443, implicite ou écrit"),
        };
        nom_dns(hote)?;
        Ok(Self { texte, hote, suite })
    }

    /// L'URL entière, telle qu'elle a été déposée.
    #[must_use]
    pub const fn texte(&self) -> &'a str {
        self.texte
    }

    /// Le nom à résoudre, et à présenter en SNI et en `Host`.
    #[must_use]
    pub const fn hote(&self) -> &'a str {
        self.hote
    }

    /// La cible de la requête HTTP : le chemin et sa requête, et `/` quand
    /// l'URL n'en porte pas (RFC 9112 §3.2.1). Une requête sans chemin —
    /// `https://h?x` — reçoit le sien devant elle ; c'est ce que la seconde
    /// tranche rend.
    #[must_use]
    pub fn cible(&self) -> (&'static str, &'a str) {
        if self.suite.starts_with('/') {
            ("", self.suite)
        } else {
            ("/", self.suite)
        }
    }
}

/// Ce nom est-il un nom DNS, et non une adresse ?
///
/// # POURQUOI LA DERNIÈRE ÉTIQUETTE DÉCIDE
///
/// Un résolveur système accepte des écritures d'IPv4 que personne ne
/// reconnaît à l'œil : `127.1`, `2130706433`, `0x7f000001`. Toutes finissent
/// par une étiquette numérique — décimale, ou hexadécimale derrière `0x` —,
/// et aucun nom de domaine public ne le fait : les domaines de premier niveau
/// sont alphabétiques. C'est la règle de l'URL du WHATWG, et elle ferme la
/// porte à la forme la plus directe d'une requête détournée **avant** la
/// résolution — l'envoi, lui, jugera de toute façon chaque adresse rendue.
fn nom_dns(hote: &str) -> Result<(), Erreur> {
    let refus = |regle| Err(Erreur::PointRefuse { regle });
    if hote.is_empty() || hote.len() > NOM_DNS_MAX {
        return refus("un nom DNS de 1 à 253 octets");
    }
    let mut derniere = "";
    for etiquette in hote.split('.') {
        let octets = etiquette.as_bytes();
        let bord = |octet: Option<&u8>| octet == Some(&b'-');
        if octets.is_empty()
            || octets.len() > ETIQUETTE_MAX
            || !octets
                .iter()
                .all(|octet| octet.is_ascii_alphanumeric() || *octet == b'-')
            || bord(octets.first())
            || bord(octets.last())
        {
            return refus("un nom DNS : lettres, chiffres, tirets, points");
        }
        derniere = etiquette;
    }
    let hexadecimale = derniere
        .strip_prefix("0x")
        .or_else(|| derniere.strip_prefix("0X"))
        .is_some_and(|reste| reste.bytes().all(|octet| octet.is_ascii_hexdigit()));
    if derniere.bytes().all(|octet| octet.is_ascii_digit()) || hexadecimale {
        return refus("un nom DNS, pas une adresse");
    }
    Ok(())
}

// ── Base64url, sans remplissage (RFC 4648 §5) ───────────────────────────────
//
// # POURQUOI ICI, ET SI PEU
//
// Deux champs de ce produit seulement sont des octets dans du JSON : la clé
// et le secret de RFC 8291. Une crate pour eux tirerait dans le graphe un
// encodeur général ; ces quarante lignes n'acceptent qu'UNE écriture de
// chaque valeur — sans remplissage, et les bits de queue à zéro —, ce qui
// rend l'aller-retour exact et le fuzz capable de le vérifier.

/// L'alphabet de base64url.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// La valeur d'un symbole, s'il en est un.
fn valeur(symbole: u8) -> Option<u32> {
    ALPHABET
        .iter()
        .position(|candidat| *candidat == symbole)
        .map(|rang| u32::try_from(rang).unwrap_or_default())
}

/// Le symbole de ces six bits — les autres sont ignorés.
fn symbole(six: u32) -> u8 {
    ALPHABET
        .get(usize::try_from(six & 0x3F).unwrap_or_default())
        .copied()
        .unwrap_or_default()
}

/// Écrit cet octet à ce rang, s'il est dans la tranche.
///
/// **Sans ouvrir de branche** — la raison écrite dans `asl-registre` sur
/// `poser` : les rangs appelés tiennent toujours, et une branche qu'aucun
/// essai ne peut prendre est du code mort.
fn poser(sortie: &mut [u8], rang: usize, octet: u8) {
    sortie
        .get_mut(rang..rang.saturating_add(1))
        .unwrap_or_default()
        .fill(octet);
}

/// Les `bits` bits de poids faible — `bits` vaut moins de huit.
const fn masque(bits: u32) -> u32 {
    1_u32.wrapping_shl(bits).wrapping_sub(1)
}

/// Décode exactement `N` octets, ou rien.
///
/// **Une seule écriture est admise** : la longueur exacte, sans `=`, et les
/// bits que la dernière lettre porte au-delà des octets à zéro.
#[must_use]
pub fn decoder_base64url<const N: usize>(texte: &str) -> Option<[u8; N]> {
    let symboles = texte.as_bytes();
    if symboles.len() != longueur_base64url(N) {
        return None;
    }
    let mut sortie = [0_u8; N];
    let mut rang = 0_usize;
    let mut accumulateur: u32 = 0;
    let mut bits: u32 = 0;
    for symbole in symboles {
        accumulateur = accumulateur.wrapping_shl(6) | valeur(*symbole)?;
        bits = bits.saturating_add(6);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            poser(
                &mut sortie,
                rang,
                u8::try_from(accumulateur.wrapping_shr(bits) & 0xFF).unwrap_or_default(),
            );
            rang = rang.saturating_add(1);
        }
        accumulateur &= masque(bits);
    }
    // Les bits qui restent ne portent rien, et doivent valoir zéro : sinon
    // deux textes rendraient les mêmes octets.
    (accumulateur == 0).then_some(sortie)
}

/// Combien de symboles `n` octets occupent, sans remplissage.
#[must_use]
pub const fn longueur_base64url(n: usize) -> usize {
    n.saturating_mul(8).div_ceil(6)
}

/// Écrit ces octets en base64url, sans remplissage, et rend ce qui a été
/// écrit — ou `None` si la sortie est trop courte.
pub fn encoder_base64url<'s>(octets: &[u8], sortie: &'s mut [u8]) -> Option<&'s [u8]> {
    let longueur = longueur_base64url(octets.len());
    let cible = sortie.get_mut(..longueur)?;
    let mut rang = 0_usize;
    let mut ecrire = |six: u32| {
        poser(cible, rang, symbole(six));
        rang = rang.saturating_add(1);
    };
    let mut accumulateur: u32 = 0;
    let mut bits: u32 = 0;
    for octet in octets {
        accumulateur = accumulateur.wrapping_shl(8) | u32::from(*octet);
        bits = bits.saturating_add(8);
        while bits >= 6 {
            bits = bits.saturating_sub(6);
            ecrire(accumulateur.wrapping_shr(bits));
        }
        accumulateur &= masque(bits);
    }
    if bits > 0 {
        ecrire(accumulateur.wrapping_shl(6_u32.saturating_sub(bits)));
    }
    sortie.get(..longueur)
}
