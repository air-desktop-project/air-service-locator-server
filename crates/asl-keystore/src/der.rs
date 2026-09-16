//! Un lecteur DER borné : une balise, une longueur, un contenu — et rien
//! d'autre.
//!
//! # POURQUOI UN LECTEUR À NOUS, ET NON `der` OU `x509-cert`
//!
//! Même raison que le marcheur X.509 d'`asl-apple` et le lecteur CBOR
//! d'`asl-attest` : ce graphe porte assez de paquets, et ce qu'on lit ici est
//! petit — deux endroits d'un certificat, puis une `KeyDescription` dont tous
//! les champs sont des entiers, des énumérés, des octets et des séquences. Un
//! lecteur générique apporterait des centaines de types dont trois serviraient.
//!
//! # CE QUE CE LECTEUR REFUSE, ET POURQUOI
//!
//! Il lit du **DER**, pas du BER : une longueur non minimale, un numéro de
//! balise non minimal, une longueur indéfinie sont refusés. Ce qui arrive ici
//! est signé par un TEE ou une racine, et l'un comme l'autre encodent en DER
//! strict ; un octet qui s'en écarte vient d'autre chose que de ce qu'on
//! prétend vérifier.
//!
//! Les longueurs tiennent sur au plus trois octets (`0x82 hh ll`) : un
//! certificat de plus de 65 535 octets n'entre de toute façon pas dans la case
//! de 8 Kio du fil.
//!
//! **RIEN N'EST PRIS POUR ACQUIS** : chaque `get` est borné, chaque longueur est
//! confrontée à ce qui reste. Un contenu tronqué est une faute, jamais une
//! lecture au-delà du tampon.

/// La classe d'une balise (X.690 §8.1.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classe {
    /// Les types de base : INTEGER, SEQUENCE, OCTET STRING…
    Universelle,
    /// `[APPLICATION n]`.
    Application,
    /// `[n]` — les champs optionnels de `KeyDescription` sont de celle-ci.
    Contextuelle,
    /// `[PRIVATE n]`.
    Privee,
}

/// Une balise : sa classe, sa forme, son numéro.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Balise {
    /// Sa classe.
    pub classe: Classe,
    /// Construite (elle contient d'autres éléments) ou primitive.
    pub construite: bool,
    /// Son numéro — jusqu'à 2²⁸ − 1, ce qui couvre largement les `[719]` et
    /// suivants d'Android.
    pub numero: u32,
}

impl Balise {
    /// Une balise universelle, primitive : INTEGER, OCTET STRING…
    pub const fn universelle(numero: u32) -> Self {
        Self {
            classe: Classe::Universelle,
            construite: false,
            numero,
        }
    }

    /// Une balise universelle construite : SEQUENCE, SET.
    pub const fn construite(numero: u32) -> Self {
        Self {
            classe: Classe::Universelle,
            construite: true,
            numero,
        }
    }

    /// `[n]` EXPLICIT, donc construite.
    pub const fn contextuelle(numero: u32) -> Self {
        Self {
            classe: Classe::Contextuelle,
            construite: true,
            numero,
        }
    }
}

/// BOOLEAN.
pub const BOOLEEN: Balise = Balise::universelle(1);
/// INTEGER.
pub const ENTIER: Balise = Balise::universelle(2);
/// BIT STRING.
pub const BITS: Balise = Balise::universelle(3);
/// OCTET STRING.
pub const OCTETS: Balise = Balise::universelle(4);
/// NULL.
pub const NUL: Balise = Balise::universelle(5);
/// OBJECT IDENTIFIER.
pub const OID: Balise = Balise::universelle(6);
/// ENUMERATED.
pub const ENUMERE: Balise = Balise::universelle(10);
/// SEQUENCE.
pub const SEQUENCE: Balise = Balise::construite(16);
/// SET.
pub const ENSEMBLE: Balise = Balise::construite(17);

/// Un élément lu : sa balise et son contenu, tranche de l'entrée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Element<'a> {
    /// Sa balise.
    pub balise: Balise,
    /// Son contenu, sans l'en-tête.
    pub contenu: &'a [u8],
}

/// Ce qui empêche de lire un élément.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Faute {
    /// Il manque des octets : l'en-tête ou le contenu dépasse l'entrée.
    Tronque,
    /// Un numéro de balise mal encodé — non minimal, ou trop grand.
    Balise,
    /// Une longueur mal encodée — indéfinie, non minimale, ou sur plus de deux
    /// octets.
    Longueur,
    /// L'élément n'a pas la balise attendue.
    Inattendu,
    /// Un entier mal formé : vide, non minimal, négatif, ou plus de huit octets.
    Entier,
    /// Un booléen dont le contenu ne fait pas un octet.
    Booleen,
}

/// Lit un élément en tête d'`octets`, et rend ce qui suit.
///
/// # Erreurs
///
/// [`Faute::Tronque`], [`Faute::Balise`] ou [`Faute::Longueur`].
pub fn element(octets: &[u8]) -> Result<(Element<'_>, &[u8]), Faute> {
    let (balise, apres_balise) = balise(octets)?;
    let (longueur, apres_longueur) = longueur(apres_balise)?;
    let (contenu, reste) = apres_longueur
        .split_at_checked(longueur)
        .ok_or(Faute::Tronque)?;
    Ok((Element { balise, contenu }, reste))
}

/// Lit un élément et exige sa balise ; rend son contenu et ce qui suit.
///
/// # Erreurs
///
/// Celles d'[`element`], et [`Faute::Inattendu`] si la balise diffère.
pub fn attendu(octets: &[u8], balise: Balise) -> Result<(&[u8], &[u8]), Faute> {
    let (lu, reste) = element(octets)?;
    if lu.balise != balise {
        return Err(Faute::Inattendu);
    }
    Ok((lu.contenu, reste))
}

/// Lit une balise (X.690 §8.1.2).
fn balise(octets: &[u8]) -> Result<(Balise, &[u8]), Faute> {
    let (premier, mut reste) = octets.split_first().ok_or(Faute::Tronque)?;
    let classe = match premier >> 6 {
        0 => Classe::Universelle,
        1 => Classe::Application,
        2 => Classe::Contextuelle,
        _ => Classe::Privee,
    };
    let construite = premier & 0x20 != 0;
    let bas = u32::from(premier & 0x1F);
    if bas < 0x1F {
        return Ok((
            Balise {
                classe,
                construite,
                numero: bas,
            },
            reste,
        ));
    }
    // Forme longue : des octets en base 128, bit haut levé tant qu'il en
    // reste. Le premier ne peut pas valoir 0x80 (encodage non minimal), et
    // quatre octets suffisent à tout ce qui existe.
    let mut numero: u32 = 0;
    for rang in 0..4_usize {
        let (octet, suite) = reste.split_first().ok_or(Faute::Tronque)?;
        reste = suite;
        if rang == 0 && *octet == 0x80 {
            return Err(Faute::Balise);
        }
        numero = (numero << 7) | u32::from(octet & 0x7F);
        if octet & 0x80 == 0 {
            // La forme longue ne sert qu'aux numéros d'au moins 31.
            if numero < 0x1F {
                return Err(Faute::Balise);
            }
            return Ok((
                Balise {
                    classe,
                    construite,
                    numero,
                },
                reste,
            ));
        }
    }
    Err(Faute::Balise)
}

/// Lit une longueur (X.690 §8.1.3), en DER : minimale, définie, sur au plus
/// deux octets de valeur.
fn longueur(octets: &[u8]) -> Result<(usize, &[u8]), Faute> {
    let (premier, reste) = octets.split_first().ok_or(Faute::Tronque)?;
    match premier {
        0..=0x7F => Ok((usize::from(*premier), reste)),
        0x81 => {
            let (valeur, reste) = reste.split_first().ok_or(Faute::Tronque)?;
            if *valeur < 0x80 {
                return Err(Faute::Longueur);
            }
            Ok((usize::from(*valeur), reste))
        }
        0x82 => {
            let (deux, reste) = reste.split_at_checked(2).ok_or(Faute::Tronque)?;
            let valeur = u16::from_be_bytes([deux[0], deux[1]]);
            if valeur < 0x100 {
                return Err(Faute::Longueur);
            }
            Ok((usize::from(valeur), reste))
        }
        _ => Err(Faute::Longueur),
    }
}

/// Le contenu d'un INTEGER ou d'un ENUMERATED, comme entier non négatif sur
/// 64 bits.
///
/// DER : au moins un octet, pas de zéro de tête inutile (X.690 §8.3.2). Un
/// entier négatif n'a pas de sens pour ce qu'on lit — une version, un niveau,
/// une taille de clé — et il est refusé.
///
/// # Erreurs
///
/// [`Faute::Entier`].
pub fn entier(contenu: &[u8]) -> Result<u64, Faute> {
    let (premier, reste) = contenu.split_first().ok_or(Faute::Entier)?;
    if premier & 0x80 != 0 {
        return Err(Faute::Entier);
    }
    if *premier == 0 && reste.first().is_some_and(|suivant| suivant & 0x80 == 0) {
        return Err(Faute::Entier);
    }
    // Un zéro de tête ne sert qu'à garder positif un octet à bit haut : il ne
    // porte pas de valeur. Huit octets de valeur au plus.
    let valeur = if *premier == 0 { reste } else { contenu };
    if valeur.len() > 8 {
        return Err(Faute::Entier);
    }
    Ok(valeur
        .iter()
        .fold(0_u64, |acc, octet| (acc << 8) | u64::from(*octet)))
}

/// Le contenu d'un BOOLEAN. DER veut `0xFF` pour vrai ; on accepte tout
/// non-zéro, parce qu'un `0x01` d'un encodeur laxiste dit la même chose et que
/// rien ici ne repose sur la distinction.
///
/// # Erreurs
///
/// [`Faute::Booleen`] si le contenu ne fait pas un octet.
pub fn booleen(contenu: &[u8]) -> Result<bool, Faute> {
    match contenu {
        [octet] => Ok(*octet != 0),
        _ => Err(Faute::Booleen),
    }
}
