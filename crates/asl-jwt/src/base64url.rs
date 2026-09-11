//! base64url sans remplissage (RFC 4648 §5), décodage seul.
//!
//! On ne code jamais un jeton — c'est l'appareil qui en fabrique un, le serveur
//! qui le lit —, donc il n'y a pas d'encodeur ici. Le décodeur, lui, est borné
//! et sans allocation : il écrit dans un tampon que l'appelant fournit.

use crate::Erreur;

/// La valeur d'un symbole base64url, ou `INVALIDE`.
const INVALIDE: u8 = 0xFF;
/// Le remplissage `=`, distingué pour lui donner sa propre faute.
const REMPLISSAGE: u8 = 0xFE;

/// La table de décodage : pour chaque octet, sa valeur de six bits, ou une
/// sentinelle. **`+` et `/` de base64 ordinaire y sont invalides** : base64url
/// emploie `-` et `_`, et accepter les deux ferait lire un même jeton de deux
/// façons.
const TABLE: [u8; 256] = {
    let mut table = [INVALIDE; 256];
    // Compteurs en `u8` : l'index de table se calcule par addition d'octets, et
    // il n'y a donc aucune conversion de largeur à faire — ce que le workspace
    // refuserait sur un chemin qui lit du réseau.
    let mut i: u8 = 0;
    while i < 26 {
        table[(b'A' + i) as usize] = i;
        table[(b'a' + i) as usize] = 26 + i;
        i += 1;
    }
    let mut c: u8 = 0;
    while c < 10 {
        table[(b'0' + c) as usize] = 52 + c;
        c += 1;
    }
    table[b'-' as usize] = 62;
    table[b'_' as usize] = 63;
    table[b'=' as usize] = REMPLISSAGE;
    table
};

/// Combien d'octets un segment base64url de `symboles` symboles décode.
///
/// # Erreurs
///
/// [`Erreur::LongueurImpossible`] si `symboles % 4 == 1` : un symbole isolé ne
/// code aucun octet, et c'est le seul reste qu'un groupe base64url ne produit
/// jamais.
pub const fn longueur_decodee(symboles: usize, rang: usize) -> Result<usize, Erreur> {
    // Chaque groupe de quatre symboles fait trois octets ; un reste de deux en
    // fait un, de trois en fait deux. Les opérations sont saturantes parce que
    // la longueur vient du réseau — mais un jeton assez grand pour saturer aurait
    // déjà été refusé bien avant par les bornes de l'appelant.
    let groupes = (symboles / 4).saturating_mul(3);
    match symboles % 4 {
        0 => Ok(groupes),
        1 => Err(Erreur::LongueurImpossible { rang }),
        2 => Ok(groupes.saturating_add(1)),
        // Le seul reste qui demeure : 3 symboles → 2 octets.
        _ => Ok(groupes.saturating_add(2)),
    }
}

/// Décode `source` (base64url sans remplissage) dans `sortie`, et rend le
/// nombre d'octets écrits.
///
/// `decale` est la position de `source` dans le jeton entier, pour que les
/// fautes citent la bonne position.
///
/// # Erreurs
///
/// [`Erreur::LongueurImpossible`], [`Erreur::SymboleInvalide`],
/// [`Erreur::RemplissageRefuse`], [`Erreur::TamponTropPetit`].
pub fn decoder(
    source: &[u8],
    sortie: &mut [u8],
    rang: usize,
    decale: usize,
) -> Result<usize, Erreur> {
    let besoin = longueur_decodee(source.len(), rang)?;
    // On réserve EXACTEMENT ce qu'il faut. `ok_or` est la seule vérification de
    // taille, et elle a lieu avant qu'un octet ne soit écrit : le tampon du
    // reste de l'appelant est intact quand on refuse.
    let cible = sortie
        .get_mut(..besoin)
        .ok_or(Erreur::TamponTropPetit { attendu: besoin })?;

    let mut ecrits = 0;
    let mut morceau = 0_u32;
    let mut bits = 0_u32;
    for (i, octet) in source.iter().enumerate() {
        let valeur = TABLE[*octet as usize];
        if valeur == REMPLISSAGE {
            return Err(Erreur::RemplissageRefuse {
                position: decale.saturating_add(i),
            });
        }
        if valeur == INVALIDE {
            return Err(Erreur::SymboleInvalide {
                position: decale.saturating_add(i),
            });
        }
        morceau = morceau << 6 | u32::from(valeur);
        bits = bits.saturating_add(6);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            // `bits` tient dans `[0, 12]`, donc ce décalage ne perd rien ; le
            // `& 0xFF` rend l'octet de poids faible sans conversion large.
            let octet = ((morceau >> bits) & 0xFF) as u8;
            // `ecrits` est mathématiquement borné par `besoin`, la taille de
            // `cible` : chaque tour de huit bits produit un octet, et il y en a
            // `besoin`. L'indexation ne peut donc pas déborder.
            cible[ecrits] = octet;
            ecrits = ecrits.saturating_add(1);
        }
    }
    // Les `bits` bits qui restent (2 ou 4) ne codent aucun octet : ils DOIVENT
    // être nuls, sinon deux jetons différents décoderaient à l'identique.
    if bits > 0 {
        let masque = (1_u32 << bits).saturating_sub(1);
        if morceau & masque != 0 {
            return Err(Erreur::BitsNonNuls { rang });
        }
    }
    Ok(ecrits)
}
