//! **Cible : l'écriture d'un identifiant** — seize octets quelconques vers un
//! texte, et retour.
//!
//! # Pourquoi une deuxième cible, alors que la première fait déjà un aller-retour
//!
//! Elles partent des deux bouts, et n'atteignent pas les mêmes valeurs.
//!
//! La première part d'un TEXTE : elle n'explore que ce que le décodeur accepte,
//! donc jamais les seize octets qu'aucune chaîne plausible ne produit. Celle-ci
//! part des OCTETS, et couvre l'espace des valeurs — y compris celles que
//! `depuis_entropie` recevra d'un vrai générateur d'aléa.
//!
//! **C'est le sens qui compte en production** : un identifiant naît de seize
//! octets tirés au sort, et c'est cette écriture-là qu'un daemon recopiera.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique.**
//! 2. **TOUT identifiant se relit** — il n'existe pas de tirage qu'on sache
//!    écrire et pas relire. Un seul suffirait à perdre une machine.
//! 3. **L'écriture est ASCII, de longueur fixe, et n'emploie que l'alphabet.**
//! 4. **LE PREMIER SYMBOLE RESTE SOUS 8.** Le corps porte 130 bits pour 128
//!    utiles ; si l'encodeur employait les deux bits de rabiot, il produirait un
//!    texte que le décodeur refuserait — un identifiant qu'on écrit et qu'on ne
//!    sait pas relire.
//! 5. **Le genre survit à l'aller-retour.**

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asl_id::{Genre, Identifiant, LONGUEUR};

/// L'alphabet attendu, réécrit ici pour la raison dite dans l'autre cible.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree {
    /// Le genre, réduit modulo six.
    genre: u8,
    /// Les seize octets, tels que `depuis_entropie` les recevrait.
    octets: [u8; 16],
}

/// Le genre que désigne un octet.
const fn genre(brut: u8) -> Genre {
    match brut % 6 {
        0 => Genre::Utilisateur,
        1 => Genre::Appareil,
        2 => Genre::Machine,
        3 => Genre::Service,
        4 => Genre::Autorisation,
        _ => Genre::Annuaire,
    }
}

fuzz_target!(|entree: Entree| {
    let genre = genre(entree.genre);
    let identifiant = Identifiant::depuis_entropie(genre, entree.octets);

    let texte = identifiant.texte();
    let rendu = texte.as_str();
    let octets = rendu.as_bytes();

    // ── PROPRIÉTÉ 3 : la forme ──────────────────────────────────────────────
    assert!(rendu.is_ascii(), "l'écriture doit rester ASCII");
    assert_eq!(octets.len(), LONGUEUR, "longueur fixe");
    assert_eq!(octets[0], genre.prefixe(), "préfixe du genre");
    assert_eq!(octets[1], b'-', "séparateur");
    for (rang, octet) in octets.iter().enumerate().skip(2) {
        assert!(
            ALPHABET.contains(octet),
            "symbole hors alphabet en {rang} : {octet:?}"
        );
    }

    // ── PROPRIÉTÉ 4 : le premier symbole reste sous 8 ───────────────────────
    //
    // Sinon l'encodeur produirait un texte que le décodeur refuse pour
    // débordement — un identifiant qu'on écrit et qu'on ne sait pas relire.
    let premier = octets[2];
    assert!(
        (b'0'..=b'7').contains(&premier),
        "le premier symbole vaut {premier:?}, au-delà de 7 : les deux bits de \
         rabiot ont été employés"
    );

    // ── PROPRIÉTÉS 2 et 5 : l'aller-retour ──────────────────────────────────
    let relu = Identifiant::analyser(rendu).expect("tout identifiant écrit doit se relire");
    assert_eq!(relu, identifiant, "l'aller-retour a changé la valeur");
    assert_eq!(relu.octets(), &entree.octets, "les octets ont bougé");
    assert_eq!(relu.genre(), genre, "le genre a bougé");
    assert_eq!(relu.texte(), texte, "l'écriture n'est pas idempotente");
});
