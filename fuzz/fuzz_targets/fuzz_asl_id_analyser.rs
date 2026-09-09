//! **Cible : la lecture d'un identifiant** — des octets qu'on n'a pas choisis
//! vers un [`Identifiant`], ou vers un refus.
//!
//! # Pourquoi celle-ci en premier
//!
//! C'est le seul décodeur que ce dépôt possède aujourd'hui, et il est atteint
//! par tout ce qui entre : une requête de l'API, une annonce de daemon, un
//! fichier de configuration recopié à la main. Les lints `deny` du workspace
//! voient une conversion douteuse, **jamais une borne oubliée** — et c'est
//! exactement ce que le fuzz attrape.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **CE QUI EST ACCEPTÉ SE RÉÉCRIT ET SE RELIT À L'IDENTIQUE.** C'est la
//!    propriété qui compte le plus : l'annuaire compare des identifiants, et
//!    deux textes du même identifiant doivent donner la même valeur. Un aller
//!    simple ne le dirait pas.
//! 3. **LA FORME RENDUE EST TOUJOURS CANONIQUE** : 28 octets, le préfixe du
//!    genre, un tiret, et un corps qui n'emploie que l'alphabet — sans jamais
//!    `I`, `L`, `O` ni `U`, quelle que soit la forme lue.
//! 4. **LA CASSE NE CHANGE RIEN.**
//! 5. **LE RATTRAPAGE DE CROCKFORD NE CHANGE RIEN** : substituer `I` à `1` ou
//!    `O` à `0` dans le corps désigne le même identifiant. C'est la raison
//!    d'être de l'alphabet, et la propriété qui la vérifie sur des entrées que
//!    personne n'a choisies.
//! 6. **`analyser_genre` s'accorde avec `analyser`** : il accepte le genre lu,
//!    et refuse les cinq autres — jamais silencieusement.

#![no_main]

use libfuzzer_sys::fuzz_target;

use asl_id::{Erreur, Genre, Identifiant, LONGUEUR};

/// L'alphabet attendu, **réécrit ici** et non importé.
///
/// Un harnais qui réutiliserait la table qu'il éprouve ne vérifierait que sa
/// propre cohérence : une lettre oubliée le serait des deux côtés.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Les six genres.
const GENRES: [Genre; 6] = [
    Genre::Utilisateur,
    Genre::Appareil,
    Genre::Machine,
    Genre::Service,
    Genre::Autorisation,
    Genre::Annuaire,
];

fuzz_target!(|donnees: &[u8]| {
    // L'analyseur prend un `&str`. Des octets qui ne sont pas de l'UTF-8 ne
    // l'atteignent donc jamais — et ce n'est pas une faille : c'est le type qui
    // les arrête, plus haut, et c'est ce que fait aussi le décodeur JSON.
    let Ok(texte) = core::str::from_utf8(donnees) else {
        return;
    };

    let Ok(identifiant) = Identifiant::analyser(texte) else {
        // PROPRIÉTÉ 1 : un refus est un refus, et il n'a pas paniqué.
        return;
    };

    // ── PROPRIÉTÉ 3 : la forme rendue est canonique ─────────────────────────
    let canonique = identifiant.texte();
    let octets = canonique.as_str().as_bytes();
    assert_eq!(octets.len(), LONGUEUR, "longueur canonique");
    assert_eq!(
        octets[0],
        identifiant.genre().prefixe(),
        "préfixe canonique"
    );
    assert_eq!(octets[1], b'-', "séparateur canonique");
    for (rang, octet) in octets.iter().enumerate().skip(2) {
        assert!(
            ALPHABET.contains(octet),
            "le corps canonique porte un symbole hors alphabet en {rang} : {octet:?}"
        );
    }

    // ── PROPRIÉTÉ 2 : l'aller-retour ────────────────────────────────────────
    let relu = Identifiant::analyser(canonique.as_str())
        .expect("un texte canonique doit toujours se relire");
    assert_eq!(relu, identifiant, "l'aller-retour a changé la valeur");
    assert_eq!(relu.texte(), canonique, "l'écriture n'est pas idempotente");

    // ── PROPRIÉTÉ 4 : la casse ──────────────────────────────────────────────
    for variante in [texte.to_ascii_uppercase(), texte.to_ascii_lowercase()] {
        assert_eq!(
            Identifiant::analyser(&variante),
            Ok(identifiant),
            "la casse a changé la valeur : {variante}"
        );
    }

    // ── PROPRIÉTÉ 5 : le rattrapage de Crockford ────────────────────────────
    //
    // On substitue DANS LE CORPS de la forme canonique, jamais dans le préfixe :
    // un `1` de préfixe n'existe pas, et remplacer une lettre de genre
    // changerait ce qu'on désigne au lieu de l'écrire autrement.
    for (origine, confusion) in [(b'1', 'I'), (b'1', 'L'), (b'0', 'O')] {
        let mut variante = String::with_capacity(LONGUEUR);
        variante.push_str(&canonique.as_str()[..2]);
        for octet in &octets[2..] {
            if *octet == origine {
                variante.push(confusion);
            } else {
                variante.push(char::from(*octet));
            }
        }
        assert_eq!(
            Identifiant::analyser(&variante),
            Ok(identifiant),
            "le rattrapage de Crockford a changé la valeur : {variante}"
        );
    }

    // ── PROPRIÉTÉ 6 : `analyser_genre` s'accorde avec `analyser` ────────────
    let genre = identifiant.genre();
    assert_eq!(
        Identifiant::analyser_genre(genre, texte),
        Ok(identifiant),
        "le genre lu a été refusé"
    );
    for autre in GENRES {
        if autre == genre {
            continue;
        }
        assert_eq!(
            Identifiant::analyser_genre(autre, texte),
            Err(Erreur::GenreInattendu {
                attendu: autre,
                obtenu: genre,
            }),
            "un genre {autre:?} est passé pour un {genre:?}"
        );
    }
});
