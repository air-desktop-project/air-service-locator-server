//! **Cible : le découpage d'une liste** — des octets bruts vers des tranches.
//!
//! # POURQUOI CETTE CIBLE VAUT SON TEMPS
//!
//! `elements` coupe des octets **sans les comprendre**. Il ne décode rien : il
//! suit les crochets, les accolades et les chaînes, et rend des tranches. C'est
//! exactement le genre de code où une faute ne plante pas — elle coupe au mauvais
//! endroit, et rend deux moitiés qui se décodent en autre chose.
//!
//! Et il est atteint par le réseau : c'est un CLIENT qui lit la liste que
//! l'annuaire lui rend, dans les cinq liaisons.
//!
//! # LES PROPRIÉTÉS
//!
//! 1. **Rien ne panique**, quels que soient les octets — tronqués au milieu
//!    d'une chaîne, imbriqués à mille niveaux, non-UTF-8.
//! 2. **LES TRANCHES SONT DANS LE TAMPON, ET DANS L'ORDRE.** Chacune est une
//!    sous-tranche de l'entrée, elles ne se chevauchent pas, et elles vont en
//!    croissant. Une tranche qui déborderait serait une lecture hors bornes chez
//!    le premier appelant.
//! 3. **L'ALLER-RETOUR EST FIDÈLE.** Ce qu'on découpe se recompose à
//!    l'identique — et se redécoupe en les mêmes tranches. Sans cela, le serveur
//!    et le client ne parleraient pas de la même liste.
//! 4. **LA BORNE TIENT** : jamais plus de `LISTE_MAX` tranches.

#![no_main]

use asl_proto::cadrage::{Liste, elements};
use asl_proto::{LISTE_MAX, cadrage::MESSAGE_MAX};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|donnees: &[u8]| {
    let Ok(tranches) = elements(donnees) else {
        // Un refus est une réponse : ce qui compte est qu'il n'y ait pas de
        // panique, et `fuzz_target` s'en assure.
        return;
    };
    let tranches: Vec<&[u8]> = tranches.collect();

    // ── 4. LA BORNE ────────────────────────────────────────────────────────
    assert!(tranches.len() <= LISTE_MAX, "{} tranches", tranches.len());

    // ── 2. LES TRANCHES SONT DANS LE TAMPON, ET DANS L'ORDRE ───────────────
    //
    // On compare les ADRESSES : chaque tranche doit pointer dans `donnees`, et
    // la suivante commencer après la fin de la précédente.
    let debut = donnees.as_ptr() as usize;
    let fin = debut.saturating_add(donnees.len());
    let mut precedente = debut;
    for tranche in &tranches {
        let ou = tranche.as_ptr() as usize;
        assert!(
            ou >= debut && ou.saturating_add(tranche.len()) <= fin,
            "hors du tampon"
        );
        assert!(ou >= precedente, "les tranches se chevauchent ou reculent");
        assert!(!tranche.is_empty(), "une tranche vide n'est pas un élément");
        precedente = ou.saturating_add(tranche.len());
    }

    // ── 3. L'ALLER-RETOUR ──────────────────────────────────────────────────
    let mut sortie = vec![0_u8; MESSAGE_MAX];
    let combien = {
        let mut liste = Liste::nouvelle(&mut sortie);
        for tranche in &tranches {
            liste.ajouter(tranche);
        }
        // **CE CHEMIN NE PEUT PAS ÉCHOUER SUR LA BORNE** : on vient de vérifier
        // qu'il y a au plus `LISTE_MAX` tranches. Il peut échouer sur la taille
        // du tampon, et c'est alors que l'entrée était près de `MESSAGE_MAX`.
        match liste.achever() {
            Ok(combien) => combien,
            Err(_) => return,
        }
    };
    sortie.truncate(combien);

    let redecoupees: Vec<&[u8]> = elements(&sortie)
        .expect("ce qu'on vient de composer se relit")
        .collect();
    assert_eq!(redecoupees.len(), tranches.len(), "le nombre a changé");
    for (avant, apres) in tranches.iter().zip(redecoupees.iter()) {
        assert_eq!(avant, apres, "une tranche a changé à l'aller-retour");
    }
});
