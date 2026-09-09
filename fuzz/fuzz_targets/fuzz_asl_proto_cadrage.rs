//! **Cible : le cadrage JSON** — des octets bruts vers une annonce, et retour.
//!
//! # Pourquoi c'est la cible qui vaut le plus cher
//!
//! C'est le seul endroit du produit où des octets **entièrement contrôlés par un
//! inconnu** sont analysés. Tout ce qui précède recevait déjà des valeurs ; ici
//! on part du tampon lui-même.
//!
//! Les analyseurs JSON ont une histoire de failles, et elle tient en deux
//! familles : les échappements — décodage UTF-16, paires de substitution — et
//! les désaccords entre lecteurs sur un même document — champs en double,
//! nombres, octets en trop. **Ce décodeur ferme les deux par refus**, et cette
//! cible vérifie que les refus tiennent sur des octets que personne n'a choisis.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets — y compris non-UTF-8,
//!    tronqués au milieu d'une chaîne, ou profondément imbriqués.
//! 2. **CE QUI EST DÉCODÉ EST VALIDE.** `Annonce::decoder` finit par
//!    `Annonce::nouvelle` : tous les invariants du message doivent tenir, et ils
//!    sont revérifiés ici sur le résultat.
//! 3. **L'ALLER-RETOUR EST FIDÈLE ET CANONIQUE.** Ce qu'on décode, on sait le
//!    réécrire ; ce qu'on réécrit se relit à l'identique ; et **réécrire deux
//!    fois ne change plus rien**. Sans cela, deux moitiés du protocole ne
//!    parleraient pas du même message.
//! 4. **UN TAMPON JUSTE ASSEZ GRAND SUFFIT, UN TAMPON PLUS PETIT ÉCHOUE** — et
//!    il échoue proprement, sans rien écrire de tronqué qu'un lecteur prendrait
//!    pour un message.
//! 5. **AUCUN ÉCHAPPEMENT NE SURVIT.** Si le décodeur accepte, le texte
//!    d'origine ne contenait aucune barre oblique inverse : c'est le refus le
//!    plus structurant de ce module, et il se vérifie sur l'ENTRÉE parce que
//!    c'est d'elle qu'il parle.

#![no_main]

use libfuzzer_sys::fuzz_target;

use asl_id::Genre;
use asl_proto::{ADRESSES_MAX, Annonce, MESSAGE_MAX, POINTS_MAX, Protocole, Tampons};

fuzz_target!(|donnees: &[u8]| {
    let mut tampons = Tampons::nouveaux();
    let Ok(annonce) = Annonce::decoder(donnees, &mut tampons) else {
        // PROPRIÉTÉ 1 : un refus est un refus, et il n'a pas paniqué.
        return;
    };

    // ── PROPRIÉTÉ 2 : ce qui est décodé est valide ──────────────────────────
    assert_eq!(
        annonce.machine.genre(),
        Genre::Machine,
        "un identifiant qui n'est pas une machine est passé"
    );
    assert!(
        !annonce.points.is_empty(),
        "une annonce sans point est passée"
    );
    assert!(annonce.points.len() <= POINTS_MAX);
    assert!(annonce.adresses_locales.len() <= ADRESSES_MAX);
    for point in annonce.points {
        assert_ne!(point.port.valeur(), 0, "un port nul est passé");
    }
    for (rang, point) in annonce.points.iter().enumerate() {
        for autre in annonce.points.iter().skip(rang + 1) {
            assert_ne!(point, autre, "deux points identiques sont passés");
        }
    }
    let sondable = annonce.points.iter().any(|p| p.protocole == Protocole::Tcp);
    assert_eq!(annonce.a_un_point_sondable(), sondable);

    // ── PROPRIÉTÉ 5 : aucun échappement n'a survécu ─────────────────────────
    assert!(
        !donnees.contains(&b'\\'),
        "un message accepté portait un échappement"
    );

    // ── PROPRIÉTÉ 3 : l'aller-retour ────────────────────────────────────────
    let mut sortie = [0_u8; MESSAGE_MAX];
    let ecrits = annonce
        .encoder(&mut sortie)
        .expect("un message décodé tient dans MESSAGE_MAX");
    let reecrit = &sortie[..ecrits];

    let mut encore = Tampons::nouveaux();
    let relu =
        Annonce::decoder(reecrit, &mut encore).expect("ce qu'on vient d'écrire doit se relire");

    assert_eq!(relu.machine, annonce.machine);
    assert_eq!(relu.service, annonce.service);
    assert_eq!(relu.points, annonce.points);
    assert_eq!(relu.adresses_locales, annonce.adresses_locales);

    // L'écriture est IDEMPOTENTE : réécrire ce qu'on a réécrit ne change rien.
    // C'est ce qui fait qu'un journal est comparable à lui-même.
    let mut deux_fois = [0_u8; MESSAGE_MAX];
    let encore_ecrits = relu
        .encoder(&mut deux_fois)
        .expect("réécrire ce qu'on a écrit tient dans le même tampon");
    assert_eq!(
        &deux_fois[..encore_ecrits],
        reecrit,
        "l'écriture n'est pas idempotente"
    );

    // ── PROPRIÉTÉ 4 : les bornes du tampon de sortie ────────────────────────
    //
    // Un octet de moins doit échouer PROPREMENT. Un encodeur qui tronquerait
    // laisserait dans le tampon un début de message qu'un lecteur pourrait
    // prendre pour un message.
    if ecrits > 0 {
        let mut trop_court = [0_u8; MESSAGE_MAX];
        let court = trop_court
            .get_mut(..ecrits - 1)
            .expect("ecrits <= MESSAGE_MAX");
        assert!(
            annonce.encoder(court).is_err(),
            "un tampon d'un octet trop petit a été accepté"
        );
    }
});
