//! **Cible : le message de réponse** — des octets bruts vers une réponse, et
//! retour.
//!
//! # Ce qu'elle éprouve que les autres n'éprouvent pas
//!
//! **C6 dans un type.** La contrainte dit que l'annuaire n'affirme jamais ce
//! qu'il n'a pas mesuré, et ce message est le seul où elle se traduit en formes
//! qu'un décodeur doit refuser. Trois propriétés en découlent, et elles sont
//! vérifiées ici sur des octets que personne n'a choisis.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique.**
//! 2. **UN POINT UDP N'EST JAMAIS `joignable` NI `injoignable`.** Il ne se sonde
//!    pas, donc rien n'a pu être mesuré à son sujet.
//! 3. **UN `joignable` PORTE TOUJOURS SA DATE ET SON CANDIDAT.** Le type le rend
//!    structurellement vrai ; ce qu'on vérifie ici est qu'aucun chemin du
//!    décodeur ne fabrique l'inverse.
//! 4. **LE BAIL TOLÈRE AU MOINS UN KEEPALIVE MANQUÉ.** À un pour un, la première
//!    perte de paquet tue un daemon sain.
//! 5. **L'aller-retour est fidèle, et l'écriture idempotente.**
//! 6. **Un tampon d'un octet trop petit échoue proprement.**

#![no_main]

use libfuzzer_sys::fuzz_target;

use asl_id::Genre;
use asl_proto::{MESSAGE_MAX, POINTS_MAX, Protocole, Reponse, TamponsReponse, Verdict};

fuzz_target!(|donnees: &[u8]| {
    let mut tampons = TamponsReponse::nouveaux();
    let Ok(reponse) = Reponse::decoder(donnees, &mut tampons) else {
        return;
    };

    // ── Ce qui est décodé est valide ────────────────────────────────────────
    assert_eq!(reponse.service.genre(), Genre::Service);
    assert!(!reponse.joignabilite.is_empty());
    assert!(reponse.joignabilite.len() <= POINTS_MAX);

    // PROPRIÉTÉ 4 : le bail.
    let keepalive = reponse.bail.keepalive_secondes();
    let inactivite = reponse.bail.inactivite_secondes();
    assert!(keepalive > 0, "un keepalive nul est passé");
    assert!(
        u32::from(inactivite) >= u32::from(keepalive) * 2,
        "un bail à {keepalive}/{inactivite} tue un daemon sain à la première perte"
    );

    for entree in reponse.joignabilite {
        match entree.verdict {
            // PROPRIÉTÉ 2 et 3.
            Verdict::Joignable { candidat, a } => {
                assert_eq!(
                    entree.point.protocole,
                    Protocole::Tcp,
                    "un point UDP a été dit joignable"
                );
                assert_eq!(entree.verdict.mesure_a(), Some(a));
                assert_ne!(candidat.port.valeur(), 0);
            }
            Verdict::Injoignable { a } => {
                assert_eq!(
                    entree.point.protocole,
                    Protocole::Tcp,
                    "un point UDP a été dit injoignable"
                );
                assert_eq!(entree.verdict.mesure_a(), Some(a));
            }
            // Les deux verdicts qui n'affirment aucune mesure n'en portent
            // jamais la date.
            Verdict::NonSonde { .. } | Verdict::EnCours => {
                assert_eq!(entree.verdict.mesure_a(), None);
            }
        }
        assert_ne!(entree.point.port.valeur(), 0);
    }

    // Aucun point en double.
    for (rang, entree) in reponse.joignabilite.iter().enumerate() {
        for autre in reponse.joignabilite.iter().skip(rang + 1) {
            assert_ne!(entree.point, autre.point, "deux verdicts pour un point");
        }
    }

    // Aucun échappement n'a survécu.
    assert!(!donnees.contains(&b'\\'));

    // ── PROPRIÉTÉ 5 : l'aller-retour ────────────────────────────────────────
    let mut sortie = [0_u8; MESSAGE_MAX];
    let ecrits = reponse
        .encoder(&mut sortie)
        .expect("un message décodé tient dans MESSAGE_MAX");
    let reecrit = &sortie[..ecrits];

    let mut encore = TamponsReponse::nouveaux();
    let relu = Reponse::decoder(reecrit, &mut encore).expect("ce qu'on écrit doit se relire");
    assert_eq!(relu.service, reponse.service);
    assert_eq!(relu.bail, reponse.bail);
    assert_eq!(relu.vu_depuis, reponse.vu_depuis);
    assert_eq!(relu.derriere_nat, reponse.derriere_nat);
    assert_eq!(relu.joignabilite, reponse.joignabilite);

    let mut deux_fois = [0_u8; MESSAGE_MAX];
    let encore_ecrits = relu.encoder(&mut deux_fois).expect("réécrire tient");
    assert_eq!(&deux_fois[..encore_ecrits], reecrit);

    // ── PROPRIÉTÉ 6 : les bornes du tampon ──────────────────────────────────
    if ecrits > 0 {
        let mut trop_court = [0_u8; MESSAGE_MAX];
        let court = trop_court.get_mut(..ecrits - 1).expect("borne");
        assert!(reponse.encoder(court).is_err());
    }
});
