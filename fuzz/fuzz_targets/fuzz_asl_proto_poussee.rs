//! **Cible : la poussée de verdict** — ce que l'annuaire envoie de sa propre
//! initiative dans la connexion tenue.
//!
//! # Ce qu'elle éprouve
//!
//! Les mêmes invariants de joignabilité que la réponse — et c'est justement ce
//! qu'il faut vérifier : **la validation est écrite UNE FOIS et appliquée aux
//! deux messages**. Une cible par message est ce qui attrape le jour où
//! quelqu'un en recopierait une version affaiblie ici.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique.**
//! 2. **C6 tient ici comme dans la réponse** : aucun point UDP dit mesuré,
//!    aucun `joignable` sans date.
//! 3. **AUCUN IDENTIFIANT DE SERVICE N'A PU ENTRER.** La connexion le détermine ;
//!    un champ qui le répéterait pourrait la contredire.
//! 4. **L'aller-retour est fidèle et l'écriture idempotente.**
//! 5. **Un tampon d'un octet trop petit échoue proprement.**

#![no_main]

use libfuzzer_sys::fuzz_target;

use asl_proto::{MESSAGE_MAX, POINTS_MAX, Poussee, Protocole, TamponsReponse, Verdict};

fuzz_target!(|donnees: &[u8]| {
    let mut tampons = TamponsReponse::nouveaux();
    let Ok(poussee) = Poussee::decoder(donnees, &mut tampons) else {
        return;
    };

    assert!(!poussee.joignabilite.is_empty());
    assert!(poussee.joignabilite.len() <= POINTS_MAX);

    // PROPRIÉTÉ 2 : C6.
    for entree in poussee.joignabilite {
        match entree.verdict {
            Verdict::Joignable { candidat, a } => {
                assert_eq!(entree.point.protocole, Protocole::Tcp);
                assert_eq!(entree.verdict.mesure_a(), Some(a));
                assert_ne!(candidat.port.valeur(), 0);
            }
            Verdict::Injoignable { a } => {
                assert_eq!(entree.point.protocole, Protocole::Tcp);
                assert_eq!(entree.verdict.mesure_a(), Some(a));
            }
            Verdict::NonSonde { .. } | Verdict::EnCours => {
                assert_eq!(entree.verdict.mesure_a(), None);
            }
        }
        assert_ne!(entree.point.port.valeur(), 0);
    }
    for (rang, entree) in poussee.joignabilite.iter().enumerate() {
        for autre in poussee.joignabilite.iter().skip(rang + 1) {
            assert_ne!(entree.point, autre.point);
        }
    }

    // PROPRIÉTÉ 3 : le message accepté ne nommait aucun service.
    assert!(
        !donnees
            .windows(9)
            .any(|f| f == b"\"service\":"[..9].as_ref()),
        "une poussée acceptée portait un champ `service`"
    );
    assert!(!donnees.contains(&b'\\'));

    // PROPRIÉTÉ 4 : l'aller-retour.
    let mut sortie = [0_u8; MESSAGE_MAX];
    let ecrits = poussee
        .encoder(&mut sortie)
        .expect("tient dans MESSAGE_MAX");
    let reecrit = &sortie[..ecrits];

    let mut encore = TamponsReponse::nouveaux();
    let relu = Poussee::decoder(reecrit, &mut encore).expect("ce qu'on écrit se relit");
    assert_eq!(relu.vu_depuis, poussee.vu_depuis);
    assert_eq!(relu.derriere_nat, poussee.derriere_nat);
    assert_eq!(relu.joignabilite, poussee.joignabilite);
    assert_eq!(relu.attend_encore(), poussee.attend_encore());

    let mut deux_fois = [0_u8; MESSAGE_MAX];
    let encore_ecrits = relu.encoder(&mut deux_fois).expect("réécrire tient");
    assert_eq!(&deux_fois[..encore_ecrits], reecrit);

    // PROPRIÉTÉ 5.
    if ecrits > 0 {
        let mut trop_court = [0_u8; MESSAGE_MAX];
        let court = trop_court.get_mut(..ecrits - 1).expect("borne");
        assert!(poussee.encoder(court).is_err());
    }
});
