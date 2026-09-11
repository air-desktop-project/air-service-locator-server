//! Les graines de fuzz disent-elles ce que leur nom prétend ?
//!
//! Même raison que dans `asl-attest` : `check-fuzz.sh` compte les graines et ne
//! les lit pas. Une graine « acceptée » qui serait refusée ne casserait rien —
//! elle laisserait simplement la campagne partir d'un refus, et la propriété
//! centrale de la cible (« tout `Ok` rend la clé du banc ») ne serait jamais
//! mise à l'épreuve, faute d'`Ok`.

mod forge;

use std::fs;
use std::path::PathBuf;

use asl_apple::{Attendu, Environnement, Refus, verifier};
use forge::{Banc, IDENTIFIANT_APP, PENDANT};

fn graine(nom: &str) -> Vec<u8> {
    let mut chemin = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    chemin.push("../../fuzz/seeds/apple");
    chemin.push(nom);
    fs::read(&chemin).unwrap_or_else(|faute| panic!("graine {chemin:?} illisible : {faute}"))
}

#[test]
fn chaque_graine_rend_le_verdict_de_son_nom() {
    let banc = Banc::charger();
    let attendu = Attendu {
        racine: &banc.racine,
        defi: &banc.defi,
        identifiant_app: IDENTIFIANT_APP,
        environnement: Environnement::Developpement,
        maintenant: PENDANT,
    };

    for nom in ["acceptee", "acceptee-via-p256"] {
        let certifie = verifier(&graine(nom), &attendu)
            .unwrap_or_else(|refus| panic!("{nom} devrait passer, et rend {refus}"));
        assert_eq!(&certifie.cle[..], &banc.cle[..], "{nom}");
    }

    let refus = [
        ("refus-identifiant-faux", Refus::IdentifiantDifferent),
        ("refus-sans-nonce", Refus::NonceAbsent),
        ("refus-cle-p384", Refus::CleInattendue),
        ("refus-chaine-vide", Refus::ChaineVide),
    ];
    for (nom, attendu_refus) in refus {
        assert_eq!(
            verifier(&graine(nom), &attendu),
            Err(attendu_refus),
            "{nom}"
        );
    }
    assert!(matches!(
        verifier(&graine("refus-sans-intermediaire"), &attendu),
        Err(Refus::Chaine(_))
    ));
}

#[test]
fn aucune_graine_n_est_oubliee_par_cet_essai() {
    let mut chemin = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    chemin.push("../../fuzz/seeds/apple");
    let combien = fs::read_dir(&chemin)
        .unwrap_or_else(|faute| panic!("{chemin:?} illisible : {faute}"))
        .count();
    assert_eq!(
        combien, 7,
        "7 graines sont vérifiées ici ; le répertoire en porte {combien}"
    );
}
