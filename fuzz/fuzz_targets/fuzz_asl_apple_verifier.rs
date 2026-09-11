//! **Cible : la vérification d'App Attest** — des octets quelconques vers un
//! verdict, sous la racine du banc.
//!
//! # LA PROPRIÉTÉ QUI COMPTE, ET ELLE EST FORTE
//!
//! Sous la racine du banc, UNE SEULE clé a jamais été certifiée : celle de
//! `feuille.der`. Donc **tout `Ok` doit rendre exactement cette clé**. Un `Ok`
//! qui en rendrait une autre serait une contrefaçon — libFuzzer aurait forgé
//! une attestation pour une clé qu'aucune chaîne n'a signée, et c'est
//! précisément ce que cette crate existe pour rendre impossible.
//!
//! Les autres :
//!
//! 1. **Rien ne panique**, ni dans la vérification, ni dans le marcheur DER
//!    pris seul.
//! 2. **Un refus est toujours nommé.**
//! 3. **La vérification est stable** : deux fois les mêmes octets, le même
//!    verdict.
//!
//! # POURQUOI LA RACINE DU BANC ET PAS CELLE D'APPLE
//!
//! Sous la racine d'Apple, tout serait refusé à la chaîne, et rien après ne
//! serait jamais exercé. Sous celle du banc, libFuzzer part d'un objet ACCEPTÉ
//! (la graine) et le déforme : chaque pas de la vérification est atteint.

#![no_main]

use libfuzzer_sys::fuzz_target;

use asl_apple::{Attendu, Environnement, Refus, verifier, x509};

const RACINE: &[u8] = include_bytes!("../../crates/asl-apple/tests/fixtures/racine.der");
const DEFI: &[u8] = include_bytes!("../../crates/asl-apple/tests/fixtures/defi.bin");
const CLE: &[u8] = include_bytes!("../../crates/asl-apple/tests/fixtures/cle-feuille.bin");

/// Le 1er juin 2026, dans la validité des certificats du banc.
const PENDANT: u64 = 1_780_272_000;

fn nomme(refus: &Refus) {
    assert!(matches!(
        refus,
        Refus::Grammaire(_)
            | Refus::PasDeCleAttestee
            | Refus::Compteur { .. }
            | Refus::Environnement
            | Refus::App
            | Refus::ChaineVide
            | Refus::RacineIllisible
            | Refus::FeuilleIllisible
            | Refus::Chaine(_)
            | Refus::CertificatIllisible
            | Refus::CleInattendue
            | Refus::NonceAbsent
            | Refus::NonceDifferent
            | Refus::IdentifiantDifferent
    ));
}

fuzz_target!(|octets: &[u8]| {
    // Le marcheur DER seul, sur n'importe quoi.
    let _ = x509::lire(octets);

    let attendu = Attendu {
        racine: RACINE,
        defi: DEFI,
        identifiant_app: "ABCDE12345.ch.narro.essai",
        environnement: Environnement::Developpement,
        maintenant: PENDANT,
    };
    let verdict = verifier(octets, &attendu);
    assert_eq!(
        verdict,
        verifier(octets, &attendu),
        "la vérification n'est pas stable"
    );
    match verdict {
        Ok(certifie) => {
            assert_eq!(
                &certifie.cle[..],
                CLE,
                "CONTREFAÇON : une clé que la racine du banc n'a jamais certifiée"
            );
        }
        Err(refus) => nomme(&refus),
    }
});
