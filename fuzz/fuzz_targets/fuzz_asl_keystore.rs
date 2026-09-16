//! **Cible : la vérification d'une attestation de clé Android** — des octets
//! quelconques vers un verdict, sous DEUX racines : celle du banc, et celle de
//! Google.
//!
//! # LA PROPRIÉTÉ QUI COMPTE, ET ELLE EST FORTE
//!
//! Sous chaque racine, UNE SEULE feuille a jamais été mise entre les mains de
//! libFuzzer : celle du banc (`banc-acceptee`), celle du Fairphone 5
//! (`reelle-entiere`). Donc **tout `Ok` doit rendre exactement la clé de cette
//! feuille-là**. Un `Ok` qui en rendrait une autre serait une contrefaçon —
//! libFuzzer aurait forgé une chaîne pour une clé qu'aucune racine n'a signée.
//!
//! **La racine de Google et la chaîne réelle, comme graine.** C'est ce qui
//! distingue cette cible de celle d'`asl-apple` : ici, la campagne part aussi
//! d'une chaîne qu'un vrai TEE a émise, et chaque déformation de cette chaîne
//! passe par les vrais vérificateurs — RSA-4096 compris.
//!
//! Les autres :
//!
//! 1. **Rien ne panique**, ni dans la vérification, ni dans le découpage de la
//!    case, ni dans le marcheur X.509, ni dans le lecteur de `KeyDescription`
//!    pris seuls.
//! 2. **Le lecteur de `KeyDescription` ne rend que des tranches de l'entrée.**
//! 3. **Un refus est toujours nommé.**
//! 4. **La vérification est stable** : deux fois les mêmes octets, le même
//!    verdict.

#![no_main]

use libfuzzer_sys::fuzz_target;

use asl_keystore::{Attendu, Refus, case, description, verifier, x509};

const RACINE_DU_BANC: &[u8] =
    include_bytes!("../../crates/asl-keystore/tests/fixtures/racine-du-banc.der");
const CLE_DU_BANC: &[u8; 33] =
    include_bytes!("../../crates/asl-keystore/tests/fixtures/cle-du-banc.bin");
const DEFI_DU_BANC: &[u8] =
    include_bytes!("../../crates/asl-keystore/tests/fixtures/defi-du-banc.bin");

const RACINE_DE_GOOGLE: &[u8] =
    include_bytes!("../../docs/attestation/captures/keystore-fp5-2026-09-16/cert3.der");
const FEUILLE_REELLE: &[u8] =
    include_bytes!("../../docs/attestation/captures/keystore-fp5-2026-09-16/cert0.der");
const DEFI_REEL: &[u8] =
    include_bytes!("../../docs/attestation/captures/keystore-fp5-2026-09-16/defi.bin");

/// Le 1er juin 2026, dans la validité des certificats du banc.
const PENDANT: u64 = 1_780_272_000;
/// Le 2026-09-16, le jour de la capture.
const AU_JOUR_DE_LA_CAPTURE: u64 = 1_789_560_000;

/// L'empreinte du banc, et celle de la build de débogage du Fairphone 5.
const EMPREINTE_DU_BANC: [u8; 32] = [0xA5; 32];
const EMPREINTE_REELLE: [u8; 32] = [
    0x5e, 0xa3, 0x16, 0xf1, 0xb5, 0x0f, 0x2c, 0xe5, 0x4b, 0x82, 0x25, 0xab, 0xa8, 0x5f, 0xf5, 0xcc,
    0x82, 0x38, 0xa7, 0x10, 0xb8, 0xfa, 0xe4, 0x4b, 0x4f, 0x3a, 0x19, 0x5a, 0xad, 0xeb, 0x5f, 0x68,
];

fn nomme(refus: &Refus) {
    assert!(matches!(
        refus,
        Refus::Case(_)
            | Refus::SansRacine
            | Refus::RacineIllisible
            | Refus::FeuilleIllisible
            | Refus::Chaine(_)
            | Refus::CertificatIllisible
            | Refus::CleInattendue
            | Refus::DescriptionAbsente
            | Refus::DescriptionIllisible(_)
            | Refus::CleDifferente
            | Refus::DefiDifferent
            | Refus::AttestationLogicielle(_)
            | Refus::CleLogicielle(_)
            | Refus::RacineDeConfianceAbsente
            | Refus::DemarrageNonVerifie(_)
            | Refus::AppareilDeverrouille
            | Refus::OrigineAbsente
            | Refus::OrigineInattendue(_)
            | Refus::ApplicationAbsente
            | Refus::AutrePaquet
            | Refus::AutreSignataire
    ));
}

/// Chaque tranche rendue est-elle DANS l'entrée ?
fn dans(entree: &[u8], tranche: &[u8]) -> bool {
    let debut = entree.as_ptr() as usize;
    let t = tranche.as_ptr() as usize;
    tranche.is_empty() || (t >= debut && t + tranche.len() <= debut + entree.len())
}

/// Vérifie sous cette attente, et exige que tout `Ok` rende `cle_attendue`.
fn eprouver(octets: &[u8], attendu: &Attendu<'_>, cle_attendue: &[u8; 33]) {
    let verdict = verifier(octets, attendu);
    assert_eq!(
        verdict,
        verifier(octets, attendu),
        "la vérification n'est pas stable"
    );
    match verdict {
        Ok(verdict) => assert_eq!(
            x509::compresser(&verdict.cle),
            *cle_attendue,
            "CONTREFAÇON : une clé que cette racine n'a jamais certifiée"
        ),
        Err(refus) => nomme(&refus),
    }
}

fuzz_target!(|octets: &[u8]| {
    // Les trois lecteurs pris seuls, sur n'importe quoi.
    let _ = case::decouper(octets);
    let _ = x509::lire(octets);
    if let Ok(lue) = description::lire(octets) {
        assert!(dans(octets, lue.defi));
        assert!(dans(octets, lue.identifiant_unique));
        for liste in [&lue.logiciel, &lue.materiel] {
            if let Some(racine) = liste.racine_de_confiance {
                assert!(dans(octets, racine.cle_de_demarrage));
                assert!(dans(octets, racine.empreinte_de_demarrage));
            }
            if let Some(app) = &liste.application {
                assert!(app.paquets.iter().all(|p| dans(octets, p.nom)));
                assert!(app.empreintes.iter().all(|e| dans(octets, e)));
            }
        }
    }

    // Sous la racine du banc.
    let racines = [RACINE_DU_BANC];
    let banc = Attendu {
        racines: &racines,
        defi: DEFI_DU_BANC,
        cle: CLE_DU_BANC,
        paquet: "org.airdesktop.servicelocator",
        empreinte: &EMPREINTE_DU_BANC,
        maintenant: PENDANT,
    };
    eprouver(octets, &banc, CLE_DU_BANC);

    // Sous la racine de Google, au jour de la capture.
    let feuille = x509::lire(FEUILLE_REELLE).expect("la feuille réelle se lit");
    let cle_reelle = x509::compresser(feuille.cle.try_into().expect("65 octets"));
    let racines = [RACINE_DE_GOOGLE];
    let google = Attendu {
        racines: &racines,
        defi: DEFI_REEL,
        cle: &cle_reelle,
        paquet: "org.airdesktop.servicelocator",
        empreinte: &EMPREINTE_REELLE,
        maintenant: AU_JOUR_DE_LA_CAPTURE,
    };
    eprouver(octets, &google, &cle_reelle);
});
