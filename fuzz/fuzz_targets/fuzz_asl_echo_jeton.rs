//! **Cible : le jeton d'écho, en octets et en hexadécimal.**
//!
//! Le client le lit dans la réponse de `POST /v1/echo/jetons` (386 chiffres
//! hexadécimaux) ; l'écho le lit dans une sonde (193 octets). Les deux
//! lecteurs sont éprouvés, et leur accord.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, en octets comme en texte.
//! 2. **UN JETON LU SE RÉÉCRIT À L'OCTET PRÈS**, et son hexadécimal se relit
//!    en lui-même ; les majuscules se lisent comme les minuscules.
//! 3. **UN REFUS DIT VRAI** — la longueur, la version lue à sa place, un
//!    chiffre qui n'en est pas un.
//! 4. **UN JETON CRU N'EST JAMAIS UNE CONTREFAÇON** : sous la seule racine
//!    crue, il est celui qu'elle émettrait pour ces champs.

#![no_main]

use libfuzzer_sys::fuzz_target;

use asl_cle::{ClePublique, CleSecrete, identifiant_de_racine};
use asl_echo::{JETON_HEX_OCTETS, JETON_OCTETS, Jeton, Refus};
use asl_id::{Genre, Identifiant};

// ── Le décor : les clés et les identifiants des vecteurs figés ─────────────
//
// Ceux de `crates/asl-echo/tests/fixtures/vecteurs.py`, pour que les graines —
// ces vecteurs mêmes — soient ACCEPTÉES, et que libFuzzer parte de ce qui
// passe tous les refus plutôt que de s'arrêter au premier octet.

/// L'heure des vecteurs : le jeton y est valable, la sonde d'annuaire aussi.
const MAINTENANT: u64 = 1_789_217_751_000;

fn racine() -> CleSecrete {
    CleSecrete::depuis_entropie([0x11; 32])
}

fn machine() -> CleSecrete {
    CleSecrete::depuis_entropie([0x33; 32])
}

fn racine_id() -> Identifiant {
    identifiant_de_racine(&racine().publique())
}

fn suite(premier: u8) -> [u8; 16] {
    let mut seize = [0; 16];
    for (place, octet) in seize.iter_mut().zip(premier..) {
        *place = octet;
    }
    seize
}

fn moi() -> Identifiant {
    Identifiant::depuis_entropie(Genre::Machine, suite(0x70))
}

/// Les racines que l'écho croit : une seule.
fn racines(n: Identifiant) -> Option<ClePublique> {
    (n == racine_id()).then(|| racine().publique())
}

fuzz_target!(|octets: &[u8]| {
    match Jeton::lire(octets) {
        Ok(jeton) => {
            assert_eq!(
                jeton.octets().as_slice(),
                octets,
                "un jeton lu ne se réécrit pas"
            );
            let hex = jeton.hex();
            assert_eq!(Jeton::lire_hex(hex.as_str()), Ok(jeton));
            assert_eq!(Jeton::lire_hex(&hex.as_str().to_uppercase()), Ok(jeton));
            if jeton
                .verifier(moi(), &machine().publique(), &racines, MAINTENANT)
                .is_ok()
            {
                let reemis = Jeton::emettre(
                    &racine(),
                    jeton.cible(),
                    jeton.cle_cible(),
                    jeton.sondeur(),
                    jeton.cle_sondeur(),
                    jeton.emis_a(),
                )
                .expect("des genres lus à leur place");
                assert_eq!(reemis, jeton, "un jeton contrefait cru");
            }
        }
        Err(Refus::Longueur { attendue, obtenue }) => {
            assert_eq!(attendue, JETON_OCTETS);
            assert_ne!(obtenue, JETON_OCTETS);
        }
        Err(Refus::VersionDeJeton { version }) => assert_eq!(octets.first(), Some(&version)),
        Err(Refus::CleInvalide) => {}
        Err(autre) => panic!("un refus qu'un jeton ne peut pas rendre : {autre:?}"),
    }

    if let Ok(texte) = core::str::from_utf8(octets) {
        match Jeton::lire_hex(texte) {
            Ok(jeton) => assert!(jeton.hex().as_str().eq_ignore_ascii_case(texte)),
            Err(Refus::Longueur { obtenue, .. }) => assert_ne!(obtenue, JETON_HEX_OCTETS),
            Err(Refus::Hexadecimal) => {
                assert!(
                    !texte.bytes().all(|c| c.is_ascii_hexdigit()),
                    "des chiffres refusés"
                );
            }
            Err(Refus::VersionDeJeton { .. } | Refus::CleInvalide) => {}
            Err(autre) => panic!("un refus qu'un jeton en texte ne peut pas rendre : {autre:?}"),
        }
    }
});
