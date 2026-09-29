//! **Cible : la sonde d'annuaire, telle que l'écho la reçoit d'un inconnu.**
//!
//! N'importe qui peut envoyer 384 octets au port de l'écho ; c'est le premier
//! décodeur qu'ils traversent, avant toute signature.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, sur aucun octet — ni la lecture, ni la décision.
//! 2. **UNE SONDE LUE SE RÉÉCRIT À L'OCTET PRÈS** : longueur fixe, bourrage nul,
//!    aucun champ facultatif — il n'y a qu'une écriture par sonde.
//! 3. **UN REFUS DIT VRAI** : une longueur refusée n'est pas la bonne, un
//!    premier octet refusé n'est pas l'écho v1, un bourrage refusé n'est pas
//!    nul.
//! 4. **UN `Ok` N'EST JAMAIS UNE CONTREFAÇON** : sous la seule racine crue, une
//!    sonde acceptée est EXACTEMENT celle que la racine signerait pour ces
//!    champs — Ed25519 est déterministe, le harnais la resigne et compare.

#![no_main]

use libfuzzer_sys::fuzz_target;

use asl_cle::{ClePublique, CleSecrete, identifiant_de_racine};
use asl_echo::{REQUETE_OCTETS, Refus, SondeAnnuaire, VERSION, est_de_l_echo};
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
    match SondeAnnuaire::lire(octets) {
        Ok(sonde) => {
            assert_eq!(
                sonde.octets().as_slice(),
                octets,
                "une sonde lue ne se réécrit pas"
            );
            if let Ok(acceptee) = sonde.accepter(moi(), &racines, MAINTENANT) {
                let resignee = SondeAnnuaire::signer(
                    sonde.defi(),
                    sonde.annuaire(),
                    sonde.cible(),
                    sonde.emise_a(),
                    &racine(),
                )
                .expect("des genres lus à leur place");
                assert_eq!(
                    resignee.octets().as_slice(),
                    octets,
                    "une contrefaçon acceptée"
                );
                assert_eq!(acceptee.defi(), sonde.defi());
                assert_eq!(acceptee.sondeur(), sonde.annuaire());
            }
        }
        Err(Refus::Longueur { attendue, obtenue }) => {
            assert_eq!(attendue, REQUETE_OCTETS);
            assert_eq!(obtenue, octets.len());
            assert_ne!(obtenue, REQUETE_OCTETS);
        }
        Err(Refus::PasDeLEcho { premier }) => {
            assert_eq!(octets.first(), Some(&premier));
            assert!(!est_de_l_echo(premier));
        }
        Err(Refus::Version { premier }) => {
            assert_eq!(octets.first(), Some(&premier));
            assert!(est_de_l_echo(premier) && premier != VERSION);
        }
        Err(Refus::Genre { genre }) => assert_eq!(octets.get(1), Some(&genre)),
        Err(Refus::Bourrage) => {
            assert!(
                octets[122..].iter().any(|octet| *octet != 0),
                "un bourrage nul refusé"
            );
        }
        Err(autre) => panic!("un refus qu'une sonde d'annuaire ne peut pas rendre : {autre:?}"),
    }
});
