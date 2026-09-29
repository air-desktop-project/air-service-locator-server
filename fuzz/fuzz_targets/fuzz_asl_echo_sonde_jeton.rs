//! **Cible : la sonde munie d'un jeton, et tout ce que l'écho en décide.**
//!
//! Elle porte DEUX signatures et un jeton de 193 octets lu à l'intérieur :
//! c'est le décodeur le plus riche de l'écho, et celui dont une faute
//! ouvrirait l'écho à n'importe quel sondeur.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, ni à la lecture, ni à la décision
//!    (`asl_echo::accepter`, qui trie les deux genres).
//! 2. **UNE SONDE LUE SE RÉÉCRIT À L'OCTET PRÈS.**
//! 3. **UN REFUS DIT VRAI** — la longueur, le premier octet, le bourrage, la
//!    version du jeton lue à sa place.
//! 4. **UN `Ok` N'EST JAMAIS UNE CONTREFAÇON** : sous la seule racine crue, un
//!    jeton accepté est celui que la racine émettrait pour ces champs, et la
//!    sonde celle que le sondeur des vecteurs signerait — resignés et
//!    comparés à l'octet près.

#![no_main]

use libfuzzer_sys::fuzz_target;

use asl_cle::{ClePublique, CleSecrete, identifiant_de_racine};
use asl_echo::{Jeton, REQUETE_OCTETS, Refus, SondeJeton, VERSION, accepter, est_de_l_echo};
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

fn sondeur() -> CleSecrete {
    CleSecrete::depuis_entropie([0x44; 32])
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
    let ma_cle = machine().publique();
    // La décision entière, sur les octets bruts : rien ne panique, et un
    // `Ok` par la voie du jeton est vérifié ci-dessous.
    let _ = accepter(octets, moi(), &ma_cle, &racines, &racines, MAINTENANT);

    match SondeJeton::lire(octets) {
        Ok(sonde) => {
            assert_eq!(
                sonde.octets().as_slice(),
                octets,
                "une sonde lue ne se réécrit pas"
            );
            if sonde.accepter(moi(), &ma_cle, &racines, MAINTENANT).is_ok() {
                let jeton = sonde.jeton();
                let reemis = Jeton::emettre(
                    &racine(),
                    jeton.cible(),
                    jeton.cle_cible(),
                    jeton.sondeur(),
                    jeton.cle_sondeur(),
                    jeton.emis_a(),
                )
                .expect("des genres lus à leur place");
                assert_eq!(&reemis, jeton, "un jeton contrefait accepté");
                assert_eq!(
                    jeton.cle_sondeur(),
                    sondeur().publique(),
                    "une sonde acceptée sous une clé que personne ne tient"
                );
                let resignee = SondeJeton::signer(sonde.defi(), reemis, &sondeur());
                assert_eq!(
                    resignee.octets().as_slice(),
                    octets,
                    "une sonde contrefaite acceptée"
                );
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
            assert!(est_de_l_echo(premier) && premier != VERSION);
        }
        Err(Refus::Genre { genre }) => assert_eq!(octets.get(1), Some(&genre)),
        Err(Refus::VersionDeJeton { version }) => assert_eq!(octets.get(18), Some(&version)),
        Err(Refus::CleInvalide) => {}
        Err(Refus::Bourrage) => {
            assert!(
                octets[275..].iter().any(|octet| *octet != 0),
                "un bourrage nul refusé"
            );
        }
        Err(autre) => {
            panic!("un refus qu'une sonde munie d'un jeton ne peut pas rendre : {autre:?}")
        }
    }
});
