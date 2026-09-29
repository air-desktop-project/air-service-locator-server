//! **Cible : la réponse de l'écho, telle que le sondeur la reçoit.**
//!
//! Ce sont les octets que lit `asl ping` sur une socket éphémère, et
//! l'annuaire quand il sonde : n'importe qui peut en envoyer, à n'importe
//! quel port qu'il devine.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique.**
//! 2. **UNE RÉPONSE LUE SE RÉÉCRIT À L'OCTET PRÈS** — l'adresse comprise : une
//!    IPv4 enfouie se relit en IPv4 et se réenfouit à l'identique.
//! 3. **UN REFUS DIT VRAI** — dont le port nul, lu à sa place.
//! 4. **UNE PREUVE N'EST JAMAIS UNE CONTREFAÇON** : une réponse que le sondeur
//!    vérifie sous la clé de la machine est exactement celle que la machine
//!    signerait — resignée et comparée.

#![no_main]

use libfuzzer_sys::fuzz_target;

use asl_cle::{CleSecrete, identifiant_de_racine};
use asl_echo::{Adresse, REPONSE_OCTETS, Refus, Reponse, VERSION, est_de_l_echo};
use asl_id::{Genre, Identifiant};

// ── Le décor : les clés et les identifiants des vecteurs figés ─────────────
//
// Ceux de `crates/asl-echo/tests/fixtures/vecteurs.py`, pour que les graines —
// ces vecteurs mêmes — soient ACCEPTÉES, et que libFuzzer parte de ce qui
// passe tous les refus plutôt que de s'arrêter au premier octet.

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

fn lui() -> Identifiant {
    Identifiant::depuis_entropie(Genre::Machine, suite(0x80))
}

fuzz_target!(|octets: &[u8]| {
    match Reponse::lire(octets) {
        Ok(reponse) => {
            assert_eq!(
                reponse.octets().as_slice(),
                octets,
                "une réponse lue ne se réécrit pas"
            );
            let adresse = reponse.adresse();
            assert_eq!(Adresse::depuis_source(adresse.source()), adresse);
            let cle = machine().publique();
            for sondeur in [lui(), racine_id()] {
                if reponse
                    .verifier(&reponse.defi(), moi(), sondeur, &cle)
                    .is_ok()
                {
                    let resignee =
                        Reponse::signer(reponse.defi(), moi(), adresse, sondeur, &machine())
                            .expect("des genres admis");
                    assert_eq!(
                        resignee.octets().as_slice(),
                        octets,
                        "une preuve contrefaite"
                    );
                }
            }
        }
        Err(Refus::Longueur { attendue, obtenue }) => {
            assert_eq!(attendue, REPONSE_OCTETS);
            assert_eq!(obtenue, octets.len());
            assert_ne!(obtenue, REPONSE_OCTETS);
        }
        Err(Refus::PasDeLEcho { premier }) => {
            assert_eq!(octets.first(), Some(&premier));
            assert!(!est_de_l_echo(premier));
        }
        Err(Refus::Version { premier }) => assert!(est_de_l_echo(premier) && premier != VERSION),
        Err(Refus::Genre { genre }) => assert_eq!(octets.get(1), Some(&genre)),
        Err(Refus::PortNul) => assert_eq!(&octets[50..52], &[0, 0]),
        Err(autre) => panic!("un refus qu'une réponse ne peut pas rendre : {autre:?}"),
    }
});
