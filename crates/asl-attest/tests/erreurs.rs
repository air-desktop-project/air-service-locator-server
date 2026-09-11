//! Chaque refus DIT lequel il est.
//!
//! # POURQUOI CET ESSAI EXISTE
//!
//! Ce lecteur lira le premier objet d'attestation réel que ce produit verra,
//! et je n'en ai jamais vu. **Le jour où il en refuse un, la seule chose qui
//! dira quoi faire est la phrase du refus.** Un « objet mal formé » unique
//! laisserait à chercher entre onze règles.

use asl_attest::{Champ, Erreur, X5C_MAX};

/// Toutes les fautes, une fois chacune.
fn toutes() -> Vec<(Erreur, &'static str)> {
    vec![
        (
            Erreur::Tronque { position: 3 },
            "octets tronqués en position 3",
        ),
        (
            Erreur::TypeRefuse {
                majeur: 7,
                position: 0,
            },
            "type majeur 7 refusé en position 0",
        ),
        (
            Erreur::LongueurIndefinie { position: 1 },
            "longueur indéfinie en position 1",
        ),
        (
            Erreur::EnteteReserve { position: 2 },
            "en-tête réservé en position 2",
        ),
        (
            Erreur::EncodageNonMinimal { position: 4 },
            "encodage non minimal en position 4",
        ),
        (
            Erreur::LongueurDemesuree {
                annoncee: 9,
                position: 5,
            },
            "longueur 9 démesurée en position 5",
        ),
        (
            Erreur::TexteInvalide { position: 6 },
            "texte non UTF-8 en position 6",
        ),
        (
            Erreur::PasLeBonType { position: 7 },
            "valeur d'un autre type en position 7",
        ),
        (
            Erreur::TropProfond { position: 8 },
            "imbrication trop profonde en position 8",
        ),
        (
            Erreur::DonneesEnTrop { position: 9 },
            "octets en trop à partir de 9",
        ),
        (
            Erreur::ChampManquant {
                champ: Champ::DonneesAuth,
            },
            "champ `authData` manquant",
        ),
        (
            Erreur::ChampEnDouble {
                champ: Champ::Format,
            },
            "champ `fmt` en double",
        ),
        (Erreur::FormatInconnu, "format d'attestation inconnu"),
        (
            Erreur::TropDeCertificats { annonces: 9 },
            "9 certificats annoncés, 4 au plus",
        ),
        (
            Erreur::AuthDataTronque { octets: 12 },
            "`authData` tronqué à 12 octets",
        ),
    ]
}

#[test]
fn chaque_faute_a_sa_phrase() {
    for (faute, attendue) in toutes() {
        assert_eq!(faute.to_string(), attendue, "pour {faute:?}");
    }
}

#[test]
fn aucune_phrase_n_en_repete_une_autre() {
    // Deux fautes qui rendraient le même texte seraient une faute de moins.
    let mut phrases: Vec<String> = toutes().into_iter().map(|(f, _)| f.to_string()).collect();
    let combien = phrases.len();
    phrases.sort();
    phrases.dedup();
    assert_eq!(phrases.len(), combien, "des phrases se répètent");
}

#[test]
fn la_borne_de_la_chaine_est_celle_qui_est_dite() {
    // La phrase cite X5C_MAX ; si la borne bougeait sans la phrase, le refus
    // mentirait.
    assert_eq!(X5C_MAX, 4);
}
