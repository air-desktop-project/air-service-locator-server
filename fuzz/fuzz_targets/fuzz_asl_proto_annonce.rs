//! **Cible : la validation d'une annonce** — ce que `Annonce::nouvelle` accepte,
//! et ce qu'elle promet quand elle accepte.
//!
//! # Pourquoi celle-ci
//!
//! `Annonce::nouvelle` est le seul constructeur : **une annonce qui existe est
//! une annonce valide**. Toute la valeur de ce type repose là-dessus, et une
//! seule brèche suffirait — un doublon qui passe, un compte non borné — pour que
//! les couches au-dessus héritent d'un invariant qu'elles croient tenu.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique.**
//! 2. **CE QUI EST ACCEPTÉ TIENT TOUTES LES PROMESSES**, vérifiées sur le
//!    RÉSULTAT : identifiant de machine, au moins un point, comptes bornés,
//!    aucun doublon. C'est la formulation qui compte — vérifier l'ENTRÉE
//!    reviendrait à réécrire la validation et à comparer une fonction à
//!    elle-même.
//! 3. **CE QUI EST REFUSÉ L'EST POUR UNE RAISON QUI S'APPLIQUE VRAIMENT.** Une
//!    erreur juste mais qui désigne la mauvaise cause est crue, donc pire qu'une
//!    erreur vague.
//! 4. **La validation est déterministe** : deux appels sur la même entrée
//!    rendent la même chose.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use asl_id::{Genre, Identifiant};
use asl_proto::{
    ADRESSES_MAX, Annonce, Erreur, NomService, POINTS_MAX, PointEcoute, Port, Protocole,
};

/// Un point d'écoute, tel que le fuzzer sait le fabriquer.
#[derive(Arbitrary, Debug)]
struct PointBrut {
    /// Réduit modulo deux.
    protocole: u8,
    /// Zéro compris — c'est justement le cas qui doit être refusé.
    port: u16,
}

/// Une adresse, sous une forme que le fuzzer sait fabriquer.
#[derive(Arbitrary, Debug)]
enum AdresseBrute {
    /// Quatre octets.
    V4([u8; 4]),
    /// Seize octets.
    V6([u8; 16]),
}

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// Le genre de l'identifiant, réduit modulo six — donc pas toujours une
    /// machine, ce qui est le cas à refuser.
    genre: u8,
    /// L'entropie de l'identifiant.
    entropie: [u8; 16],
    /// Le nom, tel qu'il arriverait du réseau.
    nom: &'a str,
    /// Les points d'écoute, en nombre quelconque.
    points: Vec<PointBrut>,
    /// Les adresses locales, en nombre quelconque.
    adresses: Vec<AdresseBrute>,
}

/// Le genre que désigne un octet.
const fn genre(brut: u8) -> Genre {
    match brut % 6 {
        0 => Genre::Utilisateur,
        1 => Genre::Appareil,
        2 => Genre::Machine,
        3 => Genre::Service,
        4 => Genre::Autorisation,
        _ => Genre::Annuaire,
    }
}

fuzz_target!(|entree: Entree| {
    // Le nom passe par son propre analyseur : une annonce ne se construit pas
    // avec un nom qui n'en est pas un, et c'est l'autre cible qui l'éprouve.
    let Ok(nom) = NomService::analyser(entree.nom) else {
        return;
    };

    let identifiant = Identifiant::depuis_entropie(genre(entree.genre), entree.entropie);

    // Les ports nuls sont écartés ICI, par le type — c'est `Port` qui les
    // refuse, et son refus est éprouvé par l'autre cible.
    let points: Vec<PointEcoute> = entree
        .points
        .iter()
        .filter_map(|brut| {
            let protocole = if brut.protocole % 2 == 0 {
                Protocole::Tcp
            } else {
                Protocole::Udp
            };
            Port::depuis_u16(brut.port)
                .ok()
                .map(|port| PointEcoute::nouveau(protocole, port))
        })
        .collect();

    let adresses: Vec<IpAddr> = entree
        .adresses
        .iter()
        .map(|brute| match brute {
            AdresseBrute::V4(octets) => IpAddr::V4(Ipv4Addr::from(*octets)),
            AdresseBrute::V6(octets) => IpAddr::V6(Ipv6Addr::from(*octets)),
        })
        .collect();

    let resultat = Annonce::nouvelle(identifiant, nom, &points, &adresses);

    // PROPRIÉTÉ 4 : deux appels rendent la même chose.
    assert_eq!(
        resultat,
        Annonce::nouvelle(identifiant, nom, &points, &adresses),
        "la validation n'est pas déterministe"
    );

    match resultat {
        Ok(annonce) => {
            // ── PROPRIÉTÉ 2 : les promesses, vérifiées sur le RÉSULTAT ──────
            assert_eq!(
                annonce.machine.genre(),
                Genre::Machine,
                "une annonce accepte un identifiant qui n'est pas une machine"
            );
            assert!(
                !annonce.points.is_empty(),
                "une annonce sans point d'écoute est passée"
            );
            assert!(
                annonce.points.len() <= POINTS_MAX,
                "{} points sont passés",
                annonce.points.len()
            );
            assert!(
                annonce.adresses_locales.len() <= ADRESSES_MAX,
                "{} adresses sont passées",
                annonce.adresses_locales.len()
            );

            // Aucun doublon — recompté à la main, sans réemployer la fonction
            // qui a validé.
            for (rang, point) in annonce.points.iter().enumerate() {
                for autre in annonce.points.iter().skip(rang + 1) {
                    assert_ne!(point, autre, "deux points identiques sont passés");
                }
            }

            // Aucun port nul n'a pu entrer.
            for point in annonce.points {
                assert_ne!(point.port.valeur(), 0, "un port nul est passé");
            }

            // `a_un_point_sondable` dit exactement ce qu'on peut vérifier soi-même.
            let sondable = annonce.points.iter().any(|p| p.protocole == Protocole::Tcp);
            assert_eq!(annonce.a_un_point_sondable(), sondable);
        }
        Err(faute) => {
            // ── PROPRIÉTÉ 3 : la raison du refus s'applique vraiment ────────
            match faute {
                Erreur::PasUneMachine { obtenu } => {
                    assert_ne!(obtenu, Genre::Machine);
                    assert_eq!(obtenu, identifiant.genre());
                }
                Erreur::AucunPoint => assert!(points.is_empty()),
                Erreur::TropDePoints { obtenu } => {
                    assert_eq!(obtenu, points.len());
                    assert!(obtenu > POINTS_MAX);
                }
                Erreur::TropDAdresses { obtenu } => {
                    assert_eq!(obtenu, adresses.len());
                    assert!(obtenu > ADRESSES_MAX);
                }
                Erreur::PointEnDouble => {
                    let doublon = points
                        .iter()
                        .enumerate()
                        .any(|(rang, point)| points.iter().skip(rang + 1).any(|a| a == point));
                    assert!(doublon, "un doublon annoncé qui n'existe pas");
                }
                autre => panic!("`Annonce::nouvelle` ne devrait jamais rendre {autre:?}"),
            }
        }
    }
});
