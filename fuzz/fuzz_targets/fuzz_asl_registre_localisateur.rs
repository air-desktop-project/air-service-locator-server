//! **Cible : le localisateur détecté** (`--locator auto`, décision 64) — ce
//! que le noyau écrit dans `/proc/net/if_inet6` et `/proc/net/ipv6_route`, et
//! l'adresse qu'on en choisit pour la publier aux racines.
//!
//! # Pourquoi celle-ci
//!
//! Le noyau n'est pas un inconnu ; mais le choix est **ce que la maison dit
//! au monde pour qu'on la joigne**, et une adresse de travers publiée
//! renverrait les daemons dans le vide. La lecture est écrite à la main,
//! champ par champ : C3 la veut fuzzée comme tout décodeur.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, sur aucun octet.
//! 2. **L'ADRESSE CHOISIE EST PUBLIABLE ET VIENT DU TEXTE** : une ligne lue
//!    la porte, publiable — globale, stable, ni temporaire ni dépréciée —, sur
//!    l'interface nommée si l'on en nomme une ;
//! 3. **ET C'EST LA PLUS PETITE** : aucune adresse publiable de l'interface
//!    de cette ligne n'est plus petite qu'elle.
//! 4. **RIEN DE PUBLIABLE, RIEN DE CHOISI.**

#![no_main]

use libfuzzer_sys::fuzz_target;

use asl_registre::localisateur::{AdresseDInterface, choisir, interface_par_defaut};

fuzz_target!(|octets: &[u8]| {
    let Ok(texte) = core::str::from_utf8(octets) else {
        return;
    };
    let (adresses, routes) = texte.split_once('\0').unwrap_or((texte, ""));
    let publiables: Vec<AdresseDInterface<'_>> = adresses
        .lines()
        .filter_map(AdresseDInterface::lire)
        .filter(AdresseDInterface::publiable)
        .collect();
    let _ = interface_par_defaut(routes);
    let nommee = publiables.first().map(|lue| lue.interface);
    for interface in [None, nommee] {
        match choisir(adresses, routes, interface) {
            Some(choisie) => {
                // Une même adresse peut figurer sur deux interfaces : il suffit
                // qu'UNE de ses lignes tienne les deux propriétés.
                assert!(
                    publiables.iter().any(|porteuse| {
                        porteuse.adresse == choisie
                            && interface.is_none_or(|nom| porteuse.interface == nom)
                            && !publiables.iter().any(|lue| {
                                lue.interface == porteuse.interface && lue.adresse < choisie
                            })
                    }),
                    "l'adresse choisie ne vient pas d'une ligne publiable, ou n'est pas la plus petite de son interface"
                );
            }
            None => assert!(
                !publiables
                    .iter()
                    .any(|lue| interface.is_none_or(|nom| lue.interface == nom)),
                "une adresse publiable, et rien de choisi"
            ),
        }
    }
});
