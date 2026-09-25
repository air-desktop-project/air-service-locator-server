//! **Cible : ce que le réveilleur lit d'un inconnu** — la ligne de statut
//! qu'un serveur de poussée rend, et les adresses qu'un nom résout.
//!
//! # Pourquoi celle-ci
//!
//! Le serveur de poussée est choisi par l'utilisateur, donc par n'importe
//! qui : ses octets sont entièrement contrôlés par un inconnu. Et les adresses
//! qu'un nom rend le sont aussi, par qui tient le DNS de ce nom. Les deux
//! passent par des fonctions pures d'`asl-reveil` — c'est ici qu'on les pousse.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, sur aucun octet ni aucune adresse.
//! 2. **UN CODE N'EST RENDU QUE D'UNE LIGNE ENTIÈRE** qui commence par
//!    `HTTP/1.1 ` ou `HTTP/1.0 `, et il va de 100 à 599 ; ce qui suit la
//!    ligne ne change jamais le verdict — seule la ligne se lit.
//! 3. **UNE IPv4 ENFOUIE SE JUGE COMME ELLE-MÊME** : `::ffff:a.b.c.d` et
//!    `64:ff9b::a.b.c.d` rendent le verdict de `a.b.c.d`. Recalculé ici depuis
//!    les octets, pas en rappelant la règle.
//! 4. **HORS DE `2000::/3`, RIEN N'EST ADMIS** — sauf ces deux formes.

#![no_main]

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libfuzzer_sys::fuzz_target;

use asl_reveil::{Statut, juger, lire_le_statut};

fuzz_target!(|octets: &[u8]| {
    // ── 2. LA LIGNE DE STATUT ───────────────────────────────────────────────
    match lire_le_statut(octets) {
        Statut::Code(code) => {
            assert!((100..=599).contains(&code), "un code de {code}");
            assert!(
                octets.starts_with(b"HTTP/1.1 ") || octets.starts_with(b"HTTP/1.0 "),
                "un code lu d'autre chose qu'une ligne HTTP/1.x"
            );
            let fin = octets
                .windows(2)
                .position(|paire| paire == b"\r\n")
                .expect("un code sans fin de ligne");
            // Ce qui suit la ligne ne compte pas.
            let mut autre = octets[..fin + 2].to_vec();
            autre.extend_from_slice(b"HTTP/1.1 999 et puis quoi\r\n");
            assert_eq!(lire_le_statut(&autre), Statut::Code(code));
        }
        Statut::Incomplet => {
            assert!(
                !octets.windows(2).any(|paire| paire == b"\r\n"),
                "incomplet alors que la ligne est finie"
            );
        }
        Statut::Illisible => {}
    }

    // ── 3 et 4. LES ADRESSES ────────────────────────────────────────────────
    if let Some(seize) = octets.get(..16) {
        let mut brut = [0_u8; 16];
        brut.copy_from_slice(seize);
        let v6 = Ipv6Addr::from(brut);
        let verdict = juger(IpAddr::V6(v6));
        let [_, _, _, _, _, _, _, _, _, _, _, _, a, b, c, d] = brut;
        let v4 = Ipv4Addr::new(a, b, c, d);
        let enfouie = brut[..10].iter().all(|octet| *octet == 0) && brut[10..12] == [0xFF, 0xFF];
        let nat64 = brut[..12] == [0, 0x64, 0xFF, 0x9B, 0, 0, 0, 0, 0, 0, 0, 0];
        if enfouie || nat64 {
            assert_eq!(
                verdict,
                juger(IpAddr::V4(v4)),
                "{v6} n'est pas jugée comme {v4}"
            );
        } else if brut[0] & 0xE0 != 0x20 {
            assert!(verdict.is_err(), "{v6}, hors de 2000::/3, a été admise");
        }
        // Une IPv4 quelconque, jugée seule, ne panique pas non plus.
        let _ = juger(IpAddr::V4(v4));
    }
});
