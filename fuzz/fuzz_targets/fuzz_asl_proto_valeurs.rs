//! **Cible : les valeurs du protocole** — protocole, port, nom de service, lus
//! depuis des octets qu'on n'a pas choisis.
//!
//! # Pourquoi celle-ci
//!
//! Ce sont les trois décodeurs qu'un daemon tiers atteint en premier, et le port
//! est celui où une faute coûte le plus cher : un `65536` tronqué vaudrait `0`,
//! c'est-à-dire un service annoncé sur un port qui n'existe pas, sans qu'aucune
//! erreur ne soit rendue (contrainte C3).
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique.**
//! 2. **AUCUN PORT ACCEPTÉ N'EST NUL.** C'est la promesse entière du type, et
//!    elle se vérifie sur le RÉSULTAT plutôt que sur l'entrée — donc
//!    indépendamment de la façon dont on l'a obtenu.
//! 3. **CE QUI EST ACCEPTÉ SE RÉÉCRIT ET SE RELIT À L'IDENTIQUE.** Un port qu'on
//!    saurait lire mais pas réécrire ferait diverger les deux moitiés du
//!    protocole.
//! 4. **UNE SEULE ÉCRITURE PAR VALEUR** : ce qui est accepté est déjà canonique,
//!    donc réécrire ne change pas le texte. C'est ce qui interdit qu'un même
//!    port ou un même nom entrent deux fois sous deux orthographes.
//! 5. **Un nom accepté tient dans ses bornes et son alphabet**, vérifié sur le
//!    résultat.

#![no_main]

use libfuzzer_sys::fuzz_target;

use asl_proto::{NOM_MAX, NomService, Port, Protocole};

fuzz_target!(|donnees: &[u8]| {
    let Ok(texte) = core::str::from_utf8(donnees) else {
        return;
    };

    // ── Le protocole ────────────────────────────────────────────────────────
    if let Ok(protocole) = Protocole::analyser(texte) {
        // PROPRIÉTÉ 4 : ce qui est accepté est déjà son écriture canonique.
        assert_eq!(
            protocole.texte(),
            texte,
            "le protocole n'était pas canonique"
        );
        // PROPRIÉTÉ 3 : l'aller-retour.
        assert_eq!(Protocole::analyser(protocole.texte()), Ok(protocole));
        // Seul TCP se sonde — la propriété qui gouverne l'état rendu (C6).
        assert_eq!(protocole.se_sonde(), protocole == Protocole::Tcp);
    }

    // ── Le port ─────────────────────────────────────────────────────────────
    if let Ok(port) = Port::analyser(texte) {
        // PROPRIÉTÉ 2 : aucun port accepté n'est nul.
        assert_ne!(port.valeur(), 0, "un port nul est passé : {texte:?}");

        // PROPRIÉTÉ 3 et 4 : l'écriture est canonique, et se relit.
        let mut ecrit = String::with_capacity(5);
        core::fmt::Write::write_fmt(&mut ecrit, format_args!("{port}"))
            .expect("écrire dans une String ne peut pas échouer");
        assert_eq!(ecrit, texte, "le port accepté n'était pas canonique");
        assert_eq!(Port::analyser(&ecrit), Ok(port));
    }

    // ── Le nom de service ───────────────────────────────────────────────────
    if let Ok(nom) = NomService::analyser(texte) {
        let brut = nom.as_str();
        assert_eq!(brut, texte, "le nom accepté n'était pas rendu tel quel");

        // PROPRIÉTÉ 5 : les bornes et l'alphabet, vérifiés sur le RÉSULTAT.
        assert!(!brut.is_empty(), "un nom vide est passé");
        assert!(
            brut.len() <= NOM_MAX,
            "un nom de {} octets est passé",
            brut.len()
        );
        for (position, octet) in brut.bytes().enumerate() {
            let permis = octet.is_ascii_lowercase()
                || octet.is_ascii_digit()
                || matches!(octet, b'-' | b'_' | b'.');
            assert!(permis, "octet interdit en {position} : {octet:?}");
        }
        let premier = brut.as_bytes()[0];
        let dernier = brut.as_bytes()[brut.len() - 1];
        assert!(!matches!(premier, b'-' | b'.'), "bord de tête invalide");
        assert!(!matches!(dernier, b'-' | b'.'), "bord de queue invalide");

        // PROPRIÉTÉ 3 : l'aller-retour.
        assert_eq!(NomService::analyser(brut), Ok(nom));
    }
});
