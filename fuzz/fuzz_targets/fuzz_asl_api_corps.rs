//! **Cible : les corps de l'API mobile** — des octets d'un inconnu vers une
//! demande, ou vers un refus.
//!
//! # Pourquoi celle-ci
//!
//! Ces deux corps portent le premier TEXTE LIBRE du produit : le nom d'une
//! machine, qui accepte désormais l'UTF-8 entier. C'est un relâchement
//! délibéré (voir `Lecteur::texte_libre`), et **tout relâchement d'un analyseur
//! demande qu'on le pousse sur des octets qu'on n'a pas choisis.**
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, sur aucun octet.
//! 2. **CE QU'ON A COMPRIS, ON SAIT LE RÉÉCRIRE — ET LE RELIRE À L'IDENTIQUE.**
//!    Un aller-retour qui ne rendrait pas les mêmes octets voudrait dire que
//!    deux écritures désignent la même demande, ou qu'une demande acceptée ne
//!    peut pas être redite.
//! 3. **AUCUN NOM ACCEPTÉ NE PORTE CE QUI EST REFUSÉ.** Vérifié sur la valeur
//!    RENDUE : ni guillemet, ni barre oblique inverse, ni contrôle, ni
//!    caractère qui change l'affichage de ce qui l'entoure.
//! 4. **UN NOM ACCEPTÉ TIENT DANS LA PLACE QUE L'ENTREPÔT LUI RÉSERVE.** Sans
//!    cela, une requête bien formée finirait en `500`.
//! 5. **UN ALIAS ACCEPTÉ RESTE DE L'ASCII GRAPHIQUE.** C'est la propriété qui
//!    sépare une CLÉ d'un texte d'affichage : l'alias se cherche, se compare, et
//!    repart dans un chemin — deux écritures d'une même valeur feraient croire à
//!    deux comptes qu'ils la possèdent chacun.

#![no_main]

use libfuzzer_sys::fuzz_target;

use asl_api::corps::{
    AppareilRendu, AutorisationRendue, CLE_APPAREIL_OCTETS, COMPTE_CORPS_MAX, CORPS_MAX,
    CreationDeCompte, DeclarationMachine, DemandeAlias, DemandeAutorisation, MachineRendue,
    NOM_MACHINE_MAX, PREUVE_APPAREIL_OCTETS, PlateformeAttestation,
};

/// Ce caractère change-t-il l'affichage de ce qui l'entoure ?
///
/// La même liste que `asl_proto::cadrage`, recopiée ICI À DESSEIN : une cible de
/// fuzz qui importerait le prédicat qu'elle éprouve ne prouverait que sa propre
/// cohérence.
const fn invisible(caractere: char) -> bool {
    matches!(
        caractere,
        '\u{0080}'..='\u{009F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'
    )
}

fuzz_target!(|octets: &[u8]| {
    if let Ok(machine) = DeclarationMachine::decoder(octets) {
        // ── 3. LE NOM NE PORTE RIEN DE CE QUI EST REFUSÉ ────────────────────
        for caractere in machine.nom.chars() {
            assert!(
                caractere != '"' && caractere != '\\',
                "un nom accepté porte {caractere:?}, que l'encodeur ne saurait pas écrire"
            );
            assert!(
                !caractere.is_control(),
                "un nom accepté porte un contrôle : {caractere:?}"
            );
            assert!(
                !invisible(caractere),
                "un nom accepté porte {caractere:?}, qui ment sur ce qui l'entoure"
            );
        }

        // ── 4. IL TIENT DANS LA PLACE QUE L'ENTREPÔT LUI RÉSERVE ────────────
        assert!(
            !machine.nom.is_empty() && machine.nom.len() <= NOM_MACHINE_MAX,
            "un nom de {} octets a été accepté",
            machine.nom.len()
        );

        // ── 2. L'ALLER-RETOUR ───────────────────────────────────────────────
        let mut sortie = [0_u8; CORPS_MAX];
        let combien = machine
            .encoder(&mut sortie)
            .expect("ce qui a été compris se réécrit");
        let ecrit = &sortie[..combien];
        let relue = DeclarationMachine::decoder(ecrit).expect("ce qu'on écrit se relit");
        assert_eq!(relue, machine, "l'aller-retour a changé la demande");

        let mut encore = [0_u8; CORPS_MAX];
        let deux = relue.encoder(&mut encore).expect("elle se réécrit");
        assert_eq!(&encore[..deux], ecrit, "l'écriture n'est pas canonique");
    }

    if let Ok(demande) = DemandeAlias::decoder(octets) {
        // **UN ALIAS EST UNE CLÉ, ET SA GRAMMAIRE EST ÉTROITE.** Vérifié sur ce
        // qui est RENDU : c'est de là que `GET /v1/alias/{alias}` repartira, et
        // un alias accepté ici doit pouvoir se remettre dans un chemin.
        let texte = demande.alias.as_str();
        assert!(
            texte.bytes().all(|o| o.is_ascii_graphic()),
            "un alias accepté porte autre chose que de l'ASCII graphique : {texte:?}"
        );

        let mut sortie = [0_u8; CORPS_MAX];
        let combien = demande
            .encoder(&mut sortie)
            .expect("ce qui a été compris se réécrit");
        let ecrit = &sortie[..combien];
        let relue = DemandeAlias::decoder(ecrit).expect("ce qu'on écrit se relit");
        assert_eq!(relue, demande, "l'aller-retour a changé la demande");

        let mut encore = [0_u8; CORPS_MAX];
        let deux = relue.encoder(&mut encore).expect("elle se réécrit");
        assert_eq!(&encore[..deux], ecrit, "l'écriture n'est pas canonique");
    }

    if let Ok(demande) = DemandeAutorisation::decoder(octets) {
        let mut sortie = [0_u8; CORPS_MAX];
        let combien = demande
            .encoder(&mut sortie)
            .expect("ce qui a été compris se réécrit");
        let ecrit = &sortie[..combien];
        let relue = DemandeAutorisation::decoder(ecrit).expect("ce qu'on écrit se relit");
        assert_eq!(relue, demande, "l'aller-retour a changé la demande");

        let mut encore = [0_u8; CORPS_MAX];
        let deux = relue.encoder(&mut encore).expect("elle se réécrit");
        assert_eq!(&encore[..deux], ecrit, "l'écriture n'est pas canonique");
    }

    // ── CE QU'UNE LISTE D'AUTORISATIONS REND ────────────────────────────────
    if let Ok(rendue) = AutorisationRendue::decoder(octets) {
        // L'étiquette rendue est du texte libre : elle repart dans une réponse,
        // donc ne porte rien de ce que l'encodeur ne saurait écrire sans
        // échappement.
        for caractere in rendue.etiquette.chars() {
            assert!(
                caractere != '"'
                    && caractere != '\\'
                    && !caractere.is_control()
                    && !invisible(caractere),
                "une étiquette rendue porte {caractere:?}, que l'encodeur ne saurait pas écrire"
            );
        }
        assert!(
            !rendue.etiquette.is_empty() && rendue.etiquette.len() <= NOM_MACHINE_MAX,
            "une étiquette rendue de {} octets a été acceptée",
            rendue.etiquette.len()
        );

        let mut sortie = [0_u8; CORPS_MAX];
        let combien = rendue
            .encoder(&mut sortie)
            .expect("ce qui a été compris se réécrit");
        let ecrit = &sortie[..combien];
        let relue = AutorisationRendue::decoder(ecrit).expect("ce qu'on écrit se relit");
        assert_eq!(relue, rendue, "l'aller-retour a changé l'autorisation");
        let mut encore = [0_u8; CORPS_MAX];
        let deux = relue.encoder(&mut encore).expect("elle se réécrit");
        assert_eq!(&encore[..deux], ecrit, "l'écriture n'est pas canonique");
    }

    // ── CE QU'UNE LISTE DE MACHINES REND ────────────────────────────────────
    if let Ok(machine) = MachineRendue::decoder(octets) {
        // **3. LE NOM RENDU NE PORTE RIEN DE CE QUI EST REFUSÉ.** Le même texte
        // libre que la déclaration, et il repart dans une réponse : ce qu'il
        // porte doit pouvoir se réécrire sans échappement.
        for caractere in machine.nom.chars() {
            assert!(
                caractere != '"'
                    && caractere != '\\'
                    && !caractere.is_control()
                    && !invisible(caractere),
                "un nom rendu porte {caractere:?}, que l'encodeur ne saurait pas écrire"
            );
        }
        assert!(
            !machine.nom.is_empty() && machine.nom.len() <= NOM_MACHINE_MAX,
            "un nom rendu de {} octets a été accepté",
            machine.nom.len()
        );

        // 2. L'aller-retour, canonique.
        let mut sortie = [0_u8; CORPS_MAX];
        let combien = machine
            .encoder(&mut sortie)
            .expect("ce qui a été compris se réécrit");
        let ecrit = &sortie[..combien];
        let relue = MachineRendue::decoder(ecrit).expect("ce qu'on écrit se relit");
        assert_eq!(relue, machine, "l'aller-retour a changé la machine");
        let mut encore = [0_u8; CORPS_MAX];
        let deux = relue.encoder(&mut encore).expect("elle se réécrit");
        assert_eq!(&encore[..deux], ecrit, "l'écriture n'est pas canonique");
    }

    // ── CE QU'UNE LISTE D'APPAREILS REND ────────────────────────────────────
    if let Ok(appareil) = AppareilRendu::decoder(octets) {
        let mut sortie = [0_u8; CORPS_MAX];
        let combien = appareil
            .encoder(&mut sortie)
            .expect("ce qui a été compris se réécrit");
        let ecrit = &sortie[..combien];
        let relu = AppareilRendu::decoder(ecrit).expect("ce qu'on écrit se relit");
        assert_eq!(relu, appareil, "l'aller-retour a changé l'appareil");
        let mut encore = [0_u8; CORPS_MAX];
        let deux = relu.encoder(&mut encore).expect("il se réécrit");
        assert_eq!(&encore[..deux], ecrit, "l'écriture n'est pas canonique");
    }

    // ── LE CORPS DE POST /v1/comptes ────────────────────────────────────────
    if let Ok(compte) = CreationDeCompte::decoder(octets) {
        // Les tranches ont la taille annoncée, et l'attestation est cohérente
        // avec la plate-forme — ni octet en trop derrière `Aucune`, ni vide
        // derrière une plate-forme déclarée.
        assert_eq!(compte.cle.len(), CLE_APPAREIL_OCTETS);
        assert_eq!(compte.preuve.len(), PREUVE_APPAREIL_OCTETS);
        match compte.plateforme {
            PlateformeAttestation::Aucune => assert!(
                compte.attestation.is_empty(),
                "une plate-forme Aucune ne doit rien traîner : {} octets",
                compte.attestation.len()
            ),
            PlateformeAttestation::Apple | PlateformeAttestation::Google => assert!(
                !compte.attestation.is_empty(),
                "une plate-forme déclarée sans attestation a été acceptée"
            ),
        }

        // L'aller-retour, canonique.
        let mut sortie = [0_u8; COMPTE_CORPS_MAX];
        let combien = compte
            .encoder(&mut sortie)
            .expect("ce qui a été compris se réécrit");
        let ecrit = &sortie[..combien];
        assert_eq!(
            ecrit, octets,
            "le corps n'est pas canonique : deux écritures"
        );
        let relu = CreationDeCompte::decoder(ecrit).expect("ce qu'on écrit se relit");
        assert_eq!(relu, compte, "l'aller-retour a changé le corps");
    }
});
