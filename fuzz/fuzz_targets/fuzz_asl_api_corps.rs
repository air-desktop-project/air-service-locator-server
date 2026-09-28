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
//! 6. **UN POINT DE POUSSÉE ACCEPTÉ A LA FORME QUE L'ENVOI SUPPOSE**
//!    (`protocole.md` §2.2) : `https://`, un nom DNS dont la dernière étiquette
//!    n'est pas numérique, sans `@`, sans `#`, le port 443 ou rien, de l'ASCII
//!    graphique, 1024 octets au plus ; une clé commence par `0x04`. Vérifié
//!    sur ce qui est RENDU — l'hôte, la cible —, pas sur l'entrée.
//! 7. **UN ALIAS DE DOMAINE ACCEPTÉ NE PORTE RIEN DE CE QUI EST REFUSÉ**
//!    (2026-09-26) : il est non vide, tient dans deux cent cinquante-cinq
//!    octets bruts, et ne porte ni guillemet, ni barre oblique inverse, ni
//!    contrôle, ni caractère qui change l'affichage de ce qui l'entoure — ce
//!    que `asl-registre` normalisera ensuite. Un rattachement nomme un `d-…`.
//! 8. **UNE ÉTIQUETTE DE GROUPE ACCEPTÉE EST UN NOM DE MACHINE** (2026-09-27) :
//!    non vide, soixante-quatre octets au plus, rien de refusé ; un ajout
//!    nomme un `u-…` ; la preuve d'un exploitant a sa longueur exacte, le
//!    genre `o` en tête, et nomme un compte.
//! 9. **UNE DEMANDE DE DROIT ACCEPTÉE A LA FORME QUE L'ÉTAGE 3 SUPPOSE**
//!    (2026-09-27) : un groupe, un élément domaine, machine ou service, au
//!    moins un droit connu, une étiquette aux règles d'un nom — et elle se
//!    relit à l'identique une fois réécrite.
//! 10. **UNE ADRESSE D'ANNUAIRE LOCAL ACCEPTÉE SE RÉÉMET TELLE QUELLE**
//!     (0.27.0) : ni guillemet, ni barre oblique inverse, ni contrôle — ce
//!     qu'`asl-registre` en garde, `InscriptionRendue` le réécrit sans
//!     échappement, entre ses guillemets ; un hébergeur nomme un `n-…`.
//!     **Et des locateurs publiés** (0.30.0) : quatre au plus, chacun sans ce
//!     que l'encodeur ne réécrit pas ; une liste de racines relue se réécrit
//!     en une liste qui se relit à l'identique.
//! 5. **UN ALIAS DE COMPTE ACCEPTÉ EST DU TEXTE LIBRE BORNÉ** (0.26.0,
//!    décision 46) : non vide, au plus deux cent cinquante-cinq octets bruts, sans
//!    guillemet, barre oblique inverse ni contrôle. L'unicité de sa forme — le
//!    NFC — est tenue par `asl-registre`, pas par ce cadrage.

#![no_main]

use libfuzzer_sys::fuzz_target;

use asl_api::corps::{
    ATTESTATION_CORPS_MAX, AppareilRendu, AttestationDAppareil, AutorisationRendue,
    CLE_APPAREIL_OCTETS, COMPTE_CORPS_MAX, CORPS_MAX, CreationDeCompte, DeclarationMachine,
    DemandeAlias, DemandeAutorisation, DepotPoint, DescriptionAppareil, MachineRendue, MachineVue,
    NOM_MACHINE_MAX, POINT_CORPS_MAX, PREUVE_APPAREIL_OCTETS, PlateformeAttestation,
};
use asl_api::domaine::{ALIAS_BRUT_MAX, CreationDeDomaine, PoseDAlias, Rattachement};
use asl_api::groupe::{Adhesion, Etiquetage, NOMINATION_CORPS_OCTETS, Nomination};
use asl_api::point::{POINT_MAX, UrlDePoussee};

/// Un alias de domaine accepté ne porte rien de ce qui est refusé.
fn verifier_l_alias_de_domaine(alias: &str) {
    assert!(!alias.is_empty() && alias.len() <= ALIAS_BRUT_MAX);
    for caractere in alias.chars() {
        assert!(
            caractere != '"'
                && caractere != '\\'
                && !caractere.is_control()
                && !invisible(caractere),
            "un alias de domaine accepté porte {caractere:?}"
        );
    }
}

/// Ce point a-t-il la forme que l'envoi suppose ? Recopié ICI, à dessein,
/// comme [`invisible`] : la règle est relue sur ce que l'analyseur a RENDU.
fn verifier_le_point(point: &UrlDePoussee<'_>) {
    let texte = point.texte();
    assert!(texte.len() <= POINT_MAX, "un point de plus de 1024 octets");
    assert!(texte.starts_with("https://"), "un point sans https://");
    assert!(
        texte.bytes().all(|octet| octet.is_ascii_graphic()),
        "un point porte un octet non graphique"
    );
    assert!(!texte.contains('#'), "un point porte un fragment");
    let hote = point.hote();
    assert!(
        !hote.is_empty() && hote.len() <= 253,
        "un hôte vide ou trop long"
    );
    assert!(
        hote.bytes()
            .all(|octet| octet.is_ascii_alphanumeric() || octet == b'-' || octet == b'.'),
        "un hôte porte autre chose qu'un nom DNS : {hote}"
    );
    let derniere = hote.rsplit('.').next().unwrap_or_default();
    assert!(
        !derniere.bytes().all(|octet| octet.is_ascii_digit()),
        "un hôte finit par une étiquette numérique : {hote}"
    );
    // L'autorité est l'hôte, avec au plus `:443`.
    let apres = &texte["https://".len()..];
    let autorite = &apres[..apres.find(['/', '?']).unwrap_or(apres.len())];
    assert!(
        autorite == hote || autorite == format!("{hote}:443"),
        "l'autorité {autorite} n'est pas l'hôte {hote}"
    );
    let (devant, cible) = point.cible();
    let cible = format!("{devant}{cible}");
    assert!(cible.starts_with('/'), "la cible ne commence pas par /");
    assert!(texte.ends_with(&cible[devant.len()..]));
}

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
    // ── LA PAIRE (0.36.0, décision 70) : ce qui se lit se réécrit et se relit
    // à l'identique.
    if let Ok(declaration) = asl_api::annuaire::DeclarationDePair::decoder(octets) {
        let mut sortie = [0_u8; 64];
        let combien = declaration.encoder(&mut sortie).expect("elle tient");
        assert_eq!(
            asl_api::annuaire::DeclarationDePair::decoder(&sortie[..combien]),
            Ok(declaration)
        );
    }
    if let Ok(paire) = asl_api::annuaire::PaireRendue::decoder(octets) {
        let mut sortie = [0_u8; 256];
        let combien = paire.encoder(&mut sortie).expect("elle tient");
        assert_eq!(
            asl_api::annuaire::PaireRendue::decoder(&sortie[..combien]),
            Ok(paire)
        );
    }
    // ── 10. LES ANNUAIRES LOCAUX ────────────────────────────────────────────
    if let Ok(declaration) = asl_api::annuaire::DeclarationDAnnuaire::decoder(octets) {
        assert!(
            !declaration
                .adresse
                .chars()
                .any(|c| c == '"' || c == '\\' || c.is_control()),
            "une adresse acceptée porte ce que l'encodeur ne réécrit pas"
        );
        if let Ok(adresse) = asl_registre::Adresse::nouvelle(declaration.adresse) {
            let rendue = asl_api::annuaire::InscriptionRendue {
                membre: None,
                annuaire: None,
                proprietaire: None,
                etat: "attendue",
                adresse: adresse.texte(),
                locateurs: &[],
                expire_a: Some(u64::MAX),
                paire: None,
            };
            let mut sortie = [0_u8; 512];
            let combien = rendue.encoder(&mut sortie).expect("elle tient");
            let attendu = format!(
                "{{\"etat\":\"attendue\",\"adresse\":\"{}\",\"expire_a\":{}}}",
                declaration.adresse,
                u64::MAX
            );
            assert_eq!(&sortie[..combien], attendu.as_bytes());
        }
    }
    if let Ok(hebergeur) = asl_api::annuaire::Hebergeur::decoder(octets) {
        assert_eq!(hebergeur.annuaire.genre(), asl_id::Genre::Annuaire);
    }
    if let Ok(publication) = asl_api::annuaire::PublicationDeLocateurs::decoder(octets) {
        assert!(publication.locateurs().len() <= asl_api::annuaire::LOCATEURS_MAX);
        assert!(publication.locateurs().iter().all(|locateur| {
            !locateur
                .chars()
                .any(|c| c == '"' || c == '\\' || c.is_control())
        }));
    }
    if let Ok(liste) = asl_api::annuaire::ListeDeRacines::decoder(octets) {
        let mut refaite = b"[".to_vec();
        for (rang, racine) in liste.racines().enumerate() {
            assert_eq!(racine.annuaire.genre(), asl_id::Genre::Annuaire);
            if rang > 0 {
                refaite.push(b',');
            }
            let mut sortie = [0_u8; 4_096];
            let combien = asl_api::annuaire::RacineRendue {
                annuaire: racine.annuaire,
                cle: racine.cle,
                locateurs: racine.locateurs(),
            }
            .encoder(&mut sortie)
            .expect("une racine relue tient");
            refaite.extend_from_slice(&sortie[..combien]);
        }
        refaite.push(b']');
        let relue = asl_api::annuaire::ListeDeRacines::decoder(&refaite).expect("elle se relit");
        assert!(liste.racines().eq(relue.racines()), "l'aller-retour tient");
    }
    // Une décision n'a que deux valeurs : il suffit qu'elle ne panique pas.
    let _ = asl_api::annuaire::DecisionDInscription::decoder(octets);

    // ── 9. LES DROITS ───────────────────────────────────────────────────────
    //
    // Une demande acceptée porte un groupe, un élément d'un des trois genres
    // admis, au moins un droit connu, une étiquette aux règles d'un nom ; et
    // elle se réécrit en une demande que le décodeur relit à l'identique.
    if let Ok(demande) = asl_api::droit::DemandeDeDroit::decoder(octets) {
        assert_eq!(demande.groupe.genre(), asl_id::Genre::Ensemble);
        assert!(matches!(
            demande.element.genre(),
            asl_id::Genre::Domaine | asl_id::Genre::Machine | asl_id::Genre::Service
        ));
        assert!(demande.droits != 0 && demande.droits & !0b1111 == 0);
        assert!(!demande.etiquette.is_empty() && demande.etiquette.len() <= NOM_MACHINE_MAX);
        let mut sortie = [0_u8; 1024];
        let combien = demande.encoder(&mut sortie).expect("elle tient");
        assert_eq!(
            asl_api::droit::DemandeDeDroit::decoder(&sortie[..combien]),
            Ok(demande),
            "une demande réécrite ne se relit pas"
        );
    }

    // ── 8. LES GROUPES ──────────────────────────────────────────────────────
    if let Ok(etiquetage) = Etiquetage::decoder(octets) {
        let texte = etiquetage.etiquette;
        assert!(!texte.is_empty() && texte.len() <= NOM_MACHINE_MAX);
        for caractere in texte.chars() {
            assert!(
                caractere != '"'
                    && caractere != '\\'
                    && !caractere.is_control()
                    && !invisible(caractere),
                "une étiquette acceptée porte {caractere:?}"
            );
        }
    }
    if let Ok(adhesion) = Adhesion::decoder(octets) {
        assert_eq!(adhesion.compte.genre(), asl_id::Genre::Utilisateur);
    }
    if let Ok(nomination) = Nomination::decoder(octets) {
        assert_eq!(octets.len(), NOMINATION_CORPS_OCTETS);
        assert_eq!(octets.first(), Some(&b'o'));
        assert_eq!(nomination.compte.genre(), asl_id::Genre::Utilisateur);
    }

    // ── 7. LES DOMAINES ─────────────────────────────────────────────────────
    if let Ok(CreationDeDomaine { alias: Some(alias) }) = CreationDeDomaine::decoder(octets) {
        verifier_l_alias_de_domaine(alias);
    }
    if let Ok(pose) = PoseDAlias::decoder(octets) {
        verifier_l_alias_de_domaine(pose.alias);
    }
    if let Ok(rattachement) = Rattachement::decoder(octets) {
        assert_eq!(rattachement.domaine.genre(), asl_id::Genre::Domaine);
    }

    // ── 6. LE POINT DE POUSSÉE ──────────────────────────────────────────────
    if let Ok(texte) = core::str::from_utf8(octets)
        && let Ok(point) = UrlDePoussee::analyser(texte)
    {
        verifier_le_point(&point);
    }
    if let Ok(depot) = DepotPoint::decoder(octets) {
        verifier_le_point(&depot.point);
        if let Some(cle) = depot.cle {
            assert_eq!(cle[0], 0x04, "une clé qui n'est pas un point non compressé");
        }
        let mut sortie = [0_u8; POINT_CORPS_MAX];
        let combien = depot
            .encoder(&mut sortie)
            .expect("ce qui a été compris se réécrit");
        let ecrit = &sortie[..combien];
        let relu = DepotPoint::decoder(ecrit).expect("ce qu'on écrit se relit");
        assert_eq!(relu, depot, "l'aller-retour a changé le dépôt");
    }

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
        // Du texte libre, que l'encodeur réécrit sans échappement.
        let texte = demande.alias;
        assert!(!texte.is_empty() && texte.len() <= ALIAS_BRUT_MAX);
        assert!(
            texte
                .chars()
                .all(|c| c != '"' && c != '\\' && !c.is_control() && !invisible(c)),
            "un alias accepté porte un caractère refusé : {texte:?}"
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
        // L'alias rendu (0.26.0) : sous les mêmes règles que le nom.
        if let Some(alias) = machine.alias {
            assert!(!alias.is_empty() && alias.len() <= asl_api::corps::ALIAS_DE_MACHINE_MAX);
            assert!(
                alias
                    .chars()
                    .all(|c| c != '"' && c != '\\' && !c.is_control() && !invisible(c))
            );
        }
        let relue = MachineRendue::decoder(ecrit).expect("ce qu'on écrit se relit");
        assert_eq!(relue, machine, "l'aller-retour a changé la machine");
        let mut encore = [0_u8; CORPS_MAX];
        let deux = relue.encoder(&mut encore).expect("elle se réécrit");
        assert_eq!(&encore[..deux], ecrit, "l'écriture n'est pas canonique");
    }

    // ── CE QU'UNE AUTORISATION DONNE À VOIR : UNE MACHINE ───────────────────
    if let Ok(vue) = MachineVue::decoder(octets) {
        for caractere in vue.nom.chars() {
            assert!(
                caractere != '"'
                    && caractere != '\\'
                    && !caractere.is_control()
                    && !invisible(caractere),
                "un nom vu porte {caractere:?}, que l'encodeur ne saurait pas écrire"
            );
        }
        assert!(
            !vue.nom.is_empty() && vue.nom.len() <= NOM_MACHINE_MAX,
            "un nom vu de {} octets a été accepté",
            vue.nom.len()
        );
        let mut sortie = [0_u8; CORPS_MAX];
        let combien = vue
            .encoder(&mut sortie)
            .expect("ce qui a été compris se réécrit");
        let ecrit = &sortie[..combien];
        let relue = MachineVue::decoder(ecrit).expect("ce qu'on écrit se relit");
        assert_eq!(relue, vue, "l'aller-retour a changé la machine vue");
        let mut encore = [0_u8; CORPS_MAX];
        let deux = relue.encoder(&mut encore).expect("elle se réécrit");
        assert_eq!(&encore[..deux], ecrit, "l'écriture n'est pas canonique");
    }

    // ── CE QU'UN APPAREIL DIT DE LUI-MÊME ───────────────────────────────────
    if let Ok(description) = DescriptionAppareil::decoder(octets) {
        // **3. LE MODÈLE NE PORTE RIEN DE CE QUI EST REFUSÉ**, comme le nom
        // d'une machine : il repart dans `GET /v1/appareils` sans échappement.
        for caractere in description.modele.chars() {
            assert!(
                caractere != '"'
                    && caractere != '\\'
                    && !caractere.is_control()
                    && !invisible(caractere),
                "un modèle accepté porte {caractere:?}, que l'encodeur ne saurait pas écrire"
            );
        }
        assert!(
            !description.modele.is_empty() && description.modele.len() <= NOM_MACHINE_MAX,
            "un modèle de {} octets a été accepté",
            description.modele.len()
        );

        // 2. L'aller-retour, canonique.
        let mut sortie = [0_u8; CORPS_MAX];
        let combien = description
            .encoder(&mut sortie)
            .expect("ce qui a été compris se réécrit");
        let ecrit = &sortie[..combien];
        let relue = DescriptionAppareil::decoder(ecrit).expect("ce qu'on écrit se relit");
        assert_eq!(relue, description, "l'aller-retour a changé la description");
        let mut encore = [0_u8; CORPS_MAX];
        let deux = relue.encoder(&mut encore).expect("elle se réécrit");
        assert_eq!(&encore[..deux], ecrit, "l'écriture n'est pas canonique");
    }

    // ── CE QU'UNE LISTE D'APPAREILS REND ────────────────────────────────────
    if let Ok(appareil) = AppareilRendu::decoder(octets) {
        // Une description rendue va par deux, et son modèle suit les règles
        // ci-dessus.
        if let Some(description) = &appareil.description {
            assert!(
                !description.modele.is_empty() && description.modele.len() <= NOM_MACHINE_MAX,
                "un modèle rendu de {} octets a été accepté",
                description.modele.len()
            );
        }
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
            PlateformeAttestation::Apple | PlateformeAttestation::Android => assert!(
                !compte.attestation.is_empty(),
                "une plate-forme déclarée sans attestation a été acceptée"
            ),
            // **L'INVITATION EST BORNÉE DES DEUX CÔTÉS** : c'est un code, et
            // un code fait dix octets (`protocole.md` §2.2). Les deux autres
            // portent une chaîne, dont la longueur n'est pas connue.
            PlateformeAttestation::Invitation => assert_eq!(
                compte.attestation.len(),
                asl_api::corps::CODE_INVITATION_OCTETS,
                "une invitation qui ne fait pas dix octets a été acceptée"
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

    if let Ok(preuve) = AttestationDAppareil::decoder(octets) {
        // **LE GENRE EST `a`, ET LA CHAÎNE SUIT LA PLATE-FORME** — les mêmes
        // règles que la création d'un compte, sur la preuve d'un appareil qui
        // rejoint.
        assert_eq!(preuve.appareil.genre(), asl_id::Genre::Appareil);
        assert_eq!(preuve.preuve.len(), PREUVE_APPAREIL_OCTETS);
        match preuve.plateforme {
            PlateformeAttestation::Aucune => assert!(
                preuve.attestation.is_empty(),
                "une plate-forme Aucune ne doit rien traîner : {} octets",
                preuve.attestation.len()
            ),
            PlateformeAttestation::Apple
            | PlateformeAttestation::Android
            | PlateformeAttestation::Invitation => assert!(
                !preuve.attestation.is_empty(),
                "une plate-forme déclarée sans attestation a été acceptée"
            ),
        }
        let mut sortie = [0_u8; ATTESTATION_CORPS_MAX];
        let combien = preuve
            .encoder(&mut sortie)
            .expect("ce qui a été compris se réécrit");
        let ecrit = &sortie[..combien];
        assert_eq!(
            ecrit, octets,
            "le corps n'est pas canonique : deux écritures"
        );
        let relu = AttestationDAppareil::decoder(ecrit).expect("ce qu'on écrit se relit");
        assert_eq!(relu, preuve, "l'aller-retour a changé le corps");
    }
});
