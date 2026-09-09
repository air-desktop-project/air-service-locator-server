//! L'entrepôt, sur de vrais fichiers.
//!
//! # POURQUOI DES ESSAIS D'INTÉGRATION, ET NON DES ESSAIS UNITAIRES
//!
//! Ce qu'on veut éprouver ici n'est pas une fonction, c'est **ce qui reste vrai
//! après une écriture** : l'index d'alias d'accord avec son compte, une entrée
//! de journal qui survit à sa transaction, une rupture de confiance qui n'efface
//! pas plus qu'elle ne doit. Rien de cela n'a de sens sans un vrai fichier.

use std::path::PathBuf;

use asl_id::{Genre, Identifiant};
use asl_registre::{
    AliasRange, Compte, EntreeJournal, JetonPoussee, JetonRange, Machine, NomRange, Plateforme,
    Provenance, Verdict,
};
use asl_store::{Entrepot, Faute};

/// Un entrepôt neuf, dans un fichier à nous.
fn entrepot(quoi: &str) -> (Entrepot, PathBuf) {
    let chemin =
        std::env::temp_dir().join(format!("asl-entrepot-{}-{quoi}.redb", std::process::id()));
    let _ = std::fs::remove_file(&chemin);
    let ouvert = Entrepot::ouvrir(&chemin).expect("un entrepôt neuf");
    (ouvert, chemin)
}

/// Un identifiant de ce genre, reproductible.
fn un(genre: Genre, graine: u8) -> Identifiant {
    Identifiant::depuis_entropie(genre, [graine; 16])
}

/// Un compte avec cet alias, venu d'ici.
fn compte(alias: Option<&str>) -> Compte {
    Compte {
        provenance: Provenance::Ici,
        alias: alias.map(|texte| AliasRange::nouveau(texte).expect("il tient")),
    }
}

// ── L'ouverture ─────────────────────────────────────────────────────────────

#[test]
fn une_base_neuve_rend_rien_et_non_une_erreur() {
    // **LES TABLES SONT CRÉÉES À L'OUVERTURE.** Si elles naissaient à la
    // première écriture, cette lecture-ci échouerait avec « table inexistante »
    // — une base neuve rendrait une erreur là où elle doit rendre « rien ».
    let (base, chemin) = entrepot("neuve");
    assert_eq!(
        base.compte(un(Genre::Utilisateur, 1)).expect("lisible"),
        None
    );
    assert_eq!(base.machine(un(Genre::Machine, 1)).expect("lisible"), None);
    assert_eq!(base.compte_par_alias("personne").expect("lisible"), None);
    assert_eq!(base.entrees_du_journal().expect("lisible"), 0);
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn ce_qui_est_ecrit_survit_a_la_fermeture() {
    let chemin =
        std::env::temp_dir().join(format!("asl-entrepot-{}-survie.redb", std::process::id()));
    let _ = std::fs::remove_file(&chemin);
    let qui = un(Genre::Utilisateur, 4);

    {
        let base = Entrepot::ouvrir(&chemin).expect("un entrepôt");
        base.poser_compte(qui, &compte(Some("thierry")))
            .expect("écrit");
    }
    {
        let base = Entrepot::ouvrir(&chemin).expect("le même entrepôt");
        assert_eq!(
            base.compte(qui).expect("lisible"),
            Some(compte(Some("thierry")))
        );
        assert_eq!(
            base.compte_par_alias("thierry").expect("lisible"),
            Some(qui)
        );
    }
    let _ = std::fs::remove_file(&chemin);
}

// ── Les comptes et leur alias ───────────────────────────────────────────────

#[test]
fn un_compte_se_relit_par_son_identifiant_et_par_son_alias() {
    let (base, chemin) = entrepot("compte");
    let qui = un(Genre::Utilisateur, 1);
    base.poser_compte(qui, &compte(Some("thierry")))
        .expect("écrit");

    assert_eq!(
        base.compte(qui).expect("lisible"),
        Some(compte(Some("thierry")))
    );
    assert_eq!(
        base.compte_par_alias("thierry").expect("lisible"),
        Some(qui)
    );
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn changer_d_alias_retire_l_ancien_de_l_index() {
    // **C'EST L'INVARIANT DE L'INDEX.** Sans ce retrait, l'ancien nom rendrait
    // encore un identifiant — et deux noms désigneraient un compte qui n'en
    // revendique qu'un.
    let (base, chemin) = entrepot("changement");
    let qui = un(Genre::Utilisateur, 1);
    base.poser_compte(qui, &compte(Some("avant")))
        .expect("écrit");
    base.poser_compte(qui, &compte(Some("apres")))
        .expect("réécrit");

    assert_eq!(base.compte_par_alias("apres").expect("lisible"), Some(qui));
    assert_eq!(
        base.compte_par_alias("avant").expect("lisible"),
        None,
        "l'ancien alias rend encore un identifiant"
    );
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn retirer_son_alias_le_retire_aussi_de_l_index() {
    let (base, chemin) = entrepot("retrait");
    let qui = un(Genre::Utilisateur, 1);
    base.poser_compte(qui, &compte(Some("visible")))
        .expect("écrit");
    base.poser_compte(qui, &compte(None)).expect("réécrit");

    assert_eq!(base.compte(qui).expect("lisible"), Some(compte(None)));
    assert_eq!(base.compte_par_alias("visible").expect("lisible"), None);
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn un_alias_deja_pris_par_un_autre_est_refuse() {
    // Deux comptes qui répondraient au même alias le rendraient inutilisable
    // pour retrouver quelqu'un, ce qui est sa seule raison d'être.
    let (base, chemin) = entrepot("dispute");
    base.poser_compte(un(Genre::Utilisateur, 1), &compte(Some("thierry")))
        .expect("écrit");
    let refus = base.poser_compte(un(Genre::Utilisateur, 2), &compte(Some("thierry")));
    assert!(matches!(refus, Err(Faute::AliasPris)), "{refus:?}");

    // Et le premier n'a pas bougé.
    assert_eq!(
        base.compte_par_alias("thierry").expect("lisible"),
        Some(un(Genre::Utilisateur, 1))
    );
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn reecrire_son_propre_compte_sans_changer_d_alias_est_permis() {
    // Le refus ne doit porter que sur l'alias d'un AUTRE : sinon on ne pourrait
    // plus réécrire un compte sans lui retirer son nom d'abord.
    let (base, chemin) = entrepot("idempotent");
    let qui = un(Genre::Utilisateur, 1);
    base.poser_compte(qui, &compte(Some("thierry")))
        .expect("écrit");
    base.poser_compte(qui, &compte(Some("thierry")))
        .expect("le même compte, le même alias");
    assert_eq!(
        base.compte_par_alias("thierry").expect("lisible"),
        Some(qui)
    );
    let _ = std::fs::remove_file(&chemin);
}

// ── Les machines ────────────────────────────────────────────────────────────

#[test]
fn une_machine_se_relit_entiere() {
    let (base, chemin) = entrepot("machine");
    let machine = Machine {
        provenance: Provenance::Ici,
        proprietaire: un(Genre::Utilisateur, 1),
        cle: Some([0x42; 32]),
        annonce: true,
        lecture: false,
        nom: nom_de_machine("grenier"),
    };
    let qui = un(Genre::Machine, 9);
    base.poser_machine(qui, &machine).expect("écrit");
    assert_eq!(base.machine(qui).expect("lisible"), Some(machine));
    let _ = std::fs::remove_file(&chemin);
}

// ── Le journal (C18) ────────────────────────────────────────────────────────

/// Une entrée de journal à cet instant.
fn entree(quand: u64) -> EntreeJournal {
    EntreeJournal {
        quand,
        demandeur: un(Genre::Machine, 1),
        visee: un(Genre::Machine, 2),
        service: NomRange::nouveau("imap").expect("il tient"),
        verdict: Verdict::Servi,
        provenance: Provenance::Ici,
    }
}

#[test]
fn deux_entrees_de_la_meme_milliseconde_sont_toutes_deux_gardees() {
    // **SANS LE RANG, LA SECONDE ÉCRASERAIT LA PREMIÈRE**, et le journal
    // perdrait des faits sous charge — c'est-à-dire quand il compte.
    let (base, chemin) = entrepot("simultanees");
    base.journaliser(&entree(1_000)).expect("écrit");
    base.journaliser(&entree(1_000)).expect("écrit");
    assert_eq!(base.entrees_du_journal().expect("lisible"), 2);
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn l_expiration_efface_ce_qui_precede_et_rien_d_autre() {
    let (base, chemin) = entrepot("expiration");
    for quand in [1_000_u64, 2_000, 3_000] {
        base.journaliser(&entree(quand)).expect("écrit");
    }
    assert_eq!(base.entrees_du_journal().expect("lisible"), 3);

    let efface = base.expirer_le_journal(2_000).expect("expiré");
    assert_eq!(efface, 1, "seule l'entrée de 1 000 précède 2 000");
    assert_eq!(base.entrees_du_journal().expect("lisible"), 2);
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn l_expiration_est_une_borne_ouverte_a_droite() {
    // Une entrée EXACTEMENT à la borne n'est pas expirée : elle a l'âge limite,
    // elle ne l'a pas dépassé.
    let (base, chemin) = entrepot("borne");
    base.journaliser(&entree(2_000)).expect("écrit");
    assert_eq!(base.expirer_le_journal(2_000).expect("expiré"), 0);
    assert_eq!(base.entrees_du_journal().expect("lisible"), 1);
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn expirer_un_journal_vide_ne_fait_rien() {
    let (base, chemin) = entrepot("vide");
    assert_eq!(base.expirer_le_journal(u64::MAX).expect("expiré"), 0);
    let _ = std::fs::remove_file(&chemin);
}

// ── La rupture de confiance (C17) ───────────────────────────────────────────

#[test]
fn rompre_efface_ce_qui_vient_du_pair_et_lui_seul() {
    let (base, chemin) = entrepot("rupture");
    let pair = un(Genre::Annuaire, 1);
    let autre = un(Genre::Annuaire, 2);

    let du_pair = un(Genre::Utilisateur, 1);
    let d_ailleurs = un(Genre::Utilisateur, 2);
    let d_ici = un(Genre::Utilisateur, 3);

    base.poser_compte(
        du_pair,
        &Compte {
            provenance: Provenance::Annuaire(pair),
            alias: Some(AliasRange::nouveau("depair").expect("il tient")),
        },
    )
    .expect("écrit");
    base.poser_compte(
        d_ailleurs,
        &Compte {
            provenance: Provenance::Annuaire(autre),
            alias: None,
        },
    )
    .expect("écrit");
    base.poser_compte(d_ici, &compte(Some("chezmoi")))
        .expect("écrit");

    let machine_du_pair = un(Genre::Machine, 1);
    base.poser_machine(
        machine_du_pair,
        &Machine {
            provenance: Provenance::Annuaire(pair),
            proprietaire: du_pair,
            cle: Some([1; 32]),
            annonce: true,
            lecture: true,
            nom: nom_de_machine("grenier"),
        },
    )
    .expect("écrit");

    let efface = base.oublier_ce_qui_vient_de(pair).expect("rompu");
    assert_eq!(efface, 2, "un compte et une machine");

    assert_eq!(base.compte(du_pair).expect("lisible"), None);
    assert_eq!(base.machine(machine_du_pair).expect("lisible"), None);
    assert!(
        base.compte(d_ailleurs).expect("lisible").is_some(),
        "ce qui vient d'un AUTRE annuaire a été effacé"
    );
    assert!(
        base.compte(d_ici).expect("lisible").is_some(),
        "ce qu'on a écrit soi-même a été effacé"
    );
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn rompre_emporte_l_index_d_alias_avec_le_compte() {
    // Un alias resté seul rendrait l'identifiant d'un compte qui n'existe plus.
    let (base, chemin) = entrepot("rupture-alias");
    let pair = un(Genre::Annuaire, 1);
    let qui = un(Genre::Utilisateur, 1);
    base.poser_compte(
        qui,
        &Compte {
            provenance: Provenance::Annuaire(pair),
            alias: Some(AliasRange::nouveau("orphelin").expect("il tient")),
        },
    )
    .expect("écrit");

    base.oublier_ce_qui_vient_de(pair).expect("rompu");
    assert_eq!(base.compte_par_alias("orphelin").expect("lisible"), None);
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn rompre_ne_touche_jamais_au_journal() {
    // **C'EST L'EXCEPTION DE C17**, et elle a une raison défensive : le journal
    // est ce qui permet de constater qu'un pair a essayé. L'effacer avec la
    // relation effacerait la preuve de ce qui a motivé la rupture.
    let (base, chemin) = entrepot("rupture-journal");
    let pair = un(Genre::Annuaire, 1);

    let mut venue_du_pair = entree(1_000);
    venue_du_pair.provenance = Provenance::Annuaire(pair);
    base.journaliser(&venue_du_pair).expect("écrit");
    base.journaliser(&entree(2_000)).expect("écrit");

    base.oublier_ce_qui_vient_de(pair).expect("rompu");
    assert_eq!(
        base.entrees_du_journal().expect("lisible"),
        2,
        "le journal a été amputé par une rupture de confiance"
    );
    let _ = std::fs::remove_file(&chemin);
}

// ── Les services ────────────────────────────────────────────────────────────

/// Un service de cette machine, sous ce nom.
fn service(machine: Identifiant, nom: &str) -> asl_registre::Service {
    asl_registre::Service {
        provenance: Provenance::Ici,
        machine,
        nom: NomRange::nouveau(nom).expect("il tient"),
    }
}

#[test]
fn un_service_se_relit_par_son_identifiant_et_par_son_nom() {
    let (base, chemin) = entrepot("service");
    let machine = un(Genre::Machine, 1);
    let quel = un(Genre::Service, 1);
    base.poser_service(quel, &service(machine, "imap"))
        .expect("écrit");

    assert_eq!(
        base.service(quel).expect("lisible"),
        Some(service(machine, "imap"))
    );
    assert_eq!(
        base.service_par_nom(machine, "imap").expect("lisible"),
        Some(quel)
    );
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn deux_machines_peuvent_servir_le_meme_nom() {
    // **C'EST LA RAISON DE LA CLÉ COMPOSÉE.** Un nom de service n'est unique que
    // sur SA machine ; deux machines qui servent toutes deux `imap` est le cas
    // ordinaire, pas une collision.
    let (base, chemin) = entrepot("homonymes");
    let une = un(Genre::Machine, 1);
    let autre = un(Genre::Machine, 2);
    base.poser_service(un(Genre::Service, 1), &service(une, "imap"))
        .expect("écrit");
    base.poser_service(un(Genre::Service, 2), &service(autre, "imap"))
        .expect("écrit");

    assert_eq!(
        base.service_par_nom(une, "imap").expect("lisible"),
        Some(un(Genre::Service, 1))
    );
    assert_eq!(
        base.service_par_nom(autre, "imap").expect("lisible"),
        Some(un(Genre::Service, 2))
    );
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn renommer_un_service_retire_l_ancien_nom_de_l_index() {
    let (base, chemin) = entrepot("renomme");
    let machine = un(Genre::Machine, 1);
    let quel = un(Genre::Service, 1);
    base.poser_service(quel, &service(machine, "avant"))
        .expect("écrit");
    base.poser_service(quel, &service(machine, "apres"))
        .expect("réécrit");

    assert_eq!(
        base.service_par_nom(machine, "apres").expect("lisible"),
        Some(quel)
    );
    assert_eq!(
        base.service_par_nom(machine, "avant").expect("lisible"),
        None,
        "l'ancien nom rend encore un identifiant"
    );
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn un_service_qu_aucune_machine_ne_sert_est_introuvable() {
    let (base, chemin) = entrepot("service-absent");
    assert_eq!(base.service(un(Genre::Service, 9)).expect("lisible"), None);
    assert_eq!(
        base.service_par_nom(un(Genre::Machine, 9), "rien")
            .expect("lisible"),
        None
    );
    let _ = std::fs::remove_file(&chemin);
}

// ── Les autorisations ───────────────────────────────────────────────────────

/// Une autorisation de `par` à `a`, de cette portée.
fn autorisation(
    par: Identifiant,
    a: Identifiant,
    portee: asl_registre::Portee,
) -> asl_registre::Autorisation {
    asl_registre::Autorisation {
        provenance: Provenance::Ici,
        par,
        a,
        portee,
        revoquee: false,
    }
}

#[test]
fn les_autorisations_recues_sont_celles_du_beneficiaire_et_pas_d_un_autre() {
    let (base, chemin) = entrepot("recues");
    let donneur = un(Genre::Utilisateur, 1);
    let beneficiaire = un(Genre::Utilisateur, 2);
    let etranger = un(Genre::Utilisateur, 3);

    base.poser_autorisation(
        un(Genre::Autorisation, 1),
        &autorisation(donneur, beneficiaire, asl_registre::Portee::ToutLeCompte),
    )
    .expect("écrit");
    base.poser_autorisation(
        un(Genre::Autorisation, 2),
        &autorisation(donneur, etranger, asl_registre::Portee::ToutLeCompte),
    )
    .expect("écrit");

    let siennes = base.autorisations_recues(beneficiaire).expect("lisible");
    assert_eq!(siennes.len(), 1, "{siennes:?}");
    assert_eq!(siennes.first().map(|quoi| quoi.a), Some(beneficiaire));
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn un_meme_beneficiaire_peut_en_recevoir_plusieurs() {
    // **SANS L'AUTORISATION EN QUEUE DE CLÉ**, la seconde écraserait la
    // première — et l'on n'en verrait qu'une, celle qui par malchance
    // n'accorderait pas ce qu'il fallait.
    let (base, chemin) = entrepot("plusieurs");
    let beneficiaire = un(Genre::Utilisateur, 2);
    for (rang, portee) in [
        (1_u8, asl_registre::Portee::ToutLeCompte),
        (2, asl_registre::Portee::UneMachine(un(Genre::Machine, 1))),
        (3, asl_registre::Portee::UnService(un(Genre::Service, 1))),
    ] {
        base.poser_autorisation(
            un(Genre::Autorisation, rang),
            &autorisation(un(Genre::Utilisateur, 1), beneficiaire, portee),
        )
        .expect("écrit");
    }
    assert_eq!(
        base.autorisations_recues(beneficiaire)
            .expect("lisible")
            .len(),
        3
    );
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn une_autorisation_revoquee_reste_visible() {
    // Elle est révoquée, jamais effacée : c'est `asl-auth` qui l'écarte, et la
    // cacher ici priverait l'utilisateur de voir ce qu'il a retiré.
    let (base, chemin) = entrepot("revoquee");
    let beneficiaire = un(Genre::Utilisateur, 2);
    let mut retiree = autorisation(
        un(Genre::Utilisateur, 1),
        beneficiaire,
        asl_registre::Portee::ToutLeCompte,
    );
    retiree.revoquee = true;
    base.poser_autorisation(un(Genre::Autorisation, 1), &retiree)
        .expect("écrit");

    let siennes = base.autorisations_recues(beneficiaire).expect("lisible");
    assert_eq!(siennes.first().map(|quoi| quoi.revoquee), Some(true));
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn un_compte_sans_autorisation_en_recoit_une_liste_vide() {
    let (base, chemin) = entrepot("aucune");
    assert!(
        base.autorisations_recues(un(Genre::Utilisateur, 7))
            .expect("lisible")
            .is_empty()
    );
    let _ = std::fs::remove_file(&chemin);
}

/// Un nom de machine, pour les essais.
fn nom_de_machine(texte: &str) -> asl_registre::NomRange {
    asl_registre::NomRange::nouveau(texte).expect("un nom court se range")
}

// ── Les appareils ───────────────────────────────────────────────────────────

#[test]
fn un_appareil_se_pose_et_se_relit() {
    let (base, fichier) = entrepot("appareil");
    let quel = un(Genre::Appareil, 3);
    assert_eq!(base.appareil(quel).expect("lisible"), None, "base neuve");

    let appareil = asl_registre::Appareil {
        provenance: Provenance::Ici,
        proprietaire: un(Genre::Utilisateur, 1),
        cle: [0x77; 32],
        revoque: false,
    };
    base.poser_appareil(quel, &appareil).expect("écrit");
    assert_eq!(base.appareil(quel).expect("lisible"), Some(appareil));

    let _ = std::fs::remove_file(fichier);
}

// ── Les codes d'enrôlement ──────────────────────────────────────────────────

/// L'empreinte de ce code.
fn empreinte(texte: &str) -> [u8; 32] {
    asl_cle::CodeEnrolement::analyser(texte)
        .expect("un code")
        .empreinte()
}

#[test]
fn un_code_se_pose_se_consomme_une_fois_et_pas_deux() {
    let (base, fichier) = entrepot("code");
    let machine = un(Genre::Machine, 4);
    let clef = empreinte("0123456789");

    base.poser_enrolement(
        &clef,
        &asl_registre::Enrolement {
            provenance: Provenance::Ici,
            machine,
            expire_a: 1_000,
        },
    )
    .expect("écrit");

    let pris = base.consommer_enrolement(&clef).expect("lisible");
    assert_eq!(pris.map(|quoi| quoi.machine), Some(machine));

    // **À USAGE UNIQUE**, et c'est la suppression qui le rend vrai : un code
    // consommé et un code inconnu sont le même fait.
    assert_eq!(
        base.consommer_enrolement(&clef)
            .expect("lisible")
            .map(|quoi| quoi.machine),
        None
    );

    let _ = std::fs::remove_file(fichier);
}

#[test]
fn emettre_un_code_tue_le_precedent() {
    // Deux secrets vivants pour une même machine, dont un que plus personne
    // n'attend : c'est exactement ce qu'on ne veut pas laisser derrière soi.
    let (base, fichier) = entrepot("code-remplace");
    let machine = un(Genre::Machine, 4);
    let vieux = empreinte("0123456789");
    let neuf = empreinte("9876543210");

    for clef in [&vieux, &neuf] {
        base.poser_enrolement(
            clef,
            &asl_registre::Enrolement {
                provenance: Provenance::Ici,
                machine,
                expire_a: 1_000,
            },
        )
        .expect("écrit");
    }

    assert!(
        base.consommer_enrolement(&vieux)
            .expect("lisible")
            .is_none(),
        "le premier code aurait dû mourir avec l'émission du second"
    );
    assert!(base.consommer_enrolement(&neuf).expect("lisible").is_some());

    let _ = std::fs::remove_file(fichier);
}

#[test]
fn les_codes_perimes_se_balaient_et_les_autres_restent() {
    let (base, fichier) = entrepot("code-expire");
    let perime = empreinte("0123456789");
    let vivant = empreinte("9876543210");

    for (clef, machine, expire_a) in [(&perime, 4_u8, 100_u64), (&vivant, 5, 10_000)] {
        base.poser_enrolement(
            clef,
            &asl_registre::Enrolement {
                provenance: Provenance::Ici,
                machine: un(Genre::Machine, machine),
                expire_a,
            },
        )
        .expect("écrit");
    }

    assert_eq!(base.expirer_les_enrolements(1_000).expect("balayé"), 1);
    assert!(
        base.consommer_enrolement(&perime)
            .expect("lisible")
            .is_none()
    );
    assert!(
        base.consommer_enrolement(&vivant)
            .expect("lisible")
            .is_some()
    );

    let _ = std::fs::remove_file(fichier);
}

// ── C17 : la rupture atteint TOUT ce qui porte une origine ──────────────────

#[test]
fn rompre_efface_les_services_les_autorisations_les_appareils_et_les_codes() {
    // **CETTE CONTRAINTE TOMBAIT.** C17 dit « aucun enregistrement ne doit
    // subsister avec cette origine », et la rupture n'atteignait que les comptes
    // et les machines — un service ou une autorisation venus d'un pair
    // survivaient. C17 dit aussi COMMENT elle tombe : « par un `INSERT` ajouté à
    // la hâte, jamais par une décision. »
    let (base, fichier) = entrepot("rupture-complete");
    let pair = un(Genre::Annuaire, 1);
    let venu = Provenance::Annuaire(pair);

    let compte = un(Genre::Utilisateur, 2);
    let machine = un(Genre::Machine, 3);
    let service = un(Genre::Service, 4);
    let appareil = un(Genre::Appareil, 5);
    let autorisation = un(Genre::Autorisation, 6);
    let clef = empreinte("0123456789");

    base.poser_compte(
        compte,
        &Compte {
            provenance: venu,
            alias: None,
        },
    )
    .expect("écrit");
    base.poser_machine(
        machine,
        &Machine {
            provenance: venu,
            proprietaire: compte,
            cle: Some([1; 32]),
            annonce: true,
            lecture: true,
            nom: nom_de_machine("grenier"),
        },
    )
    .expect("écrit");
    base.poser_service(
        service,
        &asl_registre::Service {
            provenance: venu,
            machine,
            nom: NomRange::nouveau("depot").expect("un nom"),
        },
    )
    .expect("écrit");
    base.poser_appareil(
        appareil,
        &asl_registre::Appareil {
            provenance: venu,
            proprietaire: compte,
            cle: [2; 32],
            revoque: false,
        },
    )
    .expect("écrit");
    base.poser_autorisation(
        autorisation,
        &asl_registre::Autorisation {
            provenance: venu,
            par: compte,
            a: un(Genre::Utilisateur, 7),
            portee: asl_registre::Portee::ToutLeCompte,
            revoquee: false,
        },
    )
    .expect("écrit");
    base.poser_enrolement(
        &clef,
        &asl_registre::Enrolement {
            provenance: venu,
            machine,
            expire_a: 10_000,
        },
    )
    .expect("écrit");

    // Et une ligne de journal, qui doit SURVIVRE — c'est la seule exception, et
    // elle est écrite dans C17 : ce qui motive une rupture est souvent ce que le
    // journal a enregistré.
    base.journaliser(&EntreeJournal {
        quand: 1,
        demandeur: compte,
        visee: machine,
        service: NomRange::nouveau("depot").expect("un nom"),
        verdict: Verdict::Servi,
        provenance: venu,
    })
    .expect("écrit");

    let efface = base.oublier_ce_qui_vient_de(pair).expect("rompu");
    assert_eq!(
        efface, 6,
        "un compte, une machine, un service, une autorisation, un appareil, un code"
    );

    assert_eq!(base.compte(compte).expect("lisible"), None);
    assert_eq!(base.machine(machine).expect("lisible"), None);
    assert_eq!(base.service(service).expect("lisible"), None);
    assert_eq!(base.appareil(appareil).expect("lisible"), None);
    assert!(base.consommer_enrolement(&clef).expect("lisible").is_none());
    assert!(
        base.service_par_nom(machine, "depot")
            .expect("lisible")
            .is_none(),
        "l'index par nom part avec le service"
    );
    assert!(
        base.autorisations_recues(un(Genre::Utilisateur, 7))
            .expect("lisible")
            .is_empty(),
        "l'index des reçues part avec l'autorisation"
    );
    assert_eq!(
        base.entrees_du_journal().expect("lisible"),
        1,
        "LE JOURNAL SURVIT — c'est l'exception de C17, et la seule"
    );

    let _ = std::fs::remove_file(fichier);
}

// ── Une base neuve ──────────────────────────────────────────────────────────

#[test]
fn une_base_neuve_rend_des_listes_vides_et_non_des_fautes() {
    // **UNE TABLE QUE REDB N'A JAMAIS VUE N'EXISTE PAS**, et l'ouvrir en lecture
    // rend `TableDoesNotExist` — pas un intervalle vide. Trois index créés après
    // coup manquaient à `ouvrir`, et lister les machines d'un compte neuf
    // échouait donc, ce que l'étage 3 traduisait en `404` là où le protocole
    // promet `200` et un tableau vide.
    let (base, fichier) = entrepot("neuve");
    let compte = un(Genre::Utilisateur, 1);
    let appareil = un(Genre::Appareil, 2);

    assert!(base.machines_de_compte(compte).expect("lisible").is_empty());
    assert!(
        base.autorisations_accordees(compte)
            .expect("lisible")
            .is_empty()
    );
    assert!(base.jeton(appareil).expect("lisible").is_none());

    let _ = std::fs::remove_file(fichier);
}

// ── Les jetons de poussée ───────────────────────────────────────────────────

/// Un jeton d'essai.
fn jeton(plateforme: Plateforme, texte: &str) -> JetonPoussee {
    JetonPoussee {
        provenance: Provenance::Ici,
        plateforme,
        jeton: JetonRange::nouveau(texte).expect("il tient"),
    }
}

#[test]
fn un_jeton_se_depose_se_relit_et_se_remplace() {
    // **LE NEUF REMPLACE L'ANCIEN**, il ne s'ajoute pas : Apple et Google font
    // tourner leurs jetons, et en garder deux enverrait chaque notification en
    // double, dont une à un jeton mort.
    let (base, fichier) = entrepot("jeton");
    let quel = un(Genre::Appareil, 3);
    assert!(base.jeton(quel).expect("lisible").is_none());

    base.poser_jeton(quel, &jeton(Plateforme::Apns, "c0ffee"))
        .expect("écrit");
    let lu = base.jeton(quel).expect("lisible").expect("il est là");
    assert_eq!(lu.plateforme, Plateforme::Apns);
    assert_eq!(lu.jeton.octets(), b"c0ffee");

    base.poser_jeton(quel, &jeton(Plateforme::Fcm, "d0d0"))
        .expect("écrit");
    let lu = base.jeton(quel).expect("lisible").expect("il est là");
    assert_eq!(
        lu.plateforme,
        Plateforme::Fcm,
        "la plate-forme change aussi"
    );
    assert_eq!(lu.jeton.octets(), b"d0d0");

    assert!(
        base.retirer_jeton(quel).expect("lisible"),
        "il y en avait un"
    );
    assert!(base.jeton(quel).expect("lisible").is_none());
    assert!(
        !base.retirer_jeton(quel).expect("lisible"),
        "retirer ce qui n'est plus là ne ment pas"
    );

    let _ = std::fs::remove_file(fichier);
}

#[test]
fn revoquer_un_appareil_emporte_son_jeton() {
    // **L'APPAREIL RESTE MARQUÉ, LE JETON PART.** L'écran d'après une perte doit
    // montrer ce qu'on a retiré ; le jeton, lui, n'a rien à montrer, et le
    // laisser derrière ferait continuer les notifications du compte vers le
    // téléphone de qui l'a.
    let (base, fichier) = entrepot("revoque-jeton");
    let quel = un(Genre::Appareil, 3);
    base.poser_appareil(
        quel,
        &asl_registre::Appareil {
            provenance: Provenance::Ici,
            proprietaire: un(Genre::Utilisateur, 1),
            cle: [0x77; 32],
            revoque: false,
        },
    )
    .expect("écrit");
    base.poser_jeton(quel, &jeton(Plateforme::Apns, "c0ffee"))
        .expect("écrit");

    base.revoquer_appareil(quel).expect("révoqué");
    assert!(
        base.appareil(quel)
            .expect("lisible")
            .expect("il reste")
            .revoque
    );
    assert!(
        base.jeton(quel).expect("lisible").is_none(),
        "le jeton part avec l'appareil"
    );

    let _ = std::fs::remove_file(fichier);
}

// ── Les révocations ─────────────────────────────────────────────────────────

#[test]
fn revoquer_un_appareil_le_marque_sans_l_effacer() {
    // **L'APPLICATION DOIT POUVOIR MONTRER CE QUI A ÉTÉ RÉVOQUÉ.** C'est
    // l'écran qu'on regarde après avoir perdu un téléphone, et une ligne
    // disparue n'y dit rien.
    let (base, fichier) = entrepot("revoque-appareil");
    let quel = un(Genre::Appareil, 3);
    assert!(
        base.revoquer_appareil(quel).expect("lisible").is_none(),
        "révoquer ce qui n'existe pas ne crée rien"
    );

    base.poser_appareil(
        quel,
        &asl_registre::Appareil {
            provenance: Provenance::Ici,
            proprietaire: un(Genre::Utilisateur, 1),
            cle: [0x77; 32],
            revoque: false,
        },
    )
    .expect("écrit");

    let avant = base.revoquer_appareil(quel).expect("révoqué");
    assert_eq!(
        avant.map(|quoi| quoi.revoque),
        Some(false),
        "ce qu'il ÉTAIT"
    );
    let apres = base.appareil(quel).expect("lisible").expect("il reste");
    assert!(apres.revoque);
    assert_eq!(apres.cle, [0x77; 32], "la clé reste, et ne vaut plus");

    let _ = std::fs::remove_file(fichier);
}

#[test]
fn revoquer_une_autorisation_la_marque_et_la_laisse_visible() {
    let (base, fichier) = entrepot("revoque-autorisation");
    let quelle = un(Genre::Autorisation, 6);
    let beneficiaire = un(Genre::Utilisateur, 7);
    assert!(base.autorisation(quelle).expect("lisible").is_none());
    assert!(
        base.revoquer_autorisation(quelle)
            .expect("lisible")
            .is_none()
    );

    base.poser_autorisation(
        quelle,
        &asl_registre::Autorisation {
            provenance: Provenance::Ici,
            par: un(Genre::Utilisateur, 2),
            a: beneficiaire,
            portee: asl_registre::Portee::ToutLeCompte,
            revoquee: false,
        },
    )
    .expect("écrit");

    assert_eq!(
        base.revoquer_autorisation(quelle)
            .expect("révoquée")
            .map(|quoi| quoi.revoquee),
        Some(false)
    );
    assert!(
        base.autorisation(quelle)
            .expect("lisible")
            .expect("elle reste")
            .revoquee
    );

    // **L'INDEX DES REÇUES NE BOUGE PAS** : le bénéficiaire doit continuer de
    // voir ce qu'on lui a retiré. C'est `couvre` qui refuse, pas l'index qui
    // cache.
    let recues = base.autorisations_recues(beneficiaire).expect("lisible");
    assert_eq!(recues.len(), 1);
    assert!(recues[0].revoquee);

    let _ = std::fs::remove_file(fichier);
}

// ── Ce que les verbes de liste interrogent ──────────────────────────────────

/// Une machine de ce compte, avec ce nom.
fn une_machine(proprietaire: Identifiant, nom: &str) -> Machine {
    Machine {
        provenance: Provenance::Ici,
        proprietaire,
        nom: NomRange::nouveau(nom).expect("il tient"),
        annonce: true,
        lecture: true,
        cle: None,
    }
}

/// Un service de cette machine, avec ce nom.
fn un_service(machine: Identifiant, nom: &str) -> asl_registre::Service {
    asl_registre::Service {
        provenance: Provenance::Ici,
        machine,
        nom: NomRange::nouveau(nom).expect("il tient"),
    }
}

#[test]
fn les_machines_d_un_compte_se_retrouvent_sans_balayer_l_annuaire() {
    // **L'INDEX EXISTE POUR CELA.** `MACHINES` porte le propriétaire à
    // l'intérieur : sans index, répondre demanderait de balayer toutes les
    // machines de l'annuaire, quand la réponse ne dépend que d'un compte.
    let (entrepot, chemin) = entrepot("machines-de-compte");
    let moi = un(Genre::Utilisateur, 1);
    let autre = un(Genre::Utilisateur, 2);

    for (marque, proprietaire) in [(10, moi), (11, moi), (12, autre)] {
        let quelle = un(Genre::Machine, marque);
        entrepot
            .poser_machine(quelle, &une_machine(proprietaire, "grenier"))
            .expect("elle s'écrit");
    }

    let miennes = entrepot.machines_de_compte(moi).expect("elles se lisent");
    assert_eq!(miennes.len(), 2);
    for (_, machine) in &miennes {
        assert_eq!(
            machine.proprietaire, moi,
            "une machine d'un autre est sortie"
        );
    }

    assert_eq!(
        entrepot
            .machines_de_compte(autre)
            .expect("elles se lisent")
            .len(),
        1
    );
    assert!(
        entrepot
            .machines_de_compte(un(Genre::Utilisateur, 3))
            .expect("elles se lisent")
            .is_empty(),
        "un compte sans machine rend une liste vide, et non une faute"
    );

    let _ = std::fs::remove_file(chemin);
}

#[test]
fn les_services_d_une_machine_se_retrouvent_par_intervalle() {
    // `SERVICES_PAR_NOM` range la machine en tête PRÉCISÉMENT pour que « tous
    // les services de cette machine » soit un intervalle et non un balayage.
    let (entrepot, chemin) = entrepot("services-de-machine");
    let une = un(Genre::Machine, 10);
    let autre = un(Genre::Machine, 11);

    for (marque, machine, nom) in [(20, une, "depot"), (21, une, "imap"), (22, autre, "depot")] {
        entrepot
            .poser_service(un(Genre::Service, marque), &un_service(machine, nom))
            .expect("il s'écrit");
    }

    let siens = entrepot.services_de_machine(une).expect("ils se lisent");
    assert_eq!(siens.len(), 2);
    for (_, service) in &siens {
        assert_eq!(
            service.machine, une,
            "un service d'une autre machine est sorti"
        );
    }
    assert_eq!(
        entrepot
            .services_de_machine(autre)
            .expect("ils se lisent")
            .len(),
        1
    );

    let _ = std::fs::remove_file(chemin);
}

#[test]
fn un_service_renomme_ne_sort_qu_une_fois() {
    // L'index suit le service, comme l'alias suit le compte : sans cela, un
    // service renommé sortirait deux fois de sa propre machine.
    let (entrepot, chemin) = entrepot("service-renomme");
    let machine = un(Genre::Machine, 10);
    let quel = un(Genre::Service, 20);

    entrepot
        .poser_service(quel, &un_service(machine, "depot"))
        .expect("il s'écrit");
    entrepot
        .poser_service(quel, &un_service(machine, "archives"))
        .expect("il se renomme");

    let siens = entrepot
        .services_de_machine(machine)
        .expect("ils se lisent");
    assert_eq!(siens.len(), 1, "l'ancien nom est resté dans l'index");
    assert_eq!(siens[0].1.nom.octets(), b"archives");

    let _ = std::fs::remove_file(chemin);
}

#[test]
fn les_autorisations_sortent_dans_les_deux_sens_avec_leur_identifiant() {
    // **C'EST L'IDENTIFIANT QU'ON PASSE À `DELETE /v1/autorisations/{g}`.** Une
    // liste dont les éléments ne se désignent pas est une liste qu'on ne peut
    // que regarder.
    let (entrepot, chemin) = entrepot("autorisations-deux-sens");
    let moi = un(Genre::Utilisateur, 1);
    let autre = un(Genre::Utilisateur, 2);

    let accordee = un(Genre::Autorisation, 30);
    let recue = un(Genre::Autorisation, 31);
    let ailleurs = un(Genre::Autorisation, 32);

    for (quelle, par, a) in [
        (accordee, moi, autre),
        (recue, autre, moi),
        (ailleurs, autre, autre),
    ] {
        entrepot
            .poser_autorisation(
                quelle,
                &asl_registre::Autorisation {
                    provenance: Provenance::Ici,
                    par,
                    a,
                    portee: asl_registre::Portee::ToutLeCompte,
                    revoquee: false,
                },
            )
            .expect("elle s'écrit");
    }

    let miennes = entrepot
        .autorisations_accordees(moi)
        .expect("elles se lisent");
    assert_eq!(miennes.len(), 1);
    assert_eq!(
        miennes[0].0, accordee,
        "l'identifiant doit sortir avec elle"
    );
    assert_eq!(miennes[0].1.a, autre);

    let vers_moi = entrepot
        .autorisations_recues_nommees(moi)
        .expect("elles se lisent");
    assert_eq!(vers_moi.len(), 1);
    assert_eq!(vers_moi[0].0, recue);

    // Et les deux sens ne se mélangent pas.
    assert_eq!(
        entrepot
            .autorisations_accordees(autre)
            .expect("elles se lisent")
            .len(),
        2
    );

    let _ = std::fs::remove_file(chemin);
}

#[test]
fn une_autorisation_revoquee_reste_dans_la_liste() {
    // **L'ÉCRAN QU'ON REGARDE APRÈS AVOIR RETIRÉ UN ACCÈS DOIT MONTRER CE QU'ON
    // A RETIRÉ.** La filtrer ici la rendrait invisible à l'application qui vient
    // de la retirer.
    let (entrepot, chemin) = entrepot("autorisation-revoquee");
    let moi = un(Genre::Utilisateur, 1);
    let autre = un(Genre::Utilisateur, 2);
    let quelle = un(Genre::Autorisation, 30);

    entrepot
        .poser_autorisation(
            quelle,
            &asl_registre::Autorisation {
                provenance: Provenance::Ici,
                par: moi,
                a: autre,
                portee: asl_registre::Portee::ToutLeCompte,
                revoquee: false,
            },
        )
        .expect("elle s'écrit");
    entrepot
        .revoquer_autorisation(quelle)
        .expect("elle se révoque");

    let miennes = entrepot
        .autorisations_accordees(moi)
        .expect("elles se lisent");
    assert_eq!(miennes.len(), 1, "une révoquée disparue de la liste");
    assert!(miennes[0].1.revoquee, "et elle doit être marquée");

    let _ = std::fs::remove_file(chemin);
}
