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
use asl_registre::{AliasRange, Compte, EntreeJournal, Machine, NomRange, Provenance, Verdict};
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
        cle: [0x42; 32],
        annonce: true,
        lecture: false,
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
            cle: [1; 32],
            annonce: true,
            lecture: true,
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
