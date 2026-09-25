//! L'entrepôt, sur de vrais fichiers.
//!
//! # POURQUOI DES ESSAIS D'INTÉGRATION, ET NON DES ESSAIS UNITAIRES
//!
//! Ce qu'on veut éprouver ici n'est pas une fonction, c'est **ce qui reste vrai
//! après une écriture** : l'index d'alias d'accord avec son compte, une entrée
//! de journal qui survit à sa transaction, une rupture de confiance qui n'efface
//! pas plus qu'elle ne doit, une estampille par écriture et une opération par
//! estampille. Rien de cela n'a de sens sans un vrai fichier.

use std::path::PathBuf;

use asl_id::{Genre, Identifiant};
use asl_registre::{
    AliasRange, Attestation, Cadre, Capacites, Cause, Compte, Effacement, EntreeJournal,
    Estampille, JetonRange, NomRange, Operation, Plateforme, PointRange, Portee, Provenance,
    Systeme, Verdict,
};
use asl_store::{Efface, Entrepot, Faute, RACINE_SANS_IDENTITE, Rattrapage, Retrait};

/// La racine pour laquelle les essais écrivent.
fn racine() -> Identifiant {
    Identifiant::depuis_entropie(Genre::Annuaire, [0xEE; 16])
}

/// Une date de révocation, en millisecondes d'époque.
const REVOQUE_LE: u64 = 1_789_000_000_000;

/// Un entrepôt neuf, dans un fichier à nous.
///
/// **LE NOM DU FICHIER EST LA CLÉ D'UNICITÉ**, et non le nom de l'essai :
/// `cargo test` les fait tourner en parallèle, et deux essais qui ouvriraient
/// le même fichier se verraient refuser par redb.
fn entrepot(quoi: &str) -> (Entrepot, PathBuf) {
    let chemin =
        std::env::temp_dir().join(format!("asl-entrepot-{}-{quoi}.redb", std::process::id()));
    let _ = std::fs::remove_file(&chemin);
    let ouvert = Entrepot::ouvrir(&chemin, racine()).expect("un entrepôt neuf");
    (ouvert, chemin)
}

/// Un identifiant de ce genre, reproductible.
fn un(genre: Genre, graine: u8) -> Identifiant {
    Identifiant::depuis_entropie(genre, [graine; 16])
}

/// Un alias.
fn alias(texte: &str) -> AliasRange {
    AliasRange::nouveau(texte).expect("il tient")
}

/// Un nom, de machine ou de service.
fn nom(texte: &str) -> NomRange {
    NomRange::nouveau(texte).expect("un nom court se range")
}

/// Les deux capacités.
const TOUT: Capacites = Capacites {
    annonce: true,
    lecture: true,
};

/// L'estampille de cette racine-ci, à ce compteur.
fn e(compteur: u64) -> Estampille {
    Estampille {
        compteur,
        racine: racine(),
    }
}

/// L'empreinte de ce code.
fn empreinte(texte: &str) -> [u8; 32] {
    asl_cle::CodeEnrolement::analyser(texte)
        .expect("un code")
        .empreinte()
}

/// Les opérations du journal, relues, avec leur estampille.
fn operations(base: &Entrepot, apres: u64) -> Vec<(Estampille, Operation)> {
    match base.operations_apres(apres).expect("lisible") {
        Rattrapage::Operations(cadres) => cadres
            .iter()
            .map(|cadre| {
                let (estampille, operation, combien) =
                    Operation::lire(cadre).expect("un cadre du journal se relit");
                assert_eq!(
                    combien,
                    cadre.len(),
                    "un cadre porte exactement son opération"
                );
                (estampille, operation)
            })
            .collect(),
        hors => panic!("le journal ne remonte pas jusqu'à {apres} : {hors:?}"),
    }
}

// ── L'ouverture ─────────────────────────────────────────────────────────────

#[test]
fn une_base_neuve_rend_rien_et_non_une_erreur() {
    // **LES TABLES SONT CRÉÉES À L'OUVERTURE.** Si elles naissaient à la
    // première écriture, cette lecture-ci échouerait avec « table inexistante »
    // — une base neuve rendrait une erreur là où elle doit rendre « rien ».
    let (base, chemin) = entrepot("neuve");
    assert_eq!(base.racine(), racine());
    assert_eq!(base.compteur().expect("lisible"), 0);
    assert_eq!(
        base.compte(un(Genre::Utilisateur, 1)).expect("lisible"),
        None
    );
    assert_eq!(base.machine(un(Genre::Machine, 1)).expect("lisible"), None);
    assert_eq!(base.compte_par_alias("personne").expect("lisible"), None);
    assert_eq!(base.entrees_du_journal().expect("lisible"), 0);
    assert_eq!(base.operations_gardees().expect("lisible"), 0);
    assert_eq!(base.curseur(un(Genre::Annuaire, 2)).expect("lisible"), 0);
    // Et son journal d'opérations remonte jusqu'au début : rien n'a été
    // retiré, il n'y a rien.
    assert_eq!(
        base.operations_apres(0).expect("lisible"),
        Rattrapage::Operations(Vec::new())
    );
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn ce_qui_est_ecrit_survit_a_la_fermeture() {
    let chemin =
        std::env::temp_dir().join(format!("asl-entrepot-{}-survie.redb", std::process::id()));
    let _ = std::fs::remove_file(&chemin);
    let qui = un(Genre::Utilisateur, 4);

    {
        let base = Entrepot::ouvrir(&chemin, racine()).expect("un entrepôt");
        base.creer_compte(qui, Provenance::Ici, Some(alias("thierry")))
            .expect("écrit");
    }
    {
        let base = Entrepot::ouvrir(&chemin, racine()).expect("le même entrepôt");
        assert_eq!(
            base.compte(qui).expect("lisible"),
            Some(Compte {
                provenance: Provenance::Ici,
                estampille: e(1),
                alias: Some(alias("thierry")),
                reclamation: e(1),
                efface: None,
            })
        );
        assert_eq!(
            base.compte_par_alias("thierry").expect("lisible"),
            Some(qui)
        );
        // **LE COMPTEUR SURVIT AUSSI** : c'est lui qui rend les estampilles
        // strictement croissantes d'un démarrage à l'autre.
        assert_eq!(base.compteur().expect("lisible"), 1);
        assert_eq!(base.operations_gardees().expect("lisible"), 1);
    }
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn une_base_d_un_format_futur_est_refusee() {
    // **UNE VERSION FUTURE RELUE PAR UNE VERSION ANCIENNE** : le cas qui
    // arrive à chaque retour arrière de déploiement. On refuse plutôt que de
    // relire de travers.
    let chemin =
        std::env::temp_dir().join(format!("asl-entrepot-{}-futur.redb", std::process::id()));
    let _ = std::fs::remove_file(&chemin);
    {
        let base = redb::Database::create(&chemin).expect("une base");
        let ecriture = base.begin_write().expect("une transaction");
        {
            let mut table = ecriture
                .open_table(redb::TableDefinition::<&str, u64>::new("racine"))
                .expect("la table");
            table.insert("format", 99).expect("écrit");
        }
        ecriture.commit().expect("commis");
    }
    let refus = Entrepot::ouvrir(&chemin, racine()).err();
    assert!(matches!(refus, Some(Faute::Format { lu: 99 })), "{refus:?}");
    let _ = std::fs::remove_file(&chemin);
}

// ── L'estampille et le journal d'opérations ─────────────────────────────────

#[test]
fn chaque_ecriture_avance_le_compteur_et_laisse_une_operation() {
    // **C'EST `replication.md` §4 ET §5.1** : le compteur avance de un à
    // chaque écriture locale, l'enregistrement porte l'estampille, et le
    // journal porte l'opération — dans la même transaction.
    let (base, chemin) = entrepot("estampilles");
    let thierry = un(Genre::Utilisateur, 1);
    let grenier = un(Genre::Machine, 2);
    let iphone = un(Genre::Appareil, 3);
    let depot = un(Genre::Service, 4);
    let accordee = un(Genre::Autorisation, 5);
    let code = empreinte("4K9M2P7R1T");

    base.creer_compte(thierry, Provenance::Ici, None)
        .expect("1");
    base.reclamer_alias(thierry, Some(alias("thierry")))
        .expect("2");
    base.creer_appareil(
        iphone,
        Provenance::Ici,
        thierry,
        [7; 33],
        Attestation::Apple,
    )
    .expect("3");
    base.poser_description(iphone, Provenance::Ici, Systeme::Ios, nom("iPhone 17"))
        .expect("4");
    base.poser_jeton(
        iphone,
        Provenance::Ici,
        Plateforme::Apns,
        JetonRange::nouveau("c0ffee").expect("il tient"),
    )
    .expect("5");
    base.creer_machine(grenier, Provenance::Ici, thierry, nom("grenier"), TOUT)
        .expect("6");
    base.modifier_machine(grenier, Some(nom("cave")), None)
        .expect("7");
    base.emettre_enrolement(&code, Provenance::Ici, grenier, 10_000)
        .expect("8");
    let enrolement = base
        .consommer_enrolement(&code)
        .expect("lisible")
        .expect("le code");
    base.lier_cle(grenier, [0x42; 32], code, enrolement.estampille)
        .expect("9");
    base.declarer_service(depot, Provenance::Ici, grenier, nom("depot"))
        .expect("10");
    base.accorder_autorisation(
        accordee,
        Provenance::Ici,
        thierry,
        un(Genre::Utilisateur, 6),
        Portee::UneMachine(grenier),
        nom("le grenier"),
    )
    .expect("11");
    base.revoquer_autorisation(accordee).expect("12");
    base.revoquer_cle(grenier).expect("13");
    base.revoquer_appareil(iphone, REVOQUE_LE).expect("14");

    assert_eq!(base.compteur().expect("lisible"), 14);
    let journal = operations(&base, 0);
    assert_eq!(journal.len(), 14);
    for (rang, (estampille, _)) in journal.iter().enumerate() {
        assert_eq!(*estampille, e(u64::try_from(rang).expect("petit") + 1));
    }
    // Un genre par verbe, dans l'ordre des verbes.
    let genres: Vec<_> = journal
        .iter()
        .map(|(_, operation)| operation.genre())
        .collect();
    use asl_registre::GenreOperation as G;
    assert_eq!(
        genres,
        [
            G::Compte,
            G::Alias,
            G::Appareil,
            G::Description,
            G::Poussee,
            G::Machine,
            G::MachineModifiee,
            G::Enrolement,
            G::CleMachine,
            G::Service,
            G::Autorisation,
            G::AutorisationRevoquee,
            G::CleMachineRevoquee,
            G::AppareilRevoque,
        ]
    );

    // Et les enregistrements portent l'estampille de leur dernière écriture.
    let compte = base.compte(thierry).expect("lisible").expect("il est là");
    assert_eq!(compte.estampille, e(2));
    assert_eq!(compte.reclamation, e(2));
    let machine = base
        .machine(grenier)
        .expect("lisible")
        .expect("elle est là");
    assert_eq!(machine.estampille, e(13), "la révocation de la clé");
    assert_eq!(machine.nom_estampille, e(7), "le renommage");
    assert_eq!(
        machine.capacites_estampille,
        e(6),
        "jamais changées : la création"
    );
    assert!(machine.cle.is_none());
    let appareil = base.appareil(iphone).expect("lisible").expect("il est là");
    assert_eq!(appareil.estampille, e(14));
    assert!(appareil.revoque());
    assert_eq!(
        base.autorisation(accordee)
            .expect("lisible")
            .map(|quoi| quoi.estampille),
        Some(e(12))
    );
    assert_eq!(
        base.service(depot)
            .expect("lisible")
            .map(|quoi| quoi.estampille),
        Some(e(10))
    );

    // Le rattrapage rend ce qui suit un compteur, et rien avant.
    assert_eq!(operations(&base, 12).len(), 2);
    assert_eq!(operations(&base, 14).len(), 0);
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn la_cle_liee_porte_l_estampille_d_emission_de_son_code() {
    // **C'EST LA RÈGLE DE `replication.md` §3.2** : la liaison qui gagne est
    // celle du code le plus récemment émis, puis la première consommation.
    // Pour la calculer, la clé porte les deux.
    let (base, chemin) = entrepot("cle-liee");
    let grenier = un(Genre::Machine, 2);
    let code = empreinte("4K9M2P7R1T");
    base.creer_machine(
        grenier,
        Provenance::Ici,
        un(Genre::Utilisateur, 1),
        nom("grenier"),
        TOUT,
    )
    .expect("1");
    base.emettre_enrolement(&code, Provenance::Ici, grenier, 10_000)
        .expect("2");
    let enrolement = base
        .consommer_enrolement(&code)
        .expect("lisible")
        .expect("le code");
    assert_eq!(enrolement.estampille, e(2));

    let avant = base
        .lier_cle(grenier, [0x42; 32], code, enrolement.estampille)
        .expect("3")
        .expect("la machine");
    assert!(avant.cle.is_none(), "ce qu'elle ÉTAIT");
    let liee = base
        .machine(grenier)
        .expect("lisible")
        .expect("elle est là")
        .cle
        .expect("liée");
    assert_eq!(liee.cle, [0x42; 32]);
    assert_eq!(liee.liaison, e(3));
    assert_eq!(liee.code, e(2));

    // L'opération porte l'empreinte, pour que l'autre racine retire le code,
    // et l'estampille d'émission.
    let (_, operation) = operations(&base, 2).remove(0);
    assert_eq!(
        operation,
        Operation::CleMachine {
            machine: grenier,
            cle: [0x42; 32],
            empreinte: code,
            code: e(2),
        }
    );

    // Lier une machine inconnue ne crée rien.
    assert_eq!(
        base.lier_cle(un(Genre::Machine, 9), [1; 32], code, e(2))
            .expect("lisible"),
        None
    );
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn revoquer_une_cle_absente_ne_laisse_aucune_operation() {
    // Sans clé, il n'y a rien à retirer : ni écriture, ni opération.
    let (base, chemin) = entrepot("cle-absente");
    let grenier = un(Genre::Machine, 2);
    base.creer_machine(
        grenier,
        Provenance::Ici,
        un(Genre::Utilisateur, 1),
        nom("grenier"),
        TOUT,
    )
    .expect("1");
    assert!(base.revoquer_cle(grenier).expect("lisible").is_some());
    assert_eq!(base.compteur().expect("lisible"), 1);
    assert_eq!(base.operations_gardees().expect("lisible"), 1);
    assert_eq!(
        base.revoquer_cle(un(Genre::Machine, 9)).expect("lisible"),
        None
    );
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn un_patch_estampille_champ_par_champ() {
    // **UNE RÈGLE PAR ENREGISTREMENT FERAIT PERDRE UN NOM PARCE QU'UNE
    // CAPACITÉ A GAGNÉ** (`replication.md` §3.2) : le nom a son estampille,
    // les capacités ont la leur.
    let (base, chemin) = entrepot("patch");
    let grenier = un(Genre::Machine, 2);
    base.creer_machine(
        grenier,
        Provenance::Ici,
        un(Genre::Utilisateur, 1),
        nom("grenier"),
        TOUT,
    )
    .expect("1");

    let avant = base
        .modifier_machine(
            grenier,
            None,
            Some(Capacites {
                annonce: false,
                lecture: true,
            }),
        )
        .expect("2")
        .expect("la machine");
    assert!(avant.annonce, "ce qu'elle ÉTAIT");
    let apres = base
        .machine(grenier)
        .expect("lisible")
        .expect("elle est là");
    assert!(!apres.annonce);
    assert_eq!(apres.capacites_estampille, e(2));
    assert_eq!(apres.nom_estampille, e(1), "le nom n'a pas bougé");
    assert_eq!(apres.estampille, e(2));

    base.modifier_machine(grenier, Some(nom("cave")), None)
        .expect("3");
    let apres = base
        .machine(grenier)
        .expect("lisible")
        .expect("elle est là");
    assert_eq!(apres.nom.octets(), b"cave");
    assert_eq!(apres.nom_estampille, e(3));
    assert_eq!(
        apres.capacites_estampille,
        e(2),
        "les capacités n'ont pas bougé"
    );

    // Rien de donné : rien d'écrit, pas d'opération, et la machine rendue.
    assert!(
        base.modifier_machine(grenier, None, None)
            .expect("4")
            .is_some()
    );
    assert_eq!(base.compteur().expect("lisible"), 3);
    assert_eq!(
        base.modifier_machine(un(Genre::Machine, 9), Some(nom("x")), None)
            .expect("lisible"),
        None
    );

    let journal = operations(&base, 1);
    assert_eq!(
        journal[0].1,
        Operation::MachineModifiee {
            machine: grenier,
            nom: None,
            capacites: Some(Capacites {
                annonce: false,
                lecture: true
            }),
        }
    );
    assert_eq!(
        journal[1].1,
        Operation::MachineModifiee {
            machine: grenier,
            nom: Some(nom("cave")),
            capacites: None,
        }
    );
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn ce_qui_ne_vient_pas_d_ici_n_entre_pas_dans_le_journal_d_operations() {
    // **C11, ENTRE RACINES** (`replication.md` §7) : la voie ne transporte que
    // des enregistrements de provenance locale. Ce qu'on a reçu d'un annuaire
    // rattaché est estampillé — c'est une écriture — mais pas journalisé.
    let (base, chemin) = entrepot("provenance");
    let pair = Provenance::Annuaire(un(Genre::Annuaire, 1));
    base.creer_compte(un(Genre::Utilisateur, 1), pair, None)
        .expect("1");
    base.creer_compte(un(Genre::Utilisateur, 2), Provenance::Ici, None)
        .expect("2");
    assert_eq!(base.compteur().expect("lisible"), 2);
    let journal = operations(&base, 0);
    assert_eq!(journal.len(), 1);
    assert_eq!(journal[0].0, e(2));
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn le_compteur_se_hisse_au_dessus_de_ce_qu_on_recoit_et_ne_recule_jamais() {
    // **L'HORLOGE DE LAMPORT** (`replication.md` §4) : `max(compteur, h)`.
    let (base, chemin) = entrepot("hisser");
    base.creer_compte(un(Genre::Utilisateur, 1), Provenance::Ici, None)
        .expect("1");
    base.hisser_le_compteur(4_812).expect("hissé");
    assert_eq!(base.compteur().expect("lisible"), 4_812);
    base.hisser_le_compteur(12).expect("ignoré");
    assert_eq!(base.compteur().expect("lisible"), 4_812, "il ne recule pas");
    // Et la prochaine écriture locale est au-dessus.
    base.creer_compte(un(Genre::Utilisateur, 2), Provenance::Ici, None)
        .expect("4813");
    assert_eq!(
        base.compte(un(Genre::Utilisateur, 2))
            .expect("lisible")
            .map(|quoi| quoi.estampille),
        Some(e(4_813))
    );
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn le_journal_d_operations_s_expire_et_dit_jusqu_ou() {
    // **TRENTE JOURS** (`replication.md` §5.4) : ce qui est retiré ne se
    // rattrape plus, et le rattrapage le dit — c'est le `410`.
    let (base, chemin) = entrepot("retention");
    for graine in 1..=3 {
        base.creer_compte(un(Genre::Utilisateur, graine), Provenance::Ici, None)
            .expect("écrit");
    }
    // Rien avant l'époque : rien n'expire.
    assert_eq!(base.expirer_les_operations(0).expect("expiré"), 0);
    assert_eq!(base.operations_gardees().expect("lisible"), 3);

    // Tout ce qui précède demain : tout expire, et le journal ne remonte plus
    // jusqu'à zéro — mais bien jusqu'au dernier retiré.
    assert_eq!(base.expirer_les_operations(u64::MAX).expect("expiré"), 3);
    assert_eq!(base.operations_gardees().expect("lisible"), 0);
    assert_eq!(
        base.operations_apres(0).expect("lisible"),
        Rattrapage::HorsJournal {
            retirees_jusqu_a: 3
        }
    );
    assert_eq!(
        base.operations_apres(2).expect("lisible"),
        Rattrapage::HorsJournal {
            retirees_jusqu_a: 3
        }
    );
    assert_eq!(
        base.operations_apres(3).expect("lisible"),
        Rattrapage::Operations(Vec::new())
    );
    // Ce qui s'écrit ensuite se rattrape depuis là.
    base.creer_compte(un(Genre::Utilisateur, 4), Provenance::Ici, None)
        .expect("écrit");
    assert_eq!(operations(&base, 3).len(), 1);
    assert_eq!(
        asl_store::RETENTION_DES_OPERATIONS_MS,
        30 * 24 * 60 * 60 * 1_000
    );
    let _ = std::fs::remove_file(&chemin);
}

/// Les cadres d'un instantané, relus.
fn instantane(base: &Entrepot) -> Vec<Cadre> {
    base.instantane()
        .expect("lisible")
        .iter()
        .map(|cadre| {
            let (lu, combien) = Cadre::lire(cadre).expect("un cadre d'instantané se relit");
            assert_eq!(
                combien,
                cadre.len(),
                "un cadre porte exactement son contenu"
            );
            lu
        })
        .collect()
}

#[test]
fn l_instantane_reconstitue_chaque_enregistrement_sous_ses_estampilles_d_origine() {
    // **C'EST `replication.md` §5.4** : l'état entier, en suite d'opérations,
    // avec les estampilles de l'écriture d'origine — champ par champ là où la
    // règle de conflit est champ par champ —, puis le cadre de fin.
    let (base, chemin) = entrepot("instantane");
    let thierry = un(Genre::Utilisateur, 1);
    let grenier = un(Genre::Machine, 2);
    let iphone = un(Genre::Appareil, 3);
    let depot = un(Genre::Service, 4);
    let accordee = un(Genre::Autorisation, 5);
    let code = empreinte("4K9M2P7R1T");
    let en_attente = empreinte("ABCDEFGH23");

    base.creer_compte(thierry, Provenance::Ici, None)
        .expect("1");
    base.reclamer_alias(thierry, Some(alias("thierry")))
        .expect("2");
    base.creer_appareil(
        iphone,
        Provenance::Ici,
        thierry,
        [7; 33],
        Attestation::Apple,
    )
    .expect("3");
    base.poser_description(iphone, Provenance::Ici, Systeme::Ios, nom("iPhone 17"))
        .expect("4");
    base.poser_jeton(
        iphone,
        Provenance::Ici,
        Plateforme::Apns,
        JetonRange::nouveau("c0ffee").expect("il tient"),
    )
    .expect("5");
    base.creer_machine(grenier, Provenance::Ici, thierry, nom("grenier"), TOUT)
        .expect("6");
    base.modifier_machine(grenier, Some(nom("cave")), None)
        .expect("7");
    base.emettre_enrolement(&code, Provenance::Ici, grenier, 10_000)
        .expect("8");
    let enrolement = base
        .consommer_enrolement(&code)
        .expect("lisible")
        .expect("le code");
    base.lier_cle(grenier, [0x42; 32], code, enrolement.estampille)
        .expect("9");
    base.declarer_service(depot, Provenance::Ici, grenier, nom("depot"))
        .expect("10");
    base.accorder_autorisation(
        accordee,
        Provenance::Ici,
        thierry,
        un(Genre::Utilisateur, 6),
        Portee::UneMachine(grenier),
        nom("le grenier"),
    )
    .expect("11");
    base.revoquer_autorisation(accordee).expect("12");
    base.revoquer_appareil(iphone, REVOQUE_LE).expect("13");
    base.emettre_enrolement(&en_attente, Provenance::Ici, grenier, 20_000)
        .expect("14");
    // **CE QUI NE VIENT PAS D'ICI NE SORT PAS** (C11) : une écriture de
    // provenance distante est estampillée — c'est une écriture —, mais elle
    // n'entre ni dans le journal, ni dans l'instantané.
    base.creer_compte(
        un(Genre::Utilisateur, 9),
        Provenance::Annuaire(un(Genre::Annuaire, 1)),
        None,
    )
    .expect("15");
    assert_eq!(base.compteur().expect("lisible"), 15);

    let cadres = instantane(&base);
    let (fin, operations) = cadres.split_last().expect("au moins la fin");
    assert_eq!(*fin, Cadre::Fin { coupe: e(15) }, "le compteur de coupe");
    assert!(
        operations
            .iter()
            .all(|cadre| matches!(cadre, Cadre::Operation { .. })),
        "un seul cadre de fin, en dernier"
    );
    let operations: Vec<(Estampille, Operation)> = operations
        .iter()
        .map(|cadre| match cadre {
            Cadre::Operation {
                estampille,
                operation,
            } => (*estampille, *operation),
            Cadre::Fin { .. } => unreachable!(),
        })
        .collect();

    // Le compte : l'enregistrement, puis sa réclamation courante.
    let compte = base.compte(thierry).expect("lisible").expect("il est là");
    assert_eq!(
        &operations[..2],
        [
            (
                e(2),
                Operation::Compte {
                    compte: thierry,
                    enregistrement: compte,
                },
            ),
            (
                e(2),
                Operation::Alias {
                    compte: thierry,
                    alias: Some(alias("thierry")),
                },
            ),
        ]
    );

    // La machine : sans clé, puis le nom sous SON estampille, les capacités
    // sous la leur, et la clé sous celle de la liaison — l'empreinte du code
    // consommé est nulle, il n'existe plus.
    let machine = base
        .machine(grenier)
        .expect("lisible")
        .expect("elle est là");
    assert_eq!(
        &operations[2..6],
        [
            (
                e(9),
                Operation::Machine {
                    machine: grenier,
                    enregistrement: asl_registre::Machine {
                        cle: None,
                        ..machine
                    },
                },
            ),
            (
                e(7),
                Operation::MachineModifiee {
                    machine: grenier,
                    nom: Some(nom("cave")),
                    capacites: None,
                },
            ),
            (
                e(6),
                Operation::MachineModifiee {
                    machine: grenier,
                    nom: None,
                    capacites: Some(TOUT),
                },
            ),
            (
                e(9),
                Operation::CleMachine {
                    machine: grenier,
                    cle: [0x42; 32],
                    empreinte: [0; 32],
                    code: e(8),
                },
            ),
        ]
    );

    // L'appareil révoqué : l'enregistrement, puis la révocation, puis son
    // attestation — elle voyage à part, parce que l'autre racine le tient
    // peut-être `attendue` ; puis ce qu'il dit de lui. Le jeton est parti
    // avec la révocation.
    let appareil = base.appareil(iphone).expect("lisible").expect("il est là");
    assert!(appareil.revoque());
    assert_eq!(
        &operations[6..10],
        [
            (
                e(13),
                Operation::Appareil {
                    appareil: iphone,
                    enregistrement: appareil,
                },
            ),
            (
                e(13),
                Operation::AppareilRevoque {
                    appareil: iphone,
                    revoque_le: REVOQUE_LE,
                },
            ),
            (
                e(13),
                Operation::AppareilAtteste {
                    appareil: iphone,
                    atteste: Attestation::Apple,
                },
            ),
            (
                e(4),
                Operation::Description {
                    appareil: iphone,
                    enregistrement: base
                        .description(iphone)
                        .expect("lisible")
                        .expect("elle est là"),
                },
            ),
        ]
    );
    assert!(
        !operations
            .iter()
            .any(|(_, operation)| matches!(operation, Operation::Poussee { .. })),
        "le jeton est parti avec l'appareil"
    );

    // Le code en attente, le service, l'autorisation révoquée.
    assert_eq!(
        &operations[10..],
        [
            (
                e(14),
                Operation::Enrolement {
                    empreinte: en_attente,
                    enregistrement: asl_registre::Enrolement {
                        provenance: Provenance::Ici,
                        estampille: e(14),
                        machine: grenier,
                        expire_a: 20_000,
                    },
                },
            ),
            (
                e(10),
                Operation::Service {
                    service: depot,
                    enregistrement: base.service(depot).expect("lisible").expect("il est là"),
                },
            ),
            (
                e(12),
                Operation::Autorisation {
                    autorisation: accordee,
                    enregistrement: base
                        .autorisation(accordee)
                        .expect("lisible")
                        .expect("elle est là"),
                },
            ),
            (
                e(12),
                Operation::AutorisationRevoquee {
                    autorisation: accordee,
                },
            ),
        ]
    );
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn un_entrepot_vide_a_un_instantane_qui_ne_porte_que_sa_fin() {
    let (base, chemin) = entrepot("instantane-vide");
    assert_eq!(instantane(&base), [Cadre::Fin { coupe: e(0) }]);

    // Une machine dont le nom et les capacités ont la même estampille — celle
    // de sa création — sort en UNE opération de modification, pas deux.
    let grenier = un(Genre::Machine, 2);
    base.creer_machine(
        grenier,
        Provenance::Ici,
        un(Genre::Utilisateur, 1),
        nom("grenier"),
        TOUT,
    )
    .expect("écrite");
    let cadres = instantane(&base);
    assert_eq!(cadres.len(), 3, "la machine, sa modification, la fin");
    assert_eq!(
        cadres[1],
        Cadre::Operation {
            estampille: e(1),
            operation: Operation::MachineModifiee {
                machine: grenier,
                nom: Some(nom("grenier")),
                capacites: Some(TOUT),
            },
        }
    );
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn la_derniere_operation_previent_sans_transaction_et_apres_le_commit() {
    // **C'EST CE QUE LA VOIE COMPARE À SON CURSEUR** à chaque tour : un entier
    // en mémoire, qui ne bouge que sur les écritures journalisées.
    let (base, chemin) = entrepot("derniere-operation");
    assert_eq!(base.derniere_operation(), 0);
    base.creer_compte(un(Genre::Utilisateur, 1), Provenance::Ici, None)
        .expect("1");
    assert_eq!(base.derniere_operation(), 1);

    // Une écriture qui n'ajoute pas d'opération ne prévient pas : hisser le
    // compteur, journaliser une requête, poser un curseur.
    base.hisser_le_compteur(100).expect("hissé");
    base.poser_curseur(un(Genre::Annuaire, 2), 50)
        .expect("posé");
    base.journaliser(&EntreeJournal {
        quand: 1,
        demandeur: un(Genre::Machine, 1),
        visee: un(Genre::Machine, 2),
        service: nom("depot"),
        verdict: Verdict::Servi,
        provenance: Provenance::Ici,
    })
    .expect("journalisé");
    assert_eq!(base.derniere_operation(), 1);
    assert_eq!(base.compteur().expect("lisible"), 100);

    // Une écriture de provenance distante avance le compteur, mais n'est pas
    // journalisée : elle ne prévient pas non plus.
    base.creer_compte(
        un(Genre::Utilisateur, 2),
        Provenance::Annuaire(un(Genre::Annuaire, 1)),
        None,
    )
    .expect("101");
    assert_eq!(base.derniere_operation(), 1);
    // La suivante, locale, est journalisée sous 102 : c'est ce qu'on lit.
    base.creer_compte(un(Genre::Utilisateur, 3), Provenance::Ici, None)
        .expect("102");
    assert_eq!(base.derniere_operation(), 102);
    assert_eq!(operations(&base, 1).len(), 1);

    // Et à la réouverture, elle repart du compteur : un majorant, jamais un
    // retard — un lecteur qui compare relit au pire une fois pour rien.
    drop(base);
    let base = Entrepot::ouvrir(&chemin, racine()).expect("rouvert");
    assert_eq!(base.derniere_operation(), 102);
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn le_curseur_d_un_pair_avance_et_ne_recule_pas() {
    // « Le tireur refuse ce qui recule » (`replication.md` §5.3).
    let (base, chemin) = entrepot("curseur");
    let argon = un(Genre::Annuaire, 2);
    let autre = un(Genre::Annuaire, 3);
    assert_eq!(base.curseur(argon).expect("lisible"), 0);
    base.poser_curseur(argon, 4_790).expect("posé");
    assert_eq!(base.curseur(argon).expect("lisible"), 4_790);
    base.poser_curseur(argon, 4_000).expect("ignoré");
    assert_eq!(
        base.curseur(argon).expect("lisible"),
        4_790,
        "il ne recule pas"
    );
    base.poser_curseur(argon, 4_812).expect("posé");
    assert_eq!(base.curseur(argon).expect("lisible"), 4_812);
    assert_eq!(
        base.curseur(autre).expect("lisible"),
        0,
        "un curseur PAR pair"
    );
    let _ = std::fs::remove_file(&chemin);
}

// ── La reprise d'une base ancienne (`replication.md` §11.4) ─────────────────

/// Une copie de la base écrite par 0.4.3, avant l'estampille.
///
/// **LA FIXTURE A ÉTÉ ÉCRITE PAR LE CODE D'AVANT**, avec ses fonctions
/// `poser_*`, puis compactée — et non fabriquée par le code d'aujourd'hui, qui
/// ne sait plus écrire cette forme. C'est ce qui fait de cet essai une preuve :
/// ce que les bancs portent est ce que ce fichier porte.
fn base_ancienne(quoi: &str) -> PathBuf {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/entrepot-0.4.3.redb");
    let copie =
        std::env::temp_dir().join(format!("asl-entrepot-{}-{quoi}.redb", std::process::id()));
    let _ = std::fs::remove_file(&copie);
    std::fs::copy(&fixture, &copie).expect("la fixture se copie");
    copie
}

#[test]
fn une_base_ancienne_est_reprise_sans_rien_perdre() {
    // **CE QUE LA FIXTURE CONTIENT** est ce que 0.4.3 y a écrit : trois
    // comptes, deux machines, deux appareils, une description, un jeton, un
    // code, deux services, deux autorisations, deux entrées de journal. Tout
    // doit être là, avec une estampille de plus — et rien d'autre.
    let chemin = base_ancienne("reprise");
    let base = Entrepot::ouvrir(&chemin, racine()).expect("la base ancienne se reprend");
    let pair = un(Genre::Annuaire, 0xA0);
    let thierry = un(Genre::Utilisateur, 1);
    let lea = un(Genre::Utilisateur, 2);
    let du_pair = un(Genre::Utilisateur, 3);
    let grenier = un(Genre::Machine, 10);
    let portable = un(Genre::Machine, 11);
    let iphone = un(Genre::Appareil, 20);
    let pixel = un(Genre::Appareil, 21);
    let depot = un(Genre::Service, 30);
    let imap = un(Genre::Service, 31);
    let accordee = un(Genre::Autorisation, 40);
    let retiree = un(Genre::Autorisation, 41);

    // ── LES COMPTES, ET LEUR ALIAS ──────────────────────────────────────────
    let compte = base.compte(thierry).expect("lisible").expect("Thierry");
    assert_eq!(compte.provenance, Provenance::Ici);
    assert_eq!(compte.alias, Some(alias("thierry")));
    assert_eq!(
        compte.estampille.racine,
        racine(),
        "estampillé par la racine qui reprend"
    );
    assert_eq!(compte.reclamation, compte.estampille);
    assert_eq!(
        base.compte_par_alias("thierry").expect("lisible"),
        Some(thierry)
    );
    let compte = base.compte(lea).expect("lisible").expect("Léa");
    assert_eq!(compte.alias, None);
    let compte = base.compte(du_pair).expect("lisible").expect("du pair");
    assert_eq!(
        compte.provenance,
        Provenance::Annuaire(pair),
        "la provenance survit"
    );
    assert_eq!(
        base.compte_par_alias("ailleurs").expect("lisible"),
        Some(du_pair)
    );

    // ── LES MACHINES, ET LEUR CLÉ ───────────────────────────────────────────
    let machine = base.machine(grenier).expect("lisible").expect("le grenier");
    assert_eq!(machine.proprietaire, thierry);
    assert_eq!(machine.nom.octets(), b"grenier");
    assert!(machine.annonce && machine.lecture);
    let liee = machine.cle.expect("enrôlée");
    assert_eq!(liee.cle, [0x42; 32]);
    assert_eq!(
        liee.liaison, machine.estampille,
        "réputée liée à la reprise"
    );
    assert_eq!(
        liee.code, machine.estampille,
        "et son code réputé émis à la reprise"
    );
    assert_eq!(machine.nom_estampille, machine.estampille);
    assert_eq!(machine.capacites_estampille, machine.estampille);
    let machine = base
        .machine(portable)
        .expect("lisible")
        .expect("le portable");
    assert_eq!(machine.nom.octets(), "portable de Thierry".as_bytes());
    assert!(!machine.annonce && machine.lecture);
    assert!(machine.cle.is_none());
    let miennes = base.machines_de_compte(thierry).expect("lisible");
    assert_eq!(miennes.len(), 2, "l'index des machines est reconstruit");

    // ── LES APPAREILS, LEUR DESCRIPTION, LEUR JETON ─────────────────────────
    let appareil = base.appareil(iphone).expect("lisible").expect("l'iPhone");
    assert_eq!(appareil.proprietaire, thierry);
    assert_eq!(appareil.cle, [0x77; 33]);
    assert_eq!(appareil.atteste, Attestation::Apple);
    assert!(!appareil.revoque());
    let appareil = base.appareil(pixel).expect("lisible").expect("le Pixel");
    assert_eq!(appareil.proprietaire, lea);
    assert_eq!(appareil.atteste, Attestation::Aucune);
    assert!(appareil.revoque());
    let description = base.description(iphone).expect("lisible").expect("décrit");
    assert_eq!(description.systeme, Systeme::Ios);
    assert_eq!(description.modele.octets(), b"iPhone 17");
    let jeton = base.jeton(iphone).expect("lisible").expect("un jeton");
    assert_eq!(jeton.plateforme, Plateforme::Apns);
    assert_eq!(jeton.jeton.octets(), b"c0ffee-jeton-apns");
    // **L'INDEX DES APPAREILS EST RECONSTRUIT** — celui-là n'existait pas
    // quand des bases réelles ont commencé à écrire.
    let siens = base.appareils_de_compte(thierry).expect("lisible");
    assert_eq!(siens.len(), 1);
    assert_eq!(siens[0].0, iphone);
    assert_eq!(siens[0].2.map(|quoi| quoi.systeme), Some(Systeme::Ios));
    assert_eq!(base.appareils_de_compte(lea).expect("lisible").len(), 1);

    // ── LE CODE EN ATTENTE ──────────────────────────────────────────────────
    let enrolement = base
        .consommer_enrolement(&empreinte("4K9M2P7R1T"))
        .expect("lisible")
        .expect("le code est là");
    assert_eq!(enrolement.machine, portable);
    assert_eq!(enrolement.expire_a, 1_800_000_000_000);
    assert_eq!(enrolement.estampille.racine, racine());

    // ── LES SERVICES ────────────────────────────────────────────────────────
    let service = base.service(depot).expect("lisible").expect("le dépôt");
    assert_eq!(service.machine, grenier);
    assert_eq!(service.nom.octets(), b"depot");
    assert_eq!(
        base.service_par_nom(grenier, "imap").expect("lisible"),
        Some(imap)
    );
    assert_eq!(base.services_de_machine(grenier).expect("lisible").len(), 2);

    // ── LES AUTORISATIONS, DANS LES DEUX SENS ───────────────────────────────
    let autorisation = base
        .autorisation(accordee)
        .expect("lisible")
        .expect("accordée");
    assert_eq!(autorisation.par, thierry);
    assert_eq!(autorisation.a, lea);
    assert_eq!(autorisation.portee, Portee::UneMachine(grenier));
    assert!(!autorisation.revoquee);
    assert_eq!(
        autorisation.etiquette.octets(),
        "le grenier pour Léa".as_bytes()
    );
    let autorisation = base
        .autorisation(retiree)
        .expect("lisible")
        .expect("retirée");
    assert!(autorisation.revoquee);
    assert_eq!(base.autorisations_recues(lea).expect("lisible").len(), 1);
    assert_eq!(base.autorisations_accordees(lea).expect("lisible").len(), 1);
    assert_eq!(
        base.autorisations_recues_nommees(thierry)
            .expect("lisible")
            .len(),
        1
    );

    // ── LE JOURNAL DES REQUÊTES NE BOUGE PAS ────────────────────────────────
    assert_eq!(base.entrees_du_journal().expect("lisible"), 2);

    // ── LES ESTAMPILLES SONT UNE SÉQUENCE, ET LE COMPTEUR EST AU-DESSUS ─────
    //
    // Quatorze enregistrements estampillés — trois comptes, deux machines, deux
    // appareils, un jeton, une description, un code, deux services, deux
    // autorisations —, donc le compteur vaut quatorze, et chacun a le sien.
    assert_eq!(base.compteur().expect("lisible"), 14);
    let mut compteurs: Vec<u64> = Vec::new();
    for qui in [thierry, lea, du_pair] {
        compteurs.push(
            base.compte(qui)
                .expect("lisible")
                .expect("là")
                .estampille
                .compteur,
        );
    }
    for quelle in [grenier, portable] {
        compteurs.push(
            base.machine(quelle)
                .expect("lisible")
                .expect("là")
                .estampille
                .compteur,
        );
    }
    for quel in [iphone, pixel] {
        compteurs.push(
            base.appareil(quel)
                .expect("lisible")
                .expect("là")
                .estampille
                .compteur,
        );
    }
    compteurs.push(jeton.estampille.compteur);
    compteurs.push(description.estampille.compteur);
    compteurs.push(enrolement.estampille.compteur);
    for quel in [depot, imap] {
        compteurs.push(
            base.service(quel)
                .expect("lisible")
                .expect("là")
                .estampille
                .compteur,
        );
    }
    for quelle in [accordee, retiree] {
        compteurs.push(
            base.autorisation(quelle)
                .expect("lisible")
                .expect("là")
                .estampille
                .compteur,
        );
    }
    compteurs.sort_unstable();
    assert_eq!(compteurs, (1..=14).collect::<Vec<u64>>());

    // ── LE JOURNAL D'OPÉRATIONS DÉMARRE VIDE, ET PAS DEPUIS ZÉRO ────────────
    //
    // Une base reprise s'amorce chez l'autre par instantané, jamais par
    // rattrapage : demander « tout depuis zéro » est refusé.
    assert_eq!(base.operations_gardees().expect("lisible"), 0);
    assert_eq!(
        base.operations_apres(0).expect("lisible"),
        Rattrapage::HorsJournal {
            retirees_jusqu_a: 14
        }
    );
    assert_eq!(
        base.operations_apres(14).expect("lisible"),
        Rattrapage::Operations(Vec::new())
    );

    // ── ET LA BASE REPRISE S'ÉCRIT COMME UNE NEUVE ──────────────────────────
    base.reclamer_alias(lea, Some(alias("lea"))).expect("écrit");
    assert_eq!(base.compteur().expect("lisible"), 15);
    assert_eq!(operations(&base, 14).len(), 1);
    assert_eq!(base.compte_par_alias("lea").expect("lisible"), Some(lea));
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn une_base_reprise_ne_se_reprend_pas_deux_fois() {
    // La reprise a posé le format : la rouvrir est une ouverture ordinaire, et
    // rien ne bouge — ni les estampilles, ni le compteur.
    let chemin = base_ancienne("reprise-deux-fois");
    let thierry = un(Genre::Utilisateur, 1);
    let avant = {
        let base = Entrepot::ouvrir(&chemin, racine()).expect("reprise");
        base.compte(thierry).expect("lisible").expect("là")
    };
    let base = Entrepot::ouvrir(&chemin, racine()).expect("rouverte");
    assert_eq!(base.compte(thierry).expect("lisible"), Some(avant));
    assert_eq!(base.compteur().expect("lisible"), 14);
    let _ = std::fs::remove_file(&chemin);
}

/// Toutes les estampilles que l'instantané porte — enregistrements, champs,
/// réclamations, cadre de fin —, avec les racines qu'elles nomment.
fn racines_de_l_instantane(base: &Entrepot) -> Vec<Identifiant> {
    instantane(base)
        .iter()
        .flat_map(|cadre| match cadre {
            Cadre::Operation {
                estampille,
                operation,
            } => {
                let mut racines = vec![estampille.racine];
                match operation {
                    Operation::Compte { enregistrement, .. } => {
                        racines.push(enregistrement.estampille.racine);
                        racines.push(enregistrement.reclamation.racine);
                    }
                    Operation::Machine { enregistrement, .. } => {
                        racines.push(enregistrement.estampille.racine);
                        racines.push(enregistrement.nom_estampille.racine);
                        racines.push(enregistrement.capacites_estampille.racine);
                    }
                    Operation::CleMachine { code, .. } => racines.push(code.racine),
                    Operation::Appareil { enregistrement, .. } => {
                        racines.push(enregistrement.estampille.racine);
                    }
                    Operation::Enrolement { enregistrement, .. } => {
                        racines.push(enregistrement.estampille.racine);
                    }
                    Operation::Service { enregistrement, .. } => {
                        racines.push(enregistrement.estampille.racine);
                    }
                    Operation::Autorisation { enregistrement, .. } => {
                        racines.push(enregistrement.estampille.racine);
                    }
                    Operation::Description { enregistrement, .. } => {
                        racines.push(enregistrement.estampille.racine);
                    }
                    Operation::Poussee { enregistrement, .. } => {
                        racines.push(enregistrement.estampille.racine);
                    }
                    Operation::PointDePoussee { enregistrement, .. } => {
                        racines.push(enregistrement.estampille.racine);
                    }
                    _ => {}
                }
                racines
            }
            Cadre::Fin { coupe } => vec![coupe.racine],
        })
        .collect()
}

#[test]
fn une_base_reprise_sans_identite_est_reestampillee_au_premier_demarrage_avec_une_cle() {
    // **C'EST LE CAS DES BANCS** (`replication.md` §11.4) : une base de 0.4.x
    // reprise par une racine SANS `--identity-key` porte ses estampilles sous
    // seize zéros. Au premier démarrage AVEC une clé, tout passe sous
    // l'identité réelle, en une transaction, une fois — et les données ne
    // bougent pas d'un octet.
    let chemin = base_ancienne("reestampillage");
    let thierry = un(Genre::Utilisateur, 1);
    let lea = un(Genre::Utilisateur, 2);
    let grenier = un(Genre::Machine, 10);
    let sans = RACINE_SANS_IDENTITE;

    // ── 1. REPRISE SANS IDENTITÉ : TOUT EST SOUS SEIZE ZÉROS ────────────────
    let (avant, journal_avant) = {
        let base = Entrepot::ouvrir(&chemin, sans).expect("reprise sans identité");
        assert_eq!(base.reestampilles(), 0, "rien à ré-estampiller sans clé");
        // Et une écriture SANS identité entre au journal sous seize zéros :
        // elle aussi devra passer sous l'identité réelle.
        base.reclamer_alias(lea, Some(alias("lea"))).expect("écrit");
        let racines = racines_de_l_instantane(&base);
        assert!(!racines.is_empty());
        assert!(
            racines.iter().all(|quoi| *quoi == sans),
            "tout est estampillé sous la racine sans identité"
        );
        assert_eq!(
            operations(&base, 14)
                .iter()
                .map(|(estampille, _)| estampille.racine)
                .collect::<Vec<_>>(),
            vec![sans]
        );
        (instantane(&base), operations(&base, 14))
    };

    // ── 2. PREMIER DÉMARRAGE AVEC UNE CLÉ : TOUT PASSE SOUS L'IDENTITÉ ──────
    let base = Entrepot::ouvrir(&chemin, racine()).expect("rouverte avec une identité");
    // Quatorze enregistrements repris, un compte réécrit par la réclamation
    // (le même enregistrement — il ne compte qu'une fois), une opération.
    assert_eq!(
        base.reestampilles(),
        15,
        "quatorze enregistrements et une opération"
    );
    let racines = racines_de_l_instantane(&base);
    assert!(
        racines.iter().all(|quoi| *quoi == racine()),
        "aucune estampille n-0… ne reste : {racines:?}"
    );
    assert_eq!(
        base.compteur().expect("lisible"),
        15,
        "le compteur ne bouge pas"
    );

    // Les données sont intactes : le même instantané, à la racine près.
    let apres = instantane(&base);
    assert_eq!(apres.len(), avant.len());
    for (avant, apres) in avant.iter().zip(apres.iter()) {
        match (avant, apres) {
            (
                Cadre::Operation {
                    estampille: e_avant,
                    operation: o_avant,
                },
                Cadre::Operation {
                    estampille: e_apres,
                    operation: o_apres,
                },
            ) => {
                assert_eq!(e_avant.compteur, e_apres.compteur);
                assert_eq!(o_avant.genre(), o_apres.genre());
            }
            (Cadre::Fin { coupe: avant }, Cadre::Fin { coupe: apres }) => {
                assert_eq!(avant.compteur, apres.compteur);
            }
            autre => panic!("l'instantané a changé de forme : {autre:?}"),
        }
    }
    // Le journal d'opérations aussi : la même opération, sous l'identité.
    let journal = operations(&base, 14);
    assert_eq!(journal.len(), 1);
    assert_eq!(journal[0].0, e(15));
    assert_eq!(journal[0].0.compteur, journal_avant[0].0.compteur);
    assert_eq!(journal[0].1, journal_avant[0].1);

    // L'index des alias suit la réclamation : chacun se retrouve par son alias.
    assert_eq!(
        base.compte_par_alias("thierry").expect("lisible"),
        Some(thierry)
    );
    assert_eq!(base.compte_par_alias("lea").expect("lisible"), Some(lea));
    let compte = base.compte(lea).expect("lisible").expect("Léa");
    assert_eq!(compte.reclamation, e(15));
    // La clé liée du grenier et son code aussi.
    let machine = base.machine(grenier).expect("lisible").expect("là");
    let liee = machine.cle.expect("enrôlée");
    assert_eq!(liee.liaison.racine, racine());
    assert_eq!(liee.code.racine, racine());
    assert_eq!(machine.nom_estampille.racine, racine());

    // ── 3. UNE SECONDE OUVERTURE NE REFAIT RIEN ─────────────────────────────
    drop(base);
    let base = Entrepot::ouvrir(&chemin, racine()).expect("rouverte");
    assert_eq!(base.reestampilles(), 0);
    assert_eq!(base.compte(lea).expect("lisible"), Some(compte));
    assert_eq!(base.compteur().expect("lisible"), 15);

    // Et l'entrepôt reprend ses écritures sous l'identité, comme un neuf.
    base.reclamer_alias(thierry, None).expect("écrit");
    assert_eq!(operations(&base, 15).len(), 1);
    assert_eq!(operations(&base, 15)[0].0, e(16));
    let _ = std::fs::remove_file(&chemin);
}

// ── Les comptes et leur alias ───────────────────────────────────────────────

#[test]
fn un_compte_se_relit_par_son_identifiant_et_par_son_alias() {
    let (base, chemin) = entrepot("compte");
    let qui = un(Genre::Utilisateur, 1);
    base.creer_compte(qui, Provenance::Ici, Some(alias("thierry")))
        .expect("écrit");

    assert_eq!(
        base.compte(qui).expect("lisible").map(|quoi| quoi.alias),
        Some(Some(alias("thierry")))
    );
    assert_eq!(
        base.compte_par_alias("thierry").expect("lisible"),
        Some(qui)
    );
    // Créer deux fois est refusé : « insérer si absent ».
    assert!(matches!(
        base.creer_compte(qui, Provenance::Ici, None),
        Err(Faute::Existe)
    ));
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn changer_d_alias_retire_l_ancien_de_l_index() {
    // **C'EST L'INVARIANT DE L'INDEX.** Sans ce retrait, l'ancien nom rendrait
    // encore un identifiant — et deux noms désigneraient un compte qui n'en
    // revendique qu'un.
    let (base, chemin) = entrepot("changement");
    let qui = un(Genre::Utilisateur, 1);
    base.creer_compte(qui, Provenance::Ici, Some(alias("avant")))
        .expect("écrit");
    assert!(
        base.reclamer_alias(qui, Some(alias("apres")))
            .expect("réécrit")
    );

    assert_eq!(base.compte_par_alias("apres").expect("lisible"), Some(qui));
    assert_eq!(
        base.compte_par_alias("avant").expect("lisible"),
        None,
        "l'ancien alias rend encore un identifiant"
    );
    let compte = base.compte(qui).expect("lisible").expect("là");
    assert_eq!(compte.reclamation, e(2), "une réclamation nouvelle");
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn retirer_son_alias_le_retire_aussi_de_l_index() {
    let (base, chemin) = entrepot("retrait");
    let qui = un(Genre::Utilisateur, 1);
    base.creer_compte(qui, Provenance::Ici, Some(alias("visible")))
        .expect("écrit");
    assert!(base.reclamer_alias(qui, None).expect("réécrit"));

    assert_eq!(
        base.compte(qui).expect("lisible").map(|quoi| quoi.alias),
        Some(None)
    );
    assert_eq!(base.compte_par_alias("visible").expect("lisible"), None);
    // L'opération dit « rien ».
    assert_eq!(
        operations(&base, 1)[0].1,
        Operation::Alias {
            compte: qui,
            alias: None
        }
    );
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn un_alias_deja_pris_par_un_autre_est_refuse() {
    // Deux comptes qui répondraient au même alias le rendraient inutilisable
    // pour retrouver quelqu'un, ce qui est sa seule raison d'être.
    let (base, chemin) = entrepot("dispute");
    base.creer_compte(
        un(Genre::Utilisateur, 1),
        Provenance::Ici,
        Some(alias("thierry")),
    )
    .expect("écrit");
    let refus = base.creer_compte(
        un(Genre::Utilisateur, 2),
        Provenance::Ici,
        Some(alias("thierry")),
    );
    assert!(matches!(refus, Err(Faute::AliasPris)), "{refus:?}");
    base.creer_compte(un(Genre::Utilisateur, 2), Provenance::Ici, None)
        .expect("écrit");
    let refus = base.reclamer_alias(un(Genre::Utilisateur, 2), Some(alias("thierry")));
    assert!(matches!(refus, Err(Faute::AliasPris)), "{refus:?}");

    // Et le premier n'a pas bougé.
    assert_eq!(
        base.compte_par_alias("thierry").expect("lisible"),
        Some(un(Genre::Utilisateur, 1))
    );
    // Un refus n'est pas une écriture : ni estampille, ni opération.
    assert_eq!(base.compteur().expect("lisible"), 2);
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn reclamer_ce_qu_on_tient_deja_ne_rafraichit_pas_la_reclamation() {
    // **LA PLUS ANCIENNE RÉCLAMATION TIENT** (`replication.md` §3.2) : la
    // rafraîchir ferait perdre un alias qu'on gagnait. Réclamer ce qu'on a
    // n'écrit rien.
    let (base, chemin) = entrepot("idempotent");
    let qui = un(Genre::Utilisateur, 1);
    base.creer_compte(qui, Provenance::Ici, Some(alias("thierry")))
        .expect("écrit");
    assert!(
        base.reclamer_alias(qui, Some(alias("thierry")))
            .expect("le même alias")
    );
    assert_eq!(base.compteur().expect("lisible"), 1, "rien n'a été écrit");
    assert_eq!(
        base.compte(qui)
            .expect("lisible")
            .map(|quoi| quoi.reclamation),
        Some(e(1))
    );
    // Un compte qui n'existe pas ne réclame rien.
    assert!(
        !base
            .reclamer_alias(un(Genre::Utilisateur, 9), Some(alias("x")))
            .expect("lisible")
    );
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn un_alias_qui_en_prefixe_un_autre_ne_le_confond_pas() {
    // L'octet nul entre l'alias et l'estampille : `lea` n'est pas `leandre`.
    let (base, chemin) = entrepot("prefixe");
    base.creer_compte(
        un(Genre::Utilisateur, 1),
        Provenance::Ici,
        Some(alias("lea")),
    )
    .expect("écrit");
    base.creer_compte(
        un(Genre::Utilisateur, 2),
        Provenance::Ici,
        Some(alias("leandre")),
    )
    .expect("écrit");
    assert_eq!(
        base.compte_par_alias("lea").expect("lisible"),
        Some(un(Genre::Utilisateur, 1))
    );
    assert_eq!(
        base.compte_par_alias("leandre").expect("lisible"),
        Some(un(Genre::Utilisateur, 2))
    );
    assert_eq!(base.compte_par_alias("le").expect("lisible"), None);
    let _ = std::fs::remove_file(&chemin);
}

// ── Les machines ────────────────────────────────────────────────────────────

#[test]
fn une_machine_se_relit_entiere() {
    let (base, chemin) = entrepot("machine");
    let qui = un(Genre::Machine, 9);
    base.creer_machine(
        qui,
        Provenance::Ici,
        un(Genre::Utilisateur, 1),
        nom("grenier"),
        Capacites {
            annonce: true,
            lecture: false,
        },
    )
    .expect("écrit");
    let machine = base.machine(qui).expect("lisible").expect("là");
    assert_eq!(machine.proprietaire, un(Genre::Utilisateur, 1));
    assert!(machine.annonce && !machine.lecture);
    assert!(machine.cle.is_none(), "déclarée, pas enrôlée");
    assert_eq!(machine.nom.octets(), b"grenier");
    assert!(matches!(
        base.creer_machine(
            qui,
            Provenance::Ici,
            un(Genre::Utilisateur, 1),
            nom("x"),
            TOUT
        ),
        Err(Faute::Existe)
    ));
    let _ = std::fs::remove_file(&chemin);
}

// ── Le journal (C18) ────────────────────────────────────────────────────────

/// Une entrée de journal à cet instant.
fn entree(quand: u64) -> EntreeJournal {
    EntreeJournal {
        quand,
        demandeur: un(Genre::Machine, 1),
        visee: un(Genre::Machine, 2),
        service: nom("imap"),
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
    // **LE JOURNAL NE SE RÉPLIQUE PAS** : ni estampille, ni opération.
    assert_eq!(base.compteur().expect("lisible"), 0);
    assert_eq!(base.operations_gardees().expect("lisible"), 0);
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

    base.creer_compte(du_pair, Provenance::Annuaire(pair), Some(alias("depair")))
        .expect("écrit");
    base.creer_compte(d_ailleurs, Provenance::Annuaire(autre), None)
        .expect("écrit");
    base.creer_compte(d_ici, Provenance::Ici, Some(alias("chezmoi")))
        .expect("écrit");

    let machine_du_pair = un(Genre::Machine, 1);
    base.creer_machine(
        machine_du_pair,
        Provenance::Annuaire(pair),
        du_pair,
        nom("grenier"),
        TOUT,
    )
    .expect("écrit");

    let efface = base.oublier_ce_qui_vient_de(pair).expect("rompu");
    assert_eq!(efface, 2, "un compte et une machine");

    assert_eq!(base.compte(du_pair).expect("lisible"), None);
    assert_eq!(base.machine(machine_du_pair).expect("lisible"), None);
    assert!(
        base.machines_de_compte(du_pair)
            .expect("lisible")
            .is_empty(),
        "l'index des machines part avec la machine"
    );
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
    base.creer_compte(qui, Provenance::Annuaire(pair), Some(alias("orphelin")))
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

#[test]
fn rompre_efface_les_services_les_autorisations_les_appareils_et_les_codes() {
    // C17 dit « aucun enregistrement ne doit subsister avec cette origine », et
    // COMMENT elle tombe : « par un `INSERT` ajouté à la hâte, jamais par une
    // décision. »
    let (base, fichier) = entrepot("rupture-complete");
    let pair = un(Genre::Annuaire, 1);
    let venu = Provenance::Annuaire(pair);

    let compte = un(Genre::Utilisateur, 2);
    let machine = un(Genre::Machine, 3);
    let service = un(Genre::Service, 4);
    let appareil = un(Genre::Appareil, 5);
    let autorisation = un(Genre::Autorisation, 6);
    let clef = empreinte("0123456789");

    base.creer_compte(compte, venu, None).expect("écrit");
    base.creer_machine(machine, venu, compte, nom("grenier"), TOUT)
        .expect("écrit");
    base.declarer_service(service, venu, machine, nom("depot"))
        .expect("écrit");
    base.creer_appareil(appareil, venu, compte, [2; 33], Attestation::Aucune)
        .expect("écrit");
    base.poser_jeton(
        appareil,
        venu,
        Plateforme::Fcm,
        JetonRange::nouveau("d0d0").expect("il tient"),
    )
    .expect("écrit");
    base.accorder_autorisation(
        autorisation,
        venu,
        compte,
        un(Genre::Utilisateur, 7),
        Portee::ToutLeCompte,
        nom("essai"),
    )
    .expect("écrit");
    base.emettre_enrolement(&clef, venu, machine, 10_000)
        .expect("écrit");
    base.poser_description(appareil, venu, Systeme::Ios, nom("iPhone 17"))
        .expect("écrit");

    // Et une ligne de journal, qui doit SURVIVRE — c'est la seule exception, et
    // elle est écrite dans C17.
    base.journaliser(&EntreeJournal {
        quand: 1,
        demandeur: compte,
        visee: machine,
        service: nom("depot"),
        verdict: Verdict::Servi,
        provenance: venu,
    })
    .expect("écrit");

    // **RIEN DE TOUT CELA N'EST DANS LE JOURNAL D'OPÉRATIONS** : ce n'est pas
    // de provenance locale.
    assert_eq!(base.operations_gardees().expect("lisible"), 0);

    let efface = base.oublier_ce_qui_vient_de(pair).expect("rompu");
    assert_eq!(
        efface, 7,
        "un compte, une machine, un service, une autorisation, un appareil, un code, une description"
    );

    assert_eq!(base.compte(compte).expect("lisible"), None);
    assert_eq!(base.machine(machine).expect("lisible"), None);
    assert_eq!(base.service(service).expect("lisible"), None);
    assert_eq!(base.appareil(appareil).expect("lisible"), None);
    assert_eq!(base.description(appareil).expect("lisible"), None);
    assert_eq!(
        base.jeton(appareil).expect("lisible"),
        None,
        "le jeton part avec l'appareil"
    );
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
    assert!(
        base.autorisations_accordees(compte)
            .expect("lisible")
            .is_empty(),
        "l'index des accordées aussi"
    );
    assert!(
        base.appareils_de_compte(compte)
            .expect("lisible")
            .is_empty(),
        "l'index des appareils part avec l'appareil"
    );
    assert_eq!(
        base.entrees_du_journal().expect("lisible"),
        1,
        "LE JOURNAL SURVIT — c'est l'exception de C17, et la seule"
    );

    let _ = std::fs::remove_file(fichier);
}

// ── Les services ────────────────────────────────────────────────────────────

#[test]
fn un_service_se_relit_par_son_identifiant_et_par_son_nom() {
    let (base, chemin) = entrepot("service");
    let machine = un(Genre::Machine, 1);
    let quel = un(Genre::Service, 1);
    base.declarer_service(quel, Provenance::Ici, machine, nom("imap"))
        .expect("écrit");

    let service = base.service(quel).expect("lisible").expect("là");
    assert_eq!(service.machine, machine);
    assert_eq!(service.nom.octets(), b"imap");
    assert_eq!(
        base.service_par_nom(machine, "imap").expect("lisible"),
        Some(quel)
    );
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn deux_machines_peuvent_servir_le_meme_nom_mais_pas_une_machine_deux_fois() {
    // **C'EST LA RAISON DE LA CLÉ COMPOSÉE.** Un nom de service n'est unique que
    // sur SA machine ; deux machines qui servent toutes deux `imap` est le cas
    // ordinaire, pas une collision. Sur la même machine, c'est un refus : « si
    // `(machine, nom)` est déjà tenu, le plus ancien reste ».
    let (base, chemin) = entrepot("homonymes");
    let une = un(Genre::Machine, 1);
    let autre = un(Genre::Machine, 2);
    base.declarer_service(un(Genre::Service, 1), Provenance::Ici, une, nom("imap"))
        .expect("écrit");
    base.declarer_service(un(Genre::Service, 2), Provenance::Ici, autre, nom("imap"))
        .expect("écrit");
    assert!(matches!(
        base.declarer_service(un(Genre::Service, 3), Provenance::Ici, une, nom("imap")),
        Err(Faute::Existe)
    ));
    assert!(matches!(
        base.declarer_service(un(Genre::Service, 1), Provenance::Ici, une, nom("pop")),
        Err(Faute::Existe)
    ));

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

#[test]
fn les_autorisations_recues_sont_celles_du_beneficiaire_et_pas_d_un_autre() {
    let (base, chemin) = entrepot("recues");
    let donneur = un(Genre::Utilisateur, 1);
    let beneficiaire = un(Genre::Utilisateur, 2);
    let etranger = un(Genre::Utilisateur, 3);

    base.accorder_autorisation(
        un(Genre::Autorisation, 1),
        Provenance::Ici,
        donneur,
        beneficiaire,
        Portee::ToutLeCompte,
        nom("essai"),
    )
    .expect("écrit");
    base.accorder_autorisation(
        un(Genre::Autorisation, 2),
        Provenance::Ici,
        donneur,
        etranger,
        Portee::ToutLeCompte,
        nom("essai"),
    )
    .expect("écrit");

    let siennes = base.autorisations_recues(beneficiaire).expect("lisible");
    assert_eq!(siennes.len(), 1, "{siennes:?}");
    assert_eq!(siennes.first().map(|quoi| quoi.a), Some(beneficiaire));
    assert!(matches!(
        base.accorder_autorisation(
            un(Genre::Autorisation, 1),
            Provenance::Ici,
            donneur,
            beneficiaire,
            Portee::ToutLeCompte,
            nom("essai"),
        ),
        Err(Faute::Existe)
    ));
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
        (1_u8, Portee::ToutLeCompte),
        (2, Portee::UneMachine(un(Genre::Machine, 1))),
        (3, Portee::UnService(un(Genre::Service, 1))),
    ] {
        base.accorder_autorisation(
            un(Genre::Autorisation, rang),
            Provenance::Ici,
            un(Genre::Utilisateur, 1),
            beneficiaire,
            portee,
            nom("essai"),
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
fn un_compte_sans_autorisation_en_recoit_une_liste_vide() {
    let (base, chemin) = entrepot("aucune");
    assert!(
        base.autorisations_recues(un(Genre::Utilisateur, 7))
            .expect("lisible")
            .is_empty()
    );
    let _ = std::fs::remove_file(&chemin);
}

// ── Les appareils ───────────────────────────────────────────────────────────

#[test]
fn un_appareil_se_pose_et_se_relit() {
    let (base, fichier) = entrepot("appareil");
    let quel = un(Genre::Appareil, 3);
    assert_eq!(base.appareil(quel).expect("lisible"), None, "base neuve");

    base.creer_appareil(
        quel,
        Provenance::Ici,
        un(Genre::Utilisateur, 1),
        [0x77; 33],
        Attestation::Aucune,
    )
    .expect("écrit");
    let appareil = base.appareil(quel).expect("lisible").expect("là");
    assert_eq!(appareil.proprietaire, un(Genre::Utilisateur, 1));
    assert_eq!(appareil.cle, [0x77; 33]);
    assert_eq!(appareil.atteste, Attestation::Aucune);
    assert!(!appareil.revoque());
    assert!(matches!(
        base.creer_appareil(
            quel,
            Provenance::Ici,
            un(Genre::Utilisateur, 1),
            [0; 33],
            Attestation::Aucune
        ),
        Err(Faute::Existe)
    ));

    let _ = std::fs::remove_file(fichier);
}

// ── Les codes d'enrôlement ──────────────────────────────────────────────────

#[test]
fn un_code_se_pose_se_consomme_une_fois_et_pas_deux() {
    let (base, fichier) = entrepot("code");
    let machine = un(Genre::Machine, 4);
    let clef = empreinte("0123456789");

    base.emettre_enrolement(&clef, Provenance::Ici, machine, 1_000)
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
    // **CONSOMMER N'EST PAS UNE OPÉRATION** : seule l'émission l'était.
    assert_eq!(base.compteur().expect("lisible"), 1);
    assert_eq!(base.operations_gardees().expect("lisible"), 1);

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
        base.emettre_enrolement(clef, Provenance::Ici, machine, 1_000)
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
        base.emettre_enrolement(clef, Provenance::Ici, un(Genre::Machine, machine), expire_a)
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
    // Expirer n'est pas une opération non plus : chaque racine à son horloge.
    assert_eq!(base.compteur().expect("lisible"), 2);

    let _ = std::fs::remove_file(fichier);
}

// ── Une base neuve ──────────────────────────────────────────────────────────

#[test]
fn une_base_neuve_rend_des_listes_vides_et_non_des_fautes() {
    // **UNE TABLE QUE REDB N'A JAMAIS VUE N'EXISTE PAS**, et l'ouvrir en lecture
    // rend `TableDoesNotExist` — pas un intervalle vide.
    let (base, fichier) = entrepot("neuve-listes");
    let compte = un(Genre::Utilisateur, 1);
    let appareil = un(Genre::Appareil, 2);

    assert!(base.machines_de_compte(compte).expect("lisible").is_empty());
    assert!(
        base.autorisations_accordees(compte)
            .expect("lisible")
            .is_empty()
    );
    assert!(base.jeton(appareil).expect("lisible").is_none());
    assert!(base.description(appareil).expect("lisible").is_none());
    assert!(
        base.appareils_de_compte(compte)
            .expect("lisible")
            .is_empty()
    );

    let _ = std::fs::remove_file(fichier);
}

// ── Les descriptions d'appareil ─────────────────────────────────────────────

#[test]
fn une_description_se_pose_se_relit_et_se_remplace() {
    // **LA NEUVE REMPLACE L'ANCIENNE** : un appareil qui se redécrit est ce
    // qu'il est aujourd'hui, pas ce qu'il a été.
    let (base, fichier) = entrepot("description");
    let quel = un(Genre::Appareil, 3);
    assert!(base.description(quel).expect("lisible").is_none());

    base.poser_description(quel, Provenance::Ici, Systeme::Ios, nom("iPhone 17"))
        .expect("écrit");
    let lue = base
        .description(quel)
        .expect("lisible")
        .expect("elle est là");
    assert_eq!(lue.systeme, Systeme::Ios);
    assert_eq!(lue.modele.octets(), "iPhone 17".as_bytes());
    assert_eq!(lue.estampille, e(1));

    base.poser_description(
        quel,
        Provenance::Ici,
        Systeme::Macos,
        nom("MacBook Pro (2019)"),
    )
    .expect("écrit");
    let lue = base
        .description(quel)
        .expect("lisible")
        .expect("elle est là");
    assert_eq!(lue.systeme, Systeme::Macos, "le système change aussi");
    assert_eq!(lue.modele.octets(), "MacBook Pro (2019)".as_bytes());
    assert_eq!(lue.estampille, e(2), "la plus récente");

    let _ = std::fs::remove_file(fichier);
}

#[test]
fn la_liste_des_appareils_porte_leur_description_quand_ils_en_ont_une() {
    // **C'EST L'ÉCRAN COMPTE** : deux appareils, dont un seul s'est décrit.
    let (base, fichier) = entrepot("liste-decrite");
    let compte = un(Genre::Utilisateur, 1);
    let decrit = un(Genre::Appareil, 2);
    let muet = un(Genre::Appareil, 3);
    for quel in [decrit, muet] {
        base.creer_appareil(
            quel,
            Provenance::Ici,
            compte,
            [0x77; 33],
            Attestation::Aucune,
        )
        .expect("écrit");
    }
    base.poser_description(decrit, Provenance::Ici, Systeme::Android, nom("Pixel 9"))
        .expect("écrit");

    let liste = base.appareils_de_compte(compte).expect("lisible");
    assert_eq!(liste.len(), 2);
    for (quel, _, lue) in liste {
        if quel == decrit {
            let lue = lue.expect("décrit");
            assert_eq!(lue.systeme, Systeme::Android);
            assert_eq!(lue.modele.octets(), b"Pixel 9");
        } else {
            assert_eq!(quel, muet);
            assert!(lue.is_none(), "un appareil muet n'a pas de description");
        }
    }

    let _ = std::fs::remove_file(fichier);
}

#[test]
fn revoquer_un_appareil_garde_sa_description() {
    // **À L'INVERSE DU JETON.** La description ne donne aucun droit, et elle est
    // ce qui rend lisible ce qu'on a retiré : « iPhone 17, révoqué ».
    let (base, fichier) = entrepot("revoque-description");
    let compte = un(Genre::Utilisateur, 1);
    let quel = un(Genre::Appareil, 3);
    base.creer_appareil(
        quel,
        Provenance::Ici,
        compte,
        [0x77; 33],
        Attestation::Aucune,
    )
    .expect("écrit");
    base.poser_description(quel, Provenance::Ici, Systeme::Ios, nom("iPhone 17"))
        .expect("écrit");

    base.revoquer_appareil(quel, REVOQUE_LE).expect("révoqué");
    let liste = base.appareils_de_compte(compte).expect("lisible");
    let (_, appareil, lue) = liste.first().expect("il reste");
    assert!(appareil.revoque());
    assert_eq!(
        lue.map(|quoi| quoi.systeme),
        Some(Systeme::Ios),
        "la description reste avec l'appareil marqué"
    );

    let _ = std::fs::remove_file(fichier);
}

// ── Les jetons de poussée ───────────────────────────────────────────────────

#[test]
fn un_jeton_se_depose_se_relit_et_se_remplace() {
    // **LE NEUF REMPLACE L'ANCIEN**, il ne s'ajoute pas : Apple et Google font
    // tourner leurs jetons, et en garder deux enverrait chaque notification en
    // double, dont une à un jeton mort.
    let (base, fichier) = entrepot("jeton");
    let quel = un(Genre::Appareil, 3);
    assert!(base.jeton(quel).expect("lisible").is_none());

    base.poser_jeton(
        quel,
        Provenance::Ici,
        Plateforme::Apns,
        JetonRange::nouveau("c0ffee").expect("il tient"),
    )
    .expect("écrit");
    let lu = base.jeton(quel).expect("lisible").expect("il est là");
    assert_eq!(lu.plateforme, Plateforme::Apns);
    assert_eq!(lu.jeton.octets(), b"c0ffee");

    base.poser_jeton(
        quel,
        Provenance::Ici,
        Plateforme::Fcm,
        JetonRange::nouveau("d0d0").expect("il tient"),
    )
    .expect("écrit");
    let lu = base.jeton(quel).expect("lisible").expect("il est là");
    assert_eq!(
        lu.plateforme,
        Plateforme::Fcm,
        "la plate-forme change aussi"
    );
    assert_eq!(lu.jeton.octets(), b"d0d0");
    assert_eq!(lu.estampille, e(2), "le plus récent");

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
    base.creer_appareil(
        quel,
        Provenance::Ici,
        un(Genre::Utilisateur, 1),
        [0x77; 33],
        Attestation::Aucune,
    )
    .expect("écrit");
    base.poser_jeton(
        quel,
        Provenance::Ici,
        Plateforme::Apns,
        JetonRange::nouveau("c0ffee").expect("il tient"),
    )
    .expect("écrit");

    base.revoquer_appareil(quel, REVOQUE_LE).expect("révoqué");
    assert!(
        base.appareil(quel)
            .expect("lisible")
            .expect("il reste")
            .revoque()
    );
    assert!(
        base.jeton(quel).expect("lisible").is_none(),
        "le jeton part avec l'appareil"
    );

    let _ = std::fs::remove_file(fichier);
}

// ── Les points de poussée (`protocole.md` §2.2, 2026-09-25) ─────────────────

/// Un point de poussée vers ce chemin.
fn un_point(chemin: &str) -> PointRange {
    PointRange::nouveau(&format!("https://ntfy.example.org/{chemin}")).expect("il tient")
}

/// Un appareil vivant de ce compte.
fn un_appareil_de(base: &Entrepot, quel: Identifiant, compte: Identifiant) {
    base.creer_appareil(
        quel,
        Provenance::Ici,
        compte,
        [0x77; 33],
        Attestation::Aucune,
    )
    .expect("écrit");
}

#[test]
fn un_point_se_depose_se_remplace_et_se_journalise() {
    let (base, fichier) = entrepot("point");
    let quel = un(Genre::Appareil, 3);
    un_appareil_de(&base, quel, un(Genre::Utilisateur, 1));
    assert!(base.point(quel).expect("lisible").is_none());

    assert!(
        base.poser_point(quel, un_point("ancien"), Some([0x04; 65]), None)
            .expect("écrit")
    );
    let lu = base.point(quel).expect("lisible").expect("il est là");
    assert_eq!(lu.point.octets(), b"https://ntfy.example.org/ancien");
    assert_eq!(lu.cle, Some([0x04; 65]));
    assert_eq!(lu.secret, None);

    // **LE NEUF REMPLACE L'ANCIEN**, la clé comprise : un point neuf vient
    // d'un distributeur neuf, et ce qu'il n'a pas donné n'est plus.
    assert!(
        base.poser_point(quel, un_point("neuf"), None, Some([0x11; 16]))
            .expect("écrit")
    );
    let lu = base.point(quel).expect("lisible").expect("il est là");
    assert_eq!(lu.point.octets(), b"https://ntfy.example.org/neuf");
    assert_eq!((lu.cle, lu.secret), (None, Some([0x11; 16])));
    assert_eq!(lu.estampille, e(3), "le plus récent");

    // Chaque dépôt est une opération `point-de-poussee`, sous son estampille.
    let journal = operations(&base, 1);
    assert_eq!(
        journal.last(),
        Some(&(
            e(3),
            Operation::PointDePoussee {
                appareil: quel,
                enregistrement: lu,
            }
        ))
    );
    // Et l'instantané le porte, pour la racine qui s'amorce.
    assert!(instantane(&base).iter().any(|cadre| matches!(
        cadre,
        Cadre::Operation {
            operation: Operation::PointDePoussee { appareil, .. },
            ..
        } if *appareil == quel
    )));

    let _ = std::fs::remove_file(fichier);
}

#[test]
fn un_appareil_absent_ou_revoque_ne_depose_pas_de_point() {
    let (base, fichier) = entrepot("point-refuse");
    let absent = un(Genre::Appareil, 4);
    assert!(
        !base
            .poser_point(absent, un_point("x"), None, None)
            .expect("lisible")
    );
    assert!(base.point(absent).expect("lisible").is_none());

    let revoque = un(Genre::Appareil, 5);
    un_appareil_de(&base, revoque, un(Genre::Utilisateur, 1));
    base.revoquer_appareil(revoque, REVOQUE_LE)
        .expect("révoqué");
    let avant = base.compteur().expect("lisible");
    assert!(
        !base
            .poser_point(revoque, un_point("x"), None, None)
            .expect("lisible")
    );
    assert!(base.point(revoque).expect("lisible").is_none());
    assert_eq!(
        base.compteur().expect("lisible"),
        avant,
        "rien n'est estampillé, rien n'est journalisé"
    );

    let _ = std::fs::remove_file(fichier);
}

#[test]
fn le_point_part_avec_l_appareil_et_seuls_les_vivants_du_compte_sont_reveilles() {
    let (base, fichier) = entrepot("points-du-compte");
    let thierry = un(Genre::Utilisateur, 1);
    let lea = un(Genre::Utilisateur, 2);
    let (pixel, fp5, sans_point, perdu) = (
        un(Genre::Appareil, 1),
        un(Genre::Appareil, 2),
        un(Genre::Appareil, 3),
        un(Genre::Appareil, 4),
    );
    base.creer_compte(thierry, Provenance::Ici, None)
        .expect("écrit");
    base.creer_compte(lea, Provenance::Ici, None)
        .expect("écrit");
    for quel in [pixel, sans_point, perdu] {
        un_appareil_de(&base, quel, thierry);
    }
    un_appareil_de(&base, fp5, lea);
    for quel in [pixel, fp5, perdu] {
        assert!(
            base.poser_point(quel, un_point(&quel.to_string()), None, None)
                .expect("écrit")
        );
    }

    // **RÉVOQUER EMPORTE LE POINT**, dans la même écriture : un téléphone
    // déclaré perdu ne doit plus être réveillé pour ce compte.
    base.revoquer_appareil(perdu, REVOQUE_LE).expect("révoqué");
    assert!(base.point(perdu).expect("lisible").is_none());

    let reveilles: Vec<Identifiant> = base
        .points_du_compte(thierry)
        .expect("lisible")
        .into_iter()
        .map(|(quel, _)| quel)
        .collect();
    assert_eq!(
        reveilles,
        vec![pixel],
        "un vivant, avec un point, de CE compte"
    );
    assert_eq!(base.points_du_compte(lea).expect("lisible").len(), 1);

    // **EFFACER LE COMPTE EMPORTE SES POINTS.**
    base.effacer_compte(thierry, Cause::Titulaire, REVOQUE_LE)
        .expect("effacé");
    assert!(base.point(pixel).expect("lisible").is_none());
    assert!(base.points_du_compte(thierry).expect("lisible").is_empty());

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
        base.revoquer_appareil(quel, REVOQUE_LE)
            .expect("lisible")
            .is_none(),
        "révoquer ce qui n'existe pas ne crée rien"
    );

    base.creer_appareil(
        quel,
        Provenance::Ici,
        un(Genre::Utilisateur, 1),
        [0x77; 33],
        Attestation::Aucune,
    )
    .expect("écrit");

    let avant = base.revoquer_appareil(quel, REVOQUE_LE).expect("révoqué");
    assert_eq!(
        avant.map(|quoi| quoi.revoque()),
        Some(false),
        "ce qu'il ÉTAIT"
    );
    let apres = base.appareil(quel).expect("lisible").expect("il reste");
    assert!(apres.revoque());
    assert_eq!(apres.cle, [0x77; 33], "la clé reste, et ne vaut plus");

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

    base.accorder_autorisation(
        quelle,
        Provenance::Ici,
        un(Genre::Utilisateur, 2),
        beneficiaire,
        Portee::ToutLeCompte,
        nom("essai"),
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

#[test]
fn les_machines_d_un_compte_se_retrouvent_sans_balayer_l_annuaire() {
    // **L'INDEX EXISTE POUR CELA.** `MACHINES` porte le propriétaire à
    // l'intérieur : sans index, répondre demanderait de balayer toutes les
    // machines de l'annuaire, quand la réponse ne dépend que d'un compte.
    let (entrepot, chemin) = entrepot("machines-de-compte");
    let moi = un(Genre::Utilisateur, 1);
    let autre = un(Genre::Utilisateur, 2);

    for (marque, proprietaire) in [(10, moi), (11, moi), (12, autre)] {
        entrepot
            .creer_machine(
                un(Genre::Machine, marque),
                Provenance::Ici,
                proprietaire,
                nom("grenier"),
                TOUT,
            )
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

    for (marque, machine, texte) in [(20, une, "depot"), (21, une, "imap"), (22, autre, "depot")] {
        entrepot
            .declarer_service(
                un(Genre::Service, marque),
                Provenance::Ici,
                machine,
                nom(texte),
            )
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
            .accorder_autorisation(
                quelle,
                Provenance::Ici,
                par,
                a,
                Portee::ToutLeCompte,
                nom("essai"),
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
        .accorder_autorisation(
            quelle,
            Provenance::Ici,
            moi,
            autre,
            Portee::ToutLeCompte,
            nom("essai"),
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

// ── La reprise d'une base d'avant les dates (`modele.md` §2.2, 0.10.1) ───────

/// Une copie de la base écrite par 0.10.1 : l'estampille et le journal
/// d'opérations sont là, `révoqué le` et `effacé le` non.
///
/// **LA FIXTURE A ÉTÉ ÉCRITE PAR LE CODE DE 0.10.1**, avec ses fonctions
/// d'écriture d'alors, puis compactée — et non fabriquée par le code
/// d'aujourd'hui, qui ne sait plus écrire cette forme. C'est ce que les bancs
/// portent au moment de ce changement de format.
fn base_sans_dates(quoi: &str) -> PathBuf {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/entrepot-0.10.1.redb");
    let copie =
        std::env::temp_dir().join(format!("asl-entrepot-{}-{quoi}.redb", std::process::id()));
    let _ = std::fs::remove_file(&copie);
    std::fs::copy(&fixture, &copie).expect("la fixture se copie");
    copie
}

/// Maintenant, en millisecondes d'époque.
fn maintenant_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |ecoule| {
            u64::try_from(ecoule.as_millis()).unwrap_or(u64::MAX)
        })
}

#[test]
fn une_base_sans_dates_est_reprise_et_les_revoques_recoivent_la_date_de_la_reprise() {
    // **CE QUE LA FIXTURE CONTIENT** est ce que 0.10.1 y a écrit : trois
    // comptes (Thierry avec l'alias `thierry`, Léa, un du pair avec `ailleurs`),
    // deux machines (le grenier enrôlé, le portable avec un code en attente),
    // deux appareils (l'iPhone de Thierry, décrit et avec un jeton ; le Pixel
    // de Léa, RÉVOQUÉ), deux services, deux autorisations dont une révoquée,
    // deux entrées de journal, dix-neuf écritures et dix-huit opérations.
    let avant = maintenant_ms();
    let chemin = base_sans_dates("reprise-dates");
    let base = Entrepot::ouvrir(&chemin, racine()).expect("la base d'avant les dates se reprend");
    let apres = maintenant_ms();
    let thierry = un(Genre::Utilisateur, 1);
    let lea = un(Genre::Utilisateur, 2);
    let du_pair = un(Genre::Utilisateur, 3);
    let grenier = un(Genre::Machine, 10);
    let portable = un(Genre::Machine, 11);
    let iphone = un(Genre::Appareil, 20);
    let pixel = un(Genre::Appareil, 21);

    // ── UN APPAREIL RÉVOQUÉ A REÇU LA DATE DE LA REPRISE, UN VIVANT RIEN ────
    assert_eq!(base.dates_de_reprise(), 1, "le Pixel, et lui seul");
    let pixel_range = base.appareil(pixel).expect("lisible").expect("le Pixel");
    let quand = pixel_range.revoque_le.expect("révoqué, donc daté");
    assert!(
        (avant..=apres).contains(&quand),
        "la date est celle de la reprise : {quand} hors de {avant}..={apres}"
    );
    assert_eq!(pixel_range.proprietaire, lea);
    let iphone_range = base.appareil(iphone).expect("lisible").expect("l'iPhone");
    assert_eq!(iphone_range.revoque_le, None);
    assert_eq!(iphone_range.atteste, Attestation::Apple);
    assert_eq!(iphone_range.cle, [0x77; 33]);

    // ── AUCUN COMPTE N'EST EFFACÉ, ET RIEN N'A BOUGÉ ────────────────────────
    for (qui, alias_attendu) in [
        (thierry, Some("thierry")),
        (lea, None),
        (du_pair, Some("ailleurs")),
    ] {
        let compte = base.compte(qui).expect("lisible").expect("là");
        assert!(!compte.est_efface(), "{qui}");
        assert_eq!(compte.alias, alias_attendu.map(alias), "{qui}");
        assert_eq!(base.compte_vivant(qui).expect("lisible"), Some(compte));
        assert_eq!(
            compte.estampille.racine,
            racine(),
            "l'estampille ne bouge pas"
        );
    }
    assert_eq!(
        base.compte(du_pair)
            .expect("lisible")
            .expect("là")
            .provenance,
        Provenance::Annuaire(un(Genre::Annuaire, 0xA0))
    );
    assert_eq!(
        base.compte_par_alias("thierry").expect("lisible"),
        Some(thierry)
    );
    assert_eq!(
        base.compte_par_alias("ailleurs").expect("lisible"),
        Some(du_pair)
    );
    let machine = base.machine(grenier).expect("lisible").expect("le grenier");
    assert_eq!(machine.cle.map(|liee| liee.cle), Some([0x42; 32]));
    assert_eq!(base.machines_de_compte(thierry).expect("lisible").len(), 2);
    assert_eq!(base.appareils_de_compte(thierry).expect("lisible").len(), 1);
    assert_eq!(base.appareils_de_compte(lea).expect("lisible").len(), 1);
    assert_eq!(
        base.description(iphone)
            .expect("lisible")
            .map(|quoi| quoi.systeme),
        Some(Systeme::Ios)
    );
    assert_eq!(
        base.jeton(iphone)
            .expect("lisible")
            .map(|quoi| quoi.plateforme),
        Some(Plateforme::Apns)
    );
    assert!(
        base.jeton(pixel).expect("lisible").is_none(),
        "parti à la révocation, chez 0.10.1"
    );
    assert_eq!(base.services_de_machine(grenier).expect("lisible").len(), 2);
    assert_eq!(base.autorisations_recues(lea).expect("lisible").len(), 1);
    assert_eq!(base.autorisations_accordees(lea).expect("lisible").len(), 1);
    assert_eq!(base.entrees_du_journal().expect("lisible"), 2);
    let enrolement = base
        .consommer_enrolement(&empreinte("4K9M2P7R1T"))
        .expect("lisible")
        .expect("le code du portable est là");
    assert_eq!(enrolement.machine, portable);

    // ── LE COMPTEUR NE BOUGE PAS, LE JOURNAL D'OPÉRATIONS REPART VIDE ───────
    //
    // Ce qu'il portait est de la forme d'hier ; l'autre racine s'amorce par
    // instantané, et un rattrapage depuis moins que le compteur est refusé.
    assert_eq!(base.compteur().expect("lisible"), 19);
    assert_eq!(base.operations_gardees().expect("lisible"), 0);
    assert_eq!(
        base.operations_apres(18).expect("lisible"),
        Rattrapage::HorsJournal {
            retirees_jusqu_a: 19
        }
    );
    assert_eq!(
        base.operations_apres(19).expect("lisible"),
        Rattrapage::Operations(Vec::new())
    );
    // Et l'instantané porte la révocation du Pixel avec sa date.
    let revocations: Vec<u64> = instantane(&base)
        .into_iter()
        .filter_map(|cadre| match cadre {
            Cadre::Operation {
                operation:
                    Operation::AppareilRevoque {
                        appareil,
                        revoque_le,
                    },
                ..
            } if appareil == pixel => Some(revoque_le),
            _ => None,
        })
        .collect();
    assert_eq!(revocations, vec![quand]);

    // ── ET LA BASE REPRISE S'ÉCRIT COMME UNE NEUVE, UNE SEULE FOIS ──────────
    base.reclamer_alias(lea, Some(alias("lea"))).expect("écrit");
    assert_eq!(base.compteur().expect("lisible"), 20);
    assert_eq!(operations(&base, 19).len(), 1);
    drop(base);
    let base = Entrepot::ouvrir(&chemin, racine()).expect("rouverte");
    assert_eq!(base.dates_de_reprise(), 0, "une seule fois");
    assert_eq!(
        base.appareil(pixel)
            .expect("lisible")
            .expect("là")
            .revoque_le,
        Some(quand),
        "la date posée à la reprise ne bouge plus"
    );
    assert_eq!(base.compteur().expect("lisible"), 20);
    let _ = std::fs::remove_file(&chemin);
}

// ── L'effacement d'un compte (`modele.md` §2.1) ──────────────────────────────

/// Une date d'effacement, en millisecondes d'époque.
const EFFACE_LE: u64 = 1_790_000_000_000;

/// Un compte garni de tout ce qu'un compte peut tenir : deux appareils (l'un
/// décrit, avec un jeton), deux machines (l'une enrôlée avec deux services,
/// l'autre avec un code en attente), un alias, une autorisation accordée à
/// `autre` et une reçue de lui. Rend ce qu'il faudra ne plus trouver.
struct Garni {
    qui: Identifiant,
    autre: Identifiant,
    appareils: [Identifiant; 2],
    machines: [Identifiant; 2],
    services: [Identifiant; 2],
    code: [u8; 32],
    accordee: Identifiant,
    recue: Identifiant,
}

fn garnir_un_compte(base: &Entrepot, graine: u8) -> Garni {
    let qui = un(Genre::Utilisateur, graine);
    let autre = un(Genre::Utilisateur, graine ^ 0xFF);
    let appareils = [
        un(Genre::Appareil, graine),
        un(Genre::Appareil, graine ^ 0x0F),
    ];
    let machines = [
        un(Genre::Machine, graine),
        un(Genre::Machine, graine ^ 0x0F),
    ];
    let services = [
        un(Genre::Service, graine),
        un(Genre::Service, graine ^ 0x0F),
    ];
    let accordee = un(Genre::Autorisation, graine);
    let recue = un(Genre::Autorisation, graine ^ 0x0F);
    base.creer_compte(
        qui,
        Provenance::Ici,
        Some(alias(&format!("compte-{graine}"))),
    )
    .expect("compte");
    if base.compte(autre).expect("lisible").is_none() {
        base.creer_compte(autre, Provenance::Ici, None)
            .expect("l'autre");
    }
    for (rang, quel) in appareils.iter().enumerate() {
        base.creer_appareil(
            *quel,
            Provenance::Ici,
            qui,
            [graine; 33],
            Attestation::Aucune,
        )
        .expect("appareil");
        if rang == 0 {
            base.poser_description(*quel, Provenance::Ici, Systeme::Ios, nom("iPhone 17"))
                .expect("description");
            base.poser_jeton(
                *quel,
                Provenance::Ici,
                Plateforme::Apns,
                JetonRange::nouveau("c0ffee").unwrap(),
            )
            .expect("jeton");
        }
    }
    for quelle in machines {
        base.creer_machine(quelle, Provenance::Ici, qui, nom("machine"), TOUT)
            .expect("machine");
    }
    let code_grenier = empreinte("2K9M2P7R1T");
    base.emettre_enrolement(&code_grenier, Provenance::Ici, machines[0], u64::MAX)
        .expect("code");
    let enrolement = base.consommer_enrolement(&code_grenier).unwrap().unwrap();
    base.lier_cle(
        machines[0],
        [graine; 32],
        code_grenier,
        enrolement.estampille,
    )
    .expect("clé");
    for (rang, quel) in services.iter().enumerate() {
        base.declarer_service(
            *quel,
            Provenance::Ici,
            machines[0],
            nom(&format!("svc{rang}")),
        )
        .expect("service");
    }
    let code = empreinte("4K9M2P7R1T");
    base.emettre_enrolement(&code, Provenance::Ici, machines[1], u64::MAX)
        .expect("code en attente");
    base.accorder_autorisation(
        accordee,
        Provenance::Ici,
        qui,
        autre,
        Portee::ToutLeCompte,
        nom("à l'autre"),
    )
    .expect("accordée");
    base.accorder_autorisation(
        recue,
        Provenance::Ici,
        autre,
        qui,
        Portee::UneMachine(machines[0]),
        nom("de l'autre"),
    )
    .expect("reçue");
    Garni {
        qui,
        autre,
        appareils,
        machines,
        services,
        code,
        accordee,
        recue,
    }
}

/// Plus rien de ce que ce compte tenait n'est là — et l'autre partie ne voit
/// plus rien non plus.
fn plus_rien(base: &Entrepot, garni: &Garni) {
    for quel in garni.appareils {
        assert!(
            base.appareil(quel).expect("lisible").is_none(),
            "appareil effacé"
        );
        assert!(base.jeton(quel).expect("lisible").is_none(), "jeton effacé");
        assert!(
            base.description(quel).expect("lisible").is_none(),
            "description effacée"
        );
    }
    assert!(
        base.appareils_de_compte(garni.qui)
            .expect("lisible")
            .is_empty()
    );
    for quelle in garni.machines {
        assert!(
            base.machine(quelle).expect("lisible").is_none(),
            "machine effacée"
        );
        assert!(
            base.services_de_machine(quelle)
                .expect("lisible")
                .is_empty()
        );
    }
    assert!(
        base.machines_de_compte(garni.qui)
            .expect("lisible")
            .is_empty()
    );
    for quel in garni.services {
        assert!(
            base.service(quel).expect("lisible").is_none(),
            "service effacé"
        );
    }
    assert!(
        base.service_par_nom(garni.machines[0], "svc0")
            .expect("lisible")
            .is_none()
    );
    assert!(
        base.consommer_enrolement(&garni.code)
            .expect("lisible")
            .is_none(),
        "le code en attente est annulé"
    );
    for quelle in [garni.accordee, garni.recue] {
        assert!(
            base.autorisation(quelle).expect("lisible").is_none(),
            "arête retirée"
        );
    }
    assert!(
        base.autorisations_accordees(garni.qui)
            .expect("lisible")
            .is_empty()
    );
    assert!(
        base.autorisations_recues_nommees(garni.qui)
            .expect("lisible")
            .is_empty()
    );
    // **L'AUTRE PARTIE NE VOIT PLUS RIEN** : ni ce qu'elle avait reçu, ni ce
    // qu'elle avait accordé.
    assert!(
        base.autorisations_recues(garni.autre)
            .expect("lisible")
            .is_empty()
    );
    assert!(
        base.autorisations_accordees(garni.autre)
            .expect("lisible")
            .is_empty()
    );
    // Le compte reste, marqué, sans alias ; l'alias est libre.
    let compte = base
        .compte(garni.qui)
        .expect("lisible")
        .expect("la marque reste");
    assert!(compte.est_efface());
    assert_eq!(compte.alias, None);
    assert_eq!(
        compte.reclamation, compte.estampille,
        "la réclamation est retirée"
    );
    assert!(base.compte_vivant(garni.qui).expect("lisible").is_none());
    // Et toute écriture pour lui est refusée.
    assert!(
        !base
            .reclamer_alias(garni.qui, Some(alias("encore")))
            .expect("lisible")
    );
}

#[test]
fn effacer_un_compte_retire_tout_dans_une_transaction_et_laisse_la_marque() {
    let (base, chemin) = entrepot("effacer");
    let garni = garnir_un_compte(&base, 0x31);
    // Un autre compte réclame le même alias, en file — comme si l'autre
    // racine l'avait accepté de son côté : à l'effacement, il l'obtient.
    let en_file = un(Genre::Utilisateur, 0x77);
    base.creer_compte(en_file, Provenance::Ici, None)
        .expect("compte");
    let reclamation = base
        .appliquer(
            un(Genre::Annuaire, 0xAA),
            &Cadre::Operation {
                estampille: Estampille {
                    compteur: 1_000,
                    racine: un(Genre::Annuaire, 0xAA),
                },
                operation: Operation::Alias {
                    compte: en_file,
                    alias: Some(alias("compte-49")),
                },
            },
            false,
        )
        .expect("lisible");
    assert!(matches!(reclamation, asl_store::Applique::Faite { .. }));
    assert_eq!(
        base.compte_par_alias("compte-49").expect("lisible"),
        Some(garni.qui),
        "le plus ancien tient"
    );

    // ── L'EFFACEMENT ────────────────────────────────────────────────────────
    let operations_avant = base.operations_gardees().expect("lisible");
    let compteur_avant = base.compteur().expect("lisible");
    let efface = base
        .effacer_compte(garni.qui, Cause::Titulaire, EFFACE_LE)
        .expect("lisible")
        .expect("le compte existe");
    let Efface::Fait(retrait) = efface else {
        panic!("attendu un effacement fait : {efface:?}");
    };
    assert_eq!(
        retrait,
        Retrait {
            appareils: 2,
            machines: 2,
            codes: 1,
            services: 2,
            autorisations: 2,
            alias: true,
            a_fermer: retrait.a_fermer.clone(),
        }
    );
    let mut a_fermer = retrait.a_fermer.clone();
    a_fermer.sort();
    let mut attendus: Vec<Identifiant> = garni
        .appareils
        .iter()
        .chain(garni.machines.iter())
        .copied()
        .collect();
    attendus.sort();
    assert_eq!(
        a_fermer, attendus,
        "les machines et les appareils sont à fermer"
    );
    plus_rien(&base, &garni);
    let compte = base.compte(garni.qui).expect("lisible").expect("là");
    assert_eq!(
        compte.efface,
        Some(Effacement {
            le: EFFACE_LE,
            cause: Cause::Titulaire
        })
    );
    assert_eq!(
        compte.estampille,
        e(compteur_avant + 1),
        "une écriture, une estampille"
    );
    // L'alias est allé au compte en file.
    assert_eq!(
        base.compte_par_alias("compte-49").expect("lisible"),
        Some(en_file)
    );
    // L'autre compte, lui, est intact.
    assert!(base.compte_vivant(garni.autre).expect("lisible").is_some());

    // ── UNE SEULE OPÉRATION, POUR TOUT LE COMPTE ────────────────────────────
    assert_eq!(
        base.operations_gardees().expect("lisible"),
        operations_avant + 1
    );
    let derniere = operations(&base, compteur_avant);
    assert_eq!(
        derniere,
        vec![(
            e(compteur_avant + 1),
            Operation::CompteEfface {
                compte: garni.qui,
                efface_le: EFFACE_LE,
                cause: Cause::Titulaire,
            }
        )]
    );
    assert_eq!(base.derniere_operation(), compteur_avant + 1);
    // Et l'instantané ne porte que la marque : ni `compte`, ni `alias`, ni
    // rien de ce qu'il tenait.
    let cadres = instantane(&base);
    let sur_lui: Vec<Operation> = cadres
        .iter()
        .filter_map(|cadre| match cadre {
            Cadre::Operation { operation, .. } => Some(*operation),
            Cadre::Fin { .. } => None,
        })
        .filter(|operation| match operation {
            Operation::Compte { compte, .. }
            | Operation::Alias { compte, .. }
            | Operation::CompteEfface { compte, .. } => *compte == garni.qui,
            Operation::Appareil { enregistrement, .. } => enregistrement.proprietaire == garni.qui,
            Operation::Machine { enregistrement, .. } => enregistrement.proprietaire == garni.qui,
            Operation::Autorisation { enregistrement, .. } => {
                enregistrement.par == garni.qui || enregistrement.a == garni.qui
            }
            _ => false,
        })
        .collect();
    assert_eq!(
        sur_lui,
        vec![Operation::CompteEfface {
            compte: garni.qui,
            efface_le: EFFACE_LE,
            cause: Cause::Titulaire,
        }]
    );

    // ── UN EFFACEMENT NE SE REFAIT PAS, ET UN INCONNU N'EXISTE PAS ──────────
    assert_eq!(
        base.effacer_compte(garni.qui, Cause::Exploitant, EFFACE_LE + 1)
            .expect("lisible"),
        Some(Efface::Deja(Effacement {
            le: EFFACE_LE,
            cause: Cause::Titulaire
        }))
    );
    assert_eq!(
        base.operations_gardees().expect("lisible"),
        operations_avant + 1,
        "rien d'écrit"
    );
    assert_eq!(
        base.effacer_compte(un(Genre::Utilisateur, 0x99), Cause::Exploitant, EFFACE_LE)
            .expect("lisible"),
        None
    );
    // Et cela survit à la fermeture.
    drop(base);
    let base = Entrepot::ouvrir(&chemin, racine()).expect("rouverte");
    plus_rien(&base, &garni);
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn effacer_un_compte_venu_du_pair_ne_journalise_rien() {
    // C11 : ce qui n'est pas de provenance locale n'entre pas dans le journal
    // d'opérations — l'effacement d'un tel compte non plus. Le retrait, lui,
    // a lieu.
    let (base, chemin) = entrepot("effacer-du-pair");
    let qui = un(Genre::Utilisateur, 0x41);
    base.creer_compte(
        qui,
        Provenance::Annuaire(un(Genre::Annuaire, 7)),
        Some(alias("du-pair")),
    )
    .expect("compte");
    let avant = base.operations_gardees().expect("lisible");
    let efface = base
        .effacer_compte(qui, Cause::Exploitant, EFFACE_LE)
        .expect("lisible");
    assert!(matches!(efface, Some(Efface::Fait(_))));
    assert_eq!(base.operations_gardees().expect("lisible"), avant);
    assert!(base.compte_vivant(qui).expect("lisible").is_none());
    assert!(base.compte_par_alias("du-pair").expect("lisible").is_none());
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn la_regle_des_orphelins_efface_apres_le_delai_et_jamais_sur_le_silence() {
    // **CE QUE LA RÈGLE COMPTE** (`modele.md` §2.1, C6) : la révocation du
    // dernier appareil vivant, et rien d'autre — ni le silence, ni l'absence
    // d'appareil.
    let (base, chemin) = entrepot("orphelins");
    let jour = 24 * 60 * 60 * 1_000_u64;
    let maintenant = 1_800_000_000_000_u64;
    let seuil = maintenant - 30 * jour;

    // A : deux appareils, révoqués il y a quarante et trente et un jours.
    let a = garnir_un_compte(&base, 0x51);
    base.revoquer_appareil(a.appareils[0], maintenant - 40 * jour)
        .expect("révoqué");
    base.revoquer_appareil(a.appareils[1], maintenant - 31 * jour)
        .expect("révoqué");
    // B : un appareil révoqué il y a trente et un jours, l'autre VIVANT.
    let b = garnir_un_compte(&base, 0x52);
    base.revoquer_appareil(b.appareils[0], maintenant - 31 * jour)
        .expect("révoqué");
    // C : aucun appareil — pas de date d'où compter.
    let c = un(Genre::Utilisateur, 0x53);
    base.creer_compte(c, Provenance::Ici, None).expect("compte");
    // D : le dernier appareil révoqué hier — pas encore.
    let d = garnir_un_compte(&base, 0x54);
    base.revoquer_appareil(d.appareils[0], maintenant - 40 * jour)
        .expect("révoqué");
    base.revoquer_appareil(d.appareils[1], maintenant - jour)
        .expect("révoqué");
    // E : déjà effacé par son titulaire — pas deux fois.
    let e_ = garnir_un_compte(&base, 0x55);
    base.effacer_compte(e_.qui, Cause::Titulaire, maintenant - 2 * jour)
        .expect("lisible");
    let operations_avant = base.operations_gardees().expect("lisible");

    // ── LE PASSAGE ──────────────────────────────────────────────────────────
    let effaces = base
        .effacer_les_orphelins(seuil, maintenant)
        .expect("lisible");
    assert_eq!(effaces.len(), 1, "A, et lui seul : {effaces:?}");
    assert_eq!(effaces[0].0, a.qui);
    assert_eq!(effaces[0].1.appareils, 2);
    assert_eq!(effaces[0].1.machines, 2);
    assert_eq!(effaces[0].1.a_fermer.len(), 4);
    plus_rien(&base, &a);
    assert_eq!(
        base.compte(a.qui).expect("lisible").expect("là").efface,
        Some(Effacement {
            le: maintenant,
            cause: Cause::Orphelin
        })
    );
    // Une opération `compte-efface`, cause orphelin.
    assert_eq!(
        base.operations_gardees().expect("lisible"),
        operations_avant + 1
    );
    let compteur = base.compteur().expect("lisible");
    assert_eq!(
        operations(&base, compteur - 1),
        vec![(
            e(compteur),
            Operation::CompteEfface {
                compte: a.qui,
                efface_le: maintenant,
                cause: Cause::Orphelin,
            }
        )]
    );
    // Les autres sont intacts.
    for qui in [b.qui, c, d.qui] {
        assert!(base.compte_vivant(qui).expect("lisible").is_some(), "{qui}");
    }
    assert_eq!(base.appareils_de_compte(b.qui).expect("lisible").len(), 2);
    assert_eq!(base.appareils_de_compte(d.qui).expect("lisible").len(), 2);
    // Un second passage ne trouve rien : la règle est idempotente.
    assert!(
        base.effacer_les_orphelins(seuil, maintenant)
            .expect("lisible")
            .is_empty()
    );
    assert_eq!(
        base.operations_gardees().expect("lisible"),
        operations_avant + 1
    );
    // Trente jours plus tard, D y passe ; B jamais, tant qu'un appareil vit.
    let effaces = base
        .effacer_les_orphelins(seuil + 30 * jour, maintenant + 30 * jour)
        .expect("lisible");
    assert_eq!(
        effaces.iter().map(|(qui, _)| *qui).collect::<Vec<_>>(),
        vec![d.qui]
    );
    assert!(base.compte_vivant(b.qui).expect("lisible").is_some());
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn revoquer_un_appareil_pose_sa_date_une_fois() {
    // **UNE SEULE DATE, POSÉE UNE FOIS** : c'est d'elle que la règle des
    // orphelins compte, et une seconde révocation ne la déplace pas — ni
    // n'écrit, ni ne journalise.
    let (base, chemin) = entrepot("revoque-date");
    let qui = un(Genre::Utilisateur, 1);
    let quel = un(Genre::Appareil, 2);
    base.creer_compte(qui, Provenance::Ici, None)
        .expect("compte");
    base.creer_appareil(quel, Provenance::Ici, qui, [0x11; 33], Attestation::Aucune)
        .expect("appareil");
    let avant = base
        .revoquer_appareil(quel, REVOQUE_LE)
        .expect("lisible")
        .expect("là");
    assert_eq!(avant.revoque_le, None);
    let apres = base.appareil(quel).expect("lisible").expect("là");
    assert_eq!(apres.revoque_le, Some(REVOQUE_LE));
    let compteur = base.compteur().expect("lisible");
    let gardees = base.operations_gardees().expect("lisible");
    let encore = base
        .revoquer_appareil(quel, REVOQUE_LE + 1_000)
        .expect("lisible")
        .expect("là");
    assert_eq!(
        encore.revoque_le,
        Some(REVOQUE_LE),
        "rendu tel qu'il était : déjà révoqué"
    );
    assert_eq!(
        base.appareil(quel)
            .expect("lisible")
            .expect("là")
            .revoque_le,
        Some(REVOQUE_LE)
    );
    assert_eq!(base.compteur().expect("lisible"), compteur);
    assert_eq!(base.operations_gardees().expect("lisible"), gardees);
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn attester_un_appareil_pose_une_preuve_une_fois_et_jamais_en_arriere() {
    // **UNE CLÉ NE S'ATTESTE QU'UNE FOIS** (`replication.md` §5.2,
    // `appareil-atteste`) : `attendue` devient `android`, l'opération est
    // journalisée ; une seconde chaîne ne change rien — ni n'écrit, ni ne
    // journalise —, et `aucune` ou `attendue` ne s'écrivent pas par ce verbe.
    let (base, chemin) = entrepot("atteste");
    let qui = un(Genre::Utilisateur, 1);
    let quel = un(Genre::Appareil, 2);
    base.creer_compte(qui, Provenance::Ici, None)
        .expect("compte");
    base.creer_appareil(
        quel,
        Provenance::Ici,
        qui,
        [0x11; 33],
        Attestation::Attendue,
    )
    .expect("appareil");
    let avant = base
        .attester_appareil(quel, Attestation::Android)
        .expect("lisible")
        .expect("là");
    assert_eq!(
        avant.atteste,
        Attestation::Attendue,
        "rendu tel qu'il était"
    );
    let apres = base.appareil(quel).expect("lisible").expect("là");
    assert_eq!(apres.atteste, Attestation::Android);
    assert_eq!(apres.estampille, e(3), "une écriture de plus");
    let compteur = base.compteur().expect("lisible");
    let gardees = base.operations_gardees().expect("lisible");
    assert_eq!(
        operations(&base, 2),
        [(
            e(3),
            Operation::AppareilAtteste {
                appareil: quel,
                atteste: Attestation::Android,
            }
        )],
        "l'opération est journalisée"
    );

    let encore = base
        .attester_appareil(quel, Attestation::Apple)
        .expect("lisible")
        .expect("là");
    assert_eq!(encore.atteste, Attestation::Android, "déjà prouvé : rien");
    assert_eq!(
        base.appareil(quel).expect("lisible").expect("là").atteste,
        Attestation::Android
    );
    assert_eq!(base.compteur().expect("lisible"), compteur);
    assert_eq!(base.operations_gardees().expect("lisible"), gardees);

    for pas_une_preuve in [Attestation::Aucune, Attestation::Attendue] {
        assert!(
            matches!(
                base.attester_appareil(quel, pas_une_preuve),
                Err(Faute::Enregistrement(asl_registre::Faute::Etiquette { .. }))
            ),
            "{pas_une_preuve:?}"
        );
    }
    assert!(
        base.attester_appareil(un(Genre::Appareil, 9), Attestation::Android)
            .expect("lisible")
            .is_none(),
        "un inconnu rend rien"
    );
    let _ = std::fs::remove_file(&chemin);
}

/// L'empreinte d'un code d'invitation, pour les essais.
fn empreinte_d_invitation(graine: u8) -> [u8; asl_registre::EMPREINTE_OCTETS] {
    [graine; asl_registre::EMPREINTE_OCTETS]
}

#[test]
fn une_invitation_s_emet_se_consomme_une_fois_et_ouvre_le_compte_en_une_transaction() {
    let (base, chemin) = entrepot("invitation-aller-retour");
    let code = empreinte_d_invitation(0x1E);
    let compte = un(Genre::Utilisateur, 1);
    let appareil = un(Genre::Appareil, 1);

    // **UN CODE INCONNU N'ÉCRIT RIEN**, et c'est le même fait qu'un code
    // consommé : l'appelant en fera un `403` sans dire lequel.
    assert!(
        !base
            .creer_compte_sur_invitation(compte, appareil, [7; 33], &code, 1_000)
            .expect("lisible"),
        "un code inconnu ne crée rien"
    );
    assert!(base.compte(compte).expect("lisible").is_none());

    base.emettre_invitation(&code, Provenance::Ici, 10_000)
        .expect("émise");

    // **EXPIRÉE, C'EST LE MÊME REFUS** — et le code reste, le balayage
    // l'enlèvera.
    assert!(
        !base
            .creer_compte_sur_invitation(compte, appareil, [7; 33], &code, 10_001)
            .expect("lisible"),
        "une invitation expirée ne crée rien"
    );
    assert!(base.compte(compte).expect("lisible").is_none());

    // Vivante : le compte naît, l'appareil est enrôlé SOUS `invitation`, et le
    // code disparaît — les trois dans la même transaction.
    assert!(
        base.creer_compte_sur_invitation(compte, appareil, [7; 33], &code, 9_999)
            .expect("lisible"),
        "une invitation vivante ouvre le compte"
    );
    assert!(base.compte(compte).expect("lisible").is_some());
    assert_eq!(
        base.appareil(appareil)
            .expect("lisible")
            .expect("là")
            .atteste,
        Attestation::Invitation,
        "il entre sous invitation, et cela se garde"
    );

    // **UNE SEULE FOIS** : le même code ne rouvre rien.
    let second = un(Genre::Utilisateur, 2);
    assert!(
        !base
            .creer_compte_sur_invitation(second, un(Genre::Appareil, 2), [8; 33], &code, 9_999)
            .expect("lisible"),
        "consommer, c'est supprimer"
    );
    assert!(base.compte(second).expect("lisible").is_none());
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn l_ecrit_ne_compte_que_nos_ecritures_et_survit_au_redemarrage() {
    // ── CE QUE CET ESSAI PROUVE ─────────────────────────────────────────────
    //
    // `replication.md` §8 : `ecrit` est la dernière estampille que CETTE racine
    // a écrite elle-même. Trois choses le distinguent de ses voisins, et l'une
    // d'elles a déjà été dite de travers une fois dans le document :
    //
    // 1. **Ce n'est pas le compteur.** L'horloge de Lamport se hisse aussi sur
    //    ce qu'on REÇOIT (§4) ; `ecrit` ne bouge que sur ce qu'on écrit. Une
    //    racine qui ne fait que recevoir garde le sien immobile — c'est le cas
    //    qu'`argon` a présenté le 2026-09-19, et qui a démenti §8.
    // 2. **Ce n'est pas `derniere_operation`**, qui repart du compteur à chaque
    //    ouverture et n'en est qu'un majorant.
    // 3. **Il est rangé**, donc il vaut après un redémarrage ce qu'il valait
    //    avant.
    let (base, chemin) = entrepot("ecrit-et-redemarrage");
    assert_eq!(base.ecrit().expect("lisible"), 0, "rien n'est encore écrit");

    base.creer_compte(un(Genre::Utilisateur, 1), Provenance::Ici, None)
        .expect("une écriture à nous");
    base.creer_compte(un(Genre::Utilisateur, 2), Provenance::Ici, None)
        .expect("une seconde");
    assert_eq!(base.ecrit().expect("lisible"), 2);
    assert_eq!(base.compteur().expect("lisible"), 2);

    // Recevoir hisse l'horloge et laisse `ecrit` où il est.
    base.hisser_le_compteur(100).expect("hissé");
    assert_eq!(base.compteur().expect("lisible"), 100);
    assert_eq!(
        base.ecrit().expect("lisible"),
        2,
        "recevoir n'est pas écrire"
    );

    // Une écriture qui ne journalise rien ne le fait pas bouger non plus.
    base.poser_curseur(un(Genre::Annuaire, 2), 50)
        .expect("posé");
    assert_eq!(base.ecrit().expect("lisible"), 2);

    // Écrire de nouveau le hisse, au-dessus de l'horloge reçue.
    base.creer_compte(un(Genre::Utilisateur, 3), Provenance::Ici, None)
        .expect("une troisième");
    assert_eq!(base.ecrit().expect("lisible"), 101);

    // ── LE REDÉMARRAGE ──────────────────────────────────────────────────────
    drop(base);
    let rouverte = Entrepot::ouvrir(&chemin, racine()).expect("rouvrir");
    assert_eq!(
        rouverte.ecrit().expect("lisible"),
        101,
        "il est rangé, donc il survit"
    );
    assert_eq!(
        rouverte.derniere_operation(),
        rouverte.compteur().expect("lisible"),
        "le majorant, lui, repart du compteur — c'est pourquoi `ecrit` existe"
    );
    drop(rouverte);
    let _ = std::fs::remove_file(&chemin);
}
