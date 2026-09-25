//! L'application des opérations reçues, et l'invariant de `docs/replication.md`
//! §3.1 : **la règle de chaque cas donne le même résultat dans tous les ordres
//! d'arrivée.**
//!
//! # L'ESSAI QUI COMPTE LE PLUS DE CETTE TRANCHE
//!
//! §3.1 : « un essai qui applique un même jeu d'opérations dans tous ses ordres
//! et compare les deux entrepôts ». C'est ce que fait
//! [`l_invariant_de_convergence`] : un jeu d'opérations conflictuelles — les cas
//! de §3.2 —, appliqué dans un large échantillon de permutations plus les deux
//! ordres extrêmes, sur des entrepôts frais, et l'on compare octet pour octet ce
//! qui se réplique. Une règle qui dépendrait de qui a reçu quoi en premier ferait
//! deux annuaires qui se croient d'accord ; ici, ils le sont vraiment.
//!
//! **La comparaison se fait sur l'INSTANTANÉ** (`Entrepot::instantane`) : c'est,
//! par définition, « ce qui se réplique » — l'état entier en opérations, sous
//! leurs estampilles d'origine. Deux entrepôts qui rendent le même instantané
//! sont identiques sur tout ce qui compte entre racines.

use std::path::PathBuf;

use asl_id::{Genre, Identifiant};
use asl_registre::{
    Appareil, Attestation, Autorisation, Cadre, Capacites, Cause, Compte, Description, Effacement,
    Enrolement, Estampille, JetonPoussee, JetonRange, Machine, NomRange, Operation, Plateforme,
    PointDePoussee, PointRange, Portee, Provenance, Service, Systeme,
};
use asl_store::{Applique, Entrepot, MotifDeRefus};

/// La racine LOCALE pour laquelle les essais écrivent.
fn locale() -> Identifiant {
    Identifiant::depuis_entropie(Genre::Annuaire, [0xEE; 16])
}

/// La racine du PAIR — celle dont on tire.
fn pair() -> Identifiant {
    Identifiant::depuis_entropie(Genre::Annuaire, [0xAA; 16])
}

/// Une TROISIÈME racine : les cas de §3.2 opposent deux écritures, et un ordre
/// total sur les estampilles a besoin, à compteur égal, d'un départage par
/// racine. Deux racines distinctes le donnent.
fn autre() -> Identifiant {
    Identifiant::depuis_entropie(Genre::Annuaire, [0xBB; 16])
}

/// Un entrepôt neuf, dans un fichier à nous.
fn entrepot(quoi: &str) -> (Entrepot, PathBuf) {
    let chemin = std::env::temp_dir().join(format!(
        "asl-application-{}-{quoi}.redb",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&chemin);
    let ouvert = Entrepot::ouvrir(&chemin, locale()).expect("un entrepôt neuf");
    (ouvert, chemin)
}

/// Un identifiant de ce genre, reproductible.
fn un(genre: Genre, graine: u8) -> Identifiant {
    Identifiant::depuis_entropie(genre, [graine; 16])
}

/// Une estampille de cette racine, à ce compteur.
fn est(racine: Identifiant, compteur: u64) -> Estampille {
    Estampille { compteur, racine }
}

/// Un nom court.
fn nom(texte: &str) -> NomRange {
    NomRange::nouveau(texte).expect("un nom court se range")
}

/// Une empreinte de code, reproductible. L'entrepôt range l'empreinte toute
/// faite — trente-deux octets — et ne sait pas la calculer ; un essai n'a donc
/// qu'à en fabriquer de distinctes.
fn empreinte(graine: u8) -> [u8; 32] {
    [graine; 32]
}

/// Applique un cadre en mode instantané — la fusion, qui ne barre ni le rejeu
/// ni le recul et n'exerce donc QUE la règle de conflit (`docs/replication.md`
/// §5.4). C'est là que l'ordre d'arrivée doit devenir sans effet.
fn appliquer(base: &Entrepot, estampille: Estampille, operation: Operation) {
    match base
        .appliquer(
            pair(),
            &Cadre::Operation {
                estampille,
                operation,
            },
            true,
        )
        .expect("l'application ne refuse pas la base")
    {
        Applique::Faite { .. } => {}
        autre => panic!("un instantané n'est ni refusé ni une fin : {autre:?}"),
    }
}

// ── Les enregistrements des essais ──────────────────────────────────────────

fn compte(estampille: Estampille, alias: Option<&str>) -> Compte {
    Compte {
        provenance: Provenance::Ici,
        estampille,
        alias: alias.map(|texte| asl_registre::AliasRange::nouveau(texte).expect("un alias")),
        reclamation: estampille,
        efface: None,
    }
}

fn machine(estampille: Estampille, proprietaire: Identifiant, nom_texte: &str) -> Machine {
    Machine {
        provenance: Provenance::Ici,
        estampille,
        proprietaire,
        cle: None,
        annonce: true,
        lecture: true,
        capacites_estampille: estampille,
        nom: nom(nom_texte),
        nom_estampille: estampille,
    }
}

fn appareil(estampille: Estampille, proprietaire: Identifiant) -> Appareil {
    Appareil {
        provenance: Provenance::Ici,
        estampille,
        proprietaire,
        cle: [0x02; 33],
        atteste: Attestation::Aucune,
        revoque_le: None,
    }
}

fn autorisation(estampille: Estampille, par: Identifiant, a: Identifiant) -> Autorisation {
    Autorisation {
        provenance: Provenance::Ici,
        estampille,
        par,
        a,
        portee: Portee::ToutLeCompte,
        revoquee: false,
        etiquette: nom("accès"),
    }
}

fn service(estampille: Estampille, machine: Identifiant, nom_texte: &str) -> Service {
    Service {
        provenance: Provenance::Ici,
        estampille,
        machine,
        nom: nom(nom_texte),
    }
}

fn enrolement(estampille: Estampille, machine: Identifiant) -> Enrolement {
    Enrolement {
        provenance: Provenance::Ici,
        estampille,
        machine,
        expire_a: u64::MAX,
    }
}

// ── Le jeu d'opérations : un prélude commun, puis les conflits ──────────────

/// Le prélude : les enregistrements de base, identiques sur les deux entrepôts.
/// Il s'applique dans le MÊME ordre partout — ce ne sont pas les conflits, ce
/// sont leurs prérequis.
fn prelude() -> Vec<(Estampille, Operation)> {
    let c1 = un(Genre::Utilisateur, 1);
    let c2 = un(Genre::Utilisateur, 2);
    let m1 = un(Genre::Machine, 1);
    let m2 = un(Genre::Machine, 2);
    let m3 = un(Genre::Machine, 3);
    let m4 = un(Genre::Machine, 4);
    let d1 = un(Genre::Appareil, 1);
    let d2 = un(Genre::Appareil, 2);
    let g1 = un(Genre::Autorisation, 1);
    // Le compte que la ligne « effacement » effacera, et ce qu'il tient :
    // un alias que c4 attend en file, une machine, un appareil, une arête
    // reçue de c4.
    let c3 = un(Genre::Utilisateur, 3);
    let c4 = un(Genre::Utilisateur, 4);
    let m5 = un(Genre::Machine, 5);
    let d3 = un(Genre::Appareil, 3);
    let g2 = un(Genre::Autorisation, 2);
    vec![
        (
            est(pair(), 1),
            Operation::Compte {
                compte: c1,
                enregistrement: compte(est(pair(), 1), None),
            },
        ),
        (
            est(pair(), 10),
            Operation::Compte {
                compte: c3,
                enregistrement: compte(est(pair(), 10), Some("trois")),
            },
        ),
        (
            est(pair(), 11),
            Operation::Compte {
                compte: c4,
                enregistrement: compte(est(pair(), 11), None),
            },
        ),
        (
            est(pair(), 12),
            Operation::Machine {
                machine: m5,
                enregistrement: machine(est(pair(), 12), c3, "m5"),
            },
        ),
        (
            est(pair(), 13),
            Operation::Appareil {
                appareil: d3,
                enregistrement: appareil(est(pair(), 13), c3),
            },
        ),
        (
            est(pair(), 14),
            Operation::Autorisation {
                autorisation: g2,
                enregistrement: autorisation(est(pair(), 14), c4, c3),
            },
        ),
        (
            est(pair(), 2),
            Operation::Compte {
                compte: c2,
                enregistrement: compte(est(pair(), 2), None),
            },
        ),
        (
            est(pair(), 3),
            Operation::Machine {
                machine: m1,
                enregistrement: machine(est(pair(), 3), c1, "m1"),
            },
        ),
        (
            est(pair(), 4),
            Operation::Machine {
                machine: m2,
                enregistrement: machine(est(pair(), 4), c1, "m2"),
            },
        ),
        (
            est(pair(), 5),
            Operation::Machine {
                machine: m3,
                enregistrement: machine(est(pair(), 5), c1, "m3"),
            },
        ),
        (
            est(pair(), 6),
            Operation::Machine {
                machine: m4,
                enregistrement: machine(est(pair(), 6), c1, "m4"),
            },
        ),
        (
            est(pair(), 7),
            Operation::Appareil {
                appareil: d1,
                enregistrement: appareil(est(pair(), 7), c1),
            },
        ),
        (
            est(pair(), 8),
            Operation::Appareil {
                appareil: d2,
                enregistrement: appareil(est(pair(), 8), c1),
            },
        ),
        // Un appareil qui reste vivant : celui dont le point se dispute.
        (
            est(pair(), 10),
            Operation::Appareil {
                appareil: un(Genre::Appareil, 4),
                enregistrement: appareil(est(pair(), 10), c1),
            },
        ),
        (
            est(pair(), 9),
            Operation::Autorisation {
                autorisation: g1,
                enregistrement: autorisation(est(pair(), 9), c1, c2),
            },
        ),
        // Le code que le cas 5 (une clé de chaque côté) fera consommer deux fois.
        (
            est(pair(), 50),
            Operation::Enrolement {
                empreinte: empreinte(0x50),
                enregistrement: enrolement(est(pair(), 50), m3),
            },
        ),
    ]
}

/// Un point de poussée sous cette estampille, vers ce chemin.
fn point(estampille: Estampille, chemin: &str) -> PointDePoussee {
    PointDePoussee {
        provenance: Provenance::Ici,
        estampille,
        point: PointRange::nouveau(&format!("https://ntfy.example.org/{chemin}"))
            .expect("il tient"),
        cle: None,
        secret: None,
    }
}

/// Les conflits — un par ligne de §3.2 qui se résout par une règle
/// indépendante de l'ordre. La ligne « code consommé d'un côté, présenté de
/// l'autre » n'y est pas : c'est une FENÊTRE, pas un conflit réordonnable — la
/// consommation suit toujours l'émission sur une même racine —, et
/// [`une_emission_apres_sa_consommation_reparait_le_temps_du_flux`] la couvre à
/// part.
fn conflits() -> Vec<(Estampille, Operation)> {
    let c1 = un(Genre::Utilisateur, 1);
    let c2 = un(Genre::Utilisateur, 2);
    let c3 = un(Genre::Utilisateur, 3);
    let c4 = un(Genre::Utilisateur, 4);
    let m1 = un(Genre::Machine, 1);
    let m3 = un(Genre::Machine, 3);
    let m4 = un(Genre::Machine, 4);
    let m5 = un(Genre::Machine, 5);
    let m6 = un(Genre::Machine, 6);
    let d1 = un(Genre::Appareil, 1);
    let d2 = un(Genre::Appareil, 2);
    let d3 = un(Genre::Appareil, 3);
    let d5 = un(Genre::Appareil, 5);
    vec![
        // Ligne 1 — révocation d'un côté, écriture de l'autre (appareil).
        (
            est(autre(), 100),
            Operation::AppareilRevoque {
                appareil: d1,
                revoque_le: 1_789_000_000_000,
            },
        ),
        (
            est(pair(), 101),
            Operation::Poussee {
                appareil: d1,
                enregistrement: JetonPoussee {
                    provenance: Provenance::Ici,
                    estampille: est(pair(), 101),
                    plateforme: Plateforme::Apns,
                    jeton: JetonRange::nouveau("un-jeton").expect("un jeton"),
                },
            },
        ),
        // Le point de poussée (décision 27) — sur d1, que l'autre côté
        // révoque : refusé dans un ordre, retiré dans l'autre.
        (
            est(pair(), 140),
            Operation::PointDePoussee {
                appareil: d1,
                enregistrement: point(est(pair(), 140), "d1"),
            },
        ),
        // Sur d4, vivant, déposé des deux côtés : le plus récent gagne.
        (
            est(autre(), 141),
            Operation::PointDePoussee {
                appareil: un(Genre::Appareil, 4),
                enregistrement: point(est(autre(), 141), "ancien"),
            },
        ),
        (
            est(pair(), 142),
            Operation::PointDePoussee {
                appareil: un(Genre::Appareil, 4),
                enregistrement: point(est(pair(), 142), "neuf"),
            },
        ),
        // Sur d3, dont le compte est effacé : jamais posé, ou retiré avec lui.
        (
            est(pair(), 143),
            Operation::PointDePoussee {
                appareil: d3,
                enregistrement: point(est(pair(), 143), "d3"),
            },
        ),
        // Ligne « attesté d'un côté, révoqué de l'autre » (2026-09-21) — d1
        // prouve sa chaîne chez le pair pendant qu'`autre` le révoque : les
        // deux s'appliquent, quel que soit l'ordre, et d1 finit `android,
        // révoqué`. Une seconde attestation, Apple, ne change rien : une clé
        // ne s'atteste qu'une fois, et c'est la première appliquée qui tient
        // — ici la seule que les deux racines aient pu voir, puisqu'elles
        // convergent : Android par les deux estampilles ci-dessous.
        (
            est(pair(), 133),
            Operation::AppareilAtteste {
                appareil: d1,
                atteste: Attestation::Android,
            },
        ),
        (
            est(autre(), 134),
            Operation::AppareilAtteste {
                appareil: d1,
                atteste: Attestation::Android,
            },
        ),
        // Ligne 2 — un alias pris des deux côtés. Le plus ancien tient : c1.
        (
            est(pair(), 102),
            Operation::Alias {
                compte: c1,
                alias: Some(asl_registre::AliasRange::nouveau("depot").expect("un alias")),
            },
        ),
        (
            est(autre(), 103),
            Operation::Alias {
                compte: c2,
                alias: Some(asl_registre::AliasRange::nouveau("depot").expect("un alias")),
            },
        ),
        // Ligne 3 — un PATCH de machine des deux côtés, champ par champ.
        (
            est(pair(), 104),
            Operation::MachineModifiee {
                machine: m1,
                nom: Some(nom("alpha")),
                capacites: None,
            },
        ),
        (
            est(autre(), 105),
            Operation::MachineModifiee {
                machine: m1,
                nom: Some(nom("beta")),
                capacites: None,
            },
        ),
        (
            est(pair(), 106),
            Operation::MachineModifiee {
                machine: m1,
                nom: None,
                capacites: Some(Capacites {
                    annonce: false,
                    lecture: true,
                }),
            },
        ),
        // Ligne 5 — le même code consommé des deux côtés, deux clés pour m3.
        // À code égal, la première consommation (plus petite liaison) gagne :
        // la clé A, sous la liaison 108.
        (
            est(pair(), 108),
            Operation::CleMachine {
                machine: m3,
                cle: [0xA1; 32],
                empreinte: empreinte(0x50),
                code: est(pair(), 50),
            },
        ),
        (
            est(autre(), 109),
            Operation::CleMachine {
                machine: m3,
                cle: [0xB2; 32],
                empreinte: empreinte(0x50),
                code: est(pair(), 50),
            },
        ),
        // Ligne 6 — deux codes émis pour m4. Le plus récent gagne : le second.
        (
            est(pair(), 110),
            Operation::Enrolement {
                empreinte: empreinte(0x61),
                enregistrement: enrolement(est(pair(), 110), m4),
            },
        ),
        (
            est(autre(), 111),
            Operation::Enrolement {
                empreinte: empreinte(0x62),
                enregistrement: enrolement(est(autre(), 111), m4),
            },
        ),
        // Ligne 7 — le même service (m1, "svc") des deux côtés. Le plus ancien
        // reste : s1.
        (
            est(pair(), 112),
            Operation::Service {
                service: un(Genre::Service, 1),
                enregistrement: service(est(pair(), 112), m1, "svc"),
            },
        ),
        (
            est(autre(), 113),
            Operation::Service {
                service: un(Genre::Service, 2),
                enregistrement: service(est(autre(), 113), m1, "svc"),
            },
        ),
        // Ligne 8 — une description déposée des deux côtés sur d2. Le plus
        // récent gagne : « iPad ».
        (
            est(pair(), 114),
            Operation::Description {
                appareil: d2,
                enregistrement: Description {
                    provenance: Provenance::Ici,
                    estampille: est(pair(), 114),
                    systeme: Systeme::Ios,
                    modele: nom("iPhone"),
                },
            },
        ),
        (
            est(autre(), 115),
            Operation::Description {
                appareil: d2,
                enregistrement: Description {
                    provenance: Provenance::Ici,
                    estampille: est(autre(), 115),
                    systeme: Systeme::Ios,
                    modele: nom("iPad"),
                },
            },
        ),
        // Ligne 1 bis — d2 révoqué des deux côtés, à deux dates. La plus
        // ancienne tient : 4 000 — c'est de là que les orphelins comptent.
        (
            est(pair(), 116),
            Operation::AppareilRevoque {
                appareil: d2,
                revoque_le: 5_000,
            },
        ),
        (
            est(autre(), 117),
            Operation::AppareilRevoque {
                appareil: d2,
                revoque_le: 4_000,
            },
        ),
        // Ligne « effacement » (2026-09-18) — c3 effacé d'un côté, écrit de
        // l'autre : un appareil enrôlé, une machine déclarée, un alias
        // réclamé, une arête accordée par lui et une à lui, un service et un
        // code sur sa machine, une description et une révocation sur son
        // appareil, une clé liée. **L'effacement l'emporte toujours** : rien
        // de tout cela ne reste, et c4 obtient l'alias qu'il attendait. Deux
        // effacements — titulaire chez `autre`, orphelin chez le pair —
        // n'en font qu'un, et la marque est celle de la plus petite
        // estampille : 120, titulaire.
        (
            est(autre(), 120),
            Operation::CompteEfface {
                compte: c3,
                efface_le: 7_000,
                cause: Cause::Titulaire,
            },
        ),
        (
            est(pair(), 125),
            Operation::CompteEfface {
                compte: c3,
                efface_le: 8_000,
                cause: Cause::Orphelin,
            },
        ),
        (
            est(pair(), 121),
            Operation::Appareil {
                appareil: d5,
                enregistrement: appareil(est(pair(), 121), c3),
            },
        ),
        (
            est(autre(), 122),
            Operation::Machine {
                machine: m6,
                enregistrement: machine(est(autre(), 122), c3, "m6"),
            },
        ),
        (
            est(pair(), 123),
            Operation::Alias {
                compte: c4,
                alias: Some(asl_registre::AliasRange::nouveau("trois").expect("un alias")),
            },
        ),
        (
            est(pair(), 124),
            Operation::Alias {
                compte: c3,
                alias: Some(asl_registre::AliasRange::nouveau("encore").expect("un alias")),
            },
        ),
        (
            est(autre(), 126),
            Operation::Autorisation {
                autorisation: un(Genre::Autorisation, 3),
                enregistrement: autorisation(est(autre(), 126), c3, c4),
            },
        ),
        (
            est(pair(), 127),
            Operation::Autorisation {
                autorisation: un(Genre::Autorisation, 4),
                enregistrement: autorisation(est(pair(), 127), c1, c3),
            },
        ),
        (
            est(pair(), 128),
            Operation::Service {
                service: un(Genre::Service, 3),
                enregistrement: service(est(pair(), 128), m5, "svc"),
            },
        ),
        (
            est(autre(), 129),
            Operation::Description {
                appareil: d3,
                enregistrement: Description {
                    provenance: Provenance::Ici,
                    estampille: est(autre(), 129),
                    systeme: Systeme::Android,
                    modele: nom("Pixel"),
                },
            },
        ),
        (
            est(pair(), 130),
            Operation::Enrolement {
                empreinte: empreinte(0x30),
                enregistrement: enrolement(est(pair(), 130), m5),
            },
        ),
        (
            est(pair(), 131),
            Operation::AppareilRevoque {
                appareil: d3,
                revoque_le: 6_000,
            },
        ),
        (
            est(autre(), 132),
            Operation::CleMachine {
                machine: m5,
                cle: [0xC5; 32],
                empreinte: empreinte(0x30),
                code: est(pair(), 130),
            },
        ),
    ]
}

/// Un générateur congruentiel — pas de crate, pas d'aléa du système : un essai
/// doit rejouer EXACTEMENT la même suite de permutations à chaque exécution.
struct Melangeur(u64);

impl Melangeur {
    fn suivant(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    /// Un mélange de Fisher-Yates de ces indices.
    fn melanger(&mut self, combien: usize) -> Vec<usize> {
        let mut ordre: Vec<usize> = (0..combien).collect();
        let mut rang = combien;
        while rang > 1 {
            rang = rang.saturating_sub(1);
            let borne = u64::try_from(rang).unwrap_or(0).saturating_add(1);
            let ou = self
                .suivant()
                .checked_rem(borne)
                .and_then(|reste| usize::try_from(reste).ok())
                .unwrap_or(0);
            ordre.swap(rang, ou);
        }
        ordre
    }
}

/// Construit un entrepôt en appliquant le prélude, puis les conflits dans cet
/// ordre, et rend son instantané — « ce qui se réplique ».
fn instantane_dans_l_ordre(quoi: &str, ordre: &[usize]) -> Vec<Vec<u8>> {
    let (base, chemin) = entrepot(quoi);
    for (estampille, operation) in prelude() {
        appliquer(&base, estampille, operation);
    }
    let conflits = conflits();
    for &rang in ordre {
        let (estampille, operation) = conflits[rang];
        appliquer(&base, estampille, operation);
    }
    let instantane = base.instantane().expect("l'instantané se lit");
    let _ = std::fs::remove_file(&chemin);
    instantane
}

#[test]
fn l_invariant_de_convergence() {
    let combien = conflits().len();

    // La référence : l'ordre naturel.
    let reference = instantane_dans_l_ordre("reference", &(0..combien).collect::<Vec<_>>());

    // Les deux ordres extrêmes : direct et inversé.
    let inverse: Vec<usize> = (0..combien).rev().collect();
    assert_eq!(
        instantane_dans_l_ordre("inverse", &inverse),
        reference,
        "l'ordre inversé ne converge pas vers le même entrepôt"
    );

    // Un large échantillon de permutations : chacune doit rendre le MÊME
    // instantané, octet pour octet. Chaque permutation frappe un fichier neuf
    // et le commet opération par opération (`docs/replication.md` §5.3) — c'est
    // ce que le disque coûte —, donc l'échantillon est large sans être immense.
    let mut melangeur = Melangeur(0x5DEECE66D);
    for essai in 0..40 {
        let ordre = melangeur.melanger(combien);
        let instantane = instantane_dans_l_ordre(&format!("melange-{essai}"), &ordre);
        assert_eq!(
            instantane, reference,
            "la permutation {ordre:?} ne converge pas (essai {essai})"
        );
    }

    // Et ce vers quoi ils convergent est bien ce que les règles annoncent : on
    // reconstruit l'état depuis la référence et l'on vérifie quelques faits.
    let (base, chemin) = entrepot("verifie");
    for (estampille, operation) in prelude() {
        appliquer(&base, estampille, operation);
    }
    for (estampille, operation) in conflits() {
        appliquer(&base, estampille, operation);
    }
    // Ligne 2 : le plus ANCIEN tient l'alias.
    assert_eq!(
        base.compte_par_alias("depot").expect("lisible"),
        Some(un(Genre::Utilisateur, 1)),
        "l'alias va à la plus ancienne réclamation"
    );
    // Ligne 1 : l'appareil est révoqué, et son jeton est parti.
    let d1 = base
        .appareil(un(Genre::Appareil, 1))
        .expect("lisible")
        .expect("d1");
    assert!(d1.revoque(), "l'appareil est révoqué");
    assert!(
        base.jeton(un(Genre::Appareil, 1))
            .expect("lisible")
            .is_none(),
        "le jeton déposé pendant la fenêtre est parti avec la révocation"
    );
    // Le point : parti avec la révocation, le plus récent sur un vivant,
    // parti avec l'effacement.
    assert!(
        base.point(un(Genre::Appareil, 1))
            .expect("lisible")
            .is_none(),
        "un point sur un appareil révoqué ne tient pas"
    );
    assert_eq!(
        base.point(un(Genre::Appareil, 4))
            .expect("lisible")
            .expect("un point")
            .point
            .octets(),
        b"https://ntfy.example.org/neuf",
        "le point le plus récent gagne"
    );
    assert!(
        base.point(un(Genre::Appareil, 3))
            .expect("lisible")
            .is_none(),
        "un point sur un appareil effacé ne tient pas"
    );
    // Ligne « attesté, révoqué » : les deux faits tiennent, dans les deux
    // ordres — l'écran d'après une perte montre que la clé était attestée.
    assert_eq!(
        d1.atteste,
        Attestation::Android,
        "l'attestation est posée sur l'appareil révoqué"
    );
    // Ligne 3 : le nom le plus récent, l'annonce retirée.
    let m1 = base
        .machine(un(Genre::Machine, 1))
        .expect("lisible")
        .expect("m1");
    assert_eq!(m1.nom.octets(), b"beta", "le nom le plus récent gagne");
    assert!(!m1.annonce, "l'annonce a été retirée");
    assert!(m1.lecture, "et la lecture, gardée");
    // Ligne 5 : la clé de la première consommation.
    let m3 = base
        .machine(un(Genre::Machine, 3))
        .expect("lisible")
        .expect("m3");
    assert_eq!(
        m3.cle.map(|liee| liee.cle),
        Some([0xA1; 32]),
        "à code égal, la première consommation lie sa clé"
    );
    // Ligne 7 : le plus ancien service reste.
    assert_eq!(
        base.service_par_nom(un(Genre::Machine, 1), "svc")
            .expect("lisible"),
        Some(un(Genre::Service, 1)),
        "le service le plus ancien reste"
    );
    // Ligne 8 : la description la plus récente.
    let desc = base
        .description(un(Genre::Appareil, 2))
        .expect("lisible")
        .expect("une description");
    assert_eq!(
        desc.modele.octets(),
        b"iPad",
        "la description la plus récente gagne"
    );
    // Ligne 1 bis : la date de révocation la plus ancienne.
    assert_eq!(
        base.appareil(un(Genre::Appareil, 2))
            .expect("lisible")
            .expect("d2")
            .revoque_le,
        Some(4_000),
        "la plus ancienne des deux dates tient"
    );
    // Ligne « effacement » : c3 n'a plus rien, et reste marqué — de la
    // marque à la plus petite estampille.
    let c3 = un(Genre::Utilisateur, 3);
    let c4 = un(Genre::Utilisateur, 4);
    let marque = base.compte(c3).expect("lisible").expect("la marque reste");
    assert_eq!(
        marque.efface,
        Some(Effacement {
            le: 7_000,
            cause: Cause::Titulaire
        })
    );
    assert_eq!(marque.estampille, est(autre(), 120));
    assert_eq!(marque.alias, None);
    assert!(base.compte_vivant(c3).expect("lisible").is_none());
    assert_eq!(
        base.compte_par_alias("trois").expect("lisible"),
        Some(c4),
        "l'alias libéré va au compte en file"
    );
    assert!(base.compte_par_alias("encore").expect("lisible").is_none());
    assert!(base.appareils_de_compte(c3).expect("lisible").is_empty());
    assert!(base.machines_de_compte(c3).expect("lisible").is_empty());
    for quel in [un(Genre::Appareil, 3), un(Genre::Appareil, 5)] {
        assert!(base.appareil(quel).expect("lisible").is_none(), "{quel}");
        assert!(base.description(quel).expect("lisible").is_none(), "{quel}");
    }
    for quelle in [un(Genre::Machine, 5), un(Genre::Machine, 6)] {
        assert!(base.machine(quelle).expect("lisible").is_none(), "{quelle}");
    }
    assert!(
        base.service(un(Genre::Service, 3))
            .expect("lisible")
            .is_none()
    );
    assert!(
        base.consommer_enrolement(&empreinte(0x30))
            .expect("lisible")
            .is_none()
    );
    for quelle in [
        un(Genre::Autorisation, 2),
        un(Genre::Autorisation, 3),
        un(Genre::Autorisation, 4),
    ] {
        assert!(
            base.autorisation(quelle).expect("lisible").is_none(),
            "{quelle}"
        );
    }
    assert!(base.autorisations_recues(c4).expect("lisible").is_empty());
    assert!(
        base.autorisations_accordees(c4)
            .expect("lisible")
            .is_empty()
    );
    assert!(
        base.autorisations_accordees(un(Genre::Utilisateur, 1))
            .expect("lisible")
            .iter()
            .all(|(quelle, _)| *quelle != un(Genre::Autorisation, 4))
    );
    let _ = std::fs::remove_file(&chemin);
}

// ── Les gardes de l'application ─────────────────────────────────────────────

#[test]
fn le_flux_refuse_ce_qui_recule_et_notre_propre_racine() {
    let (base, chemin) = entrepot("gardes");
    let compte1 = un(Genre::Utilisateur, 9);

    // Une opération du pair, en mode flux : elle passe, et avance le curseur.
    let ok = base
        .appliquer(
            pair(),
            &Cadre::Operation {
                estampille: est(pair(), 5),
                operation: Operation::Compte {
                    compte: compte1,
                    enregistrement: compte(est(pair(), 5), None),
                },
            },
            false,
        )
        .expect("lisible");
    assert!(matches!(ok, Applique::Faite { curseur: 5, .. }));
    assert_eq!(base.curseur(pair()).expect("lisible"), 5);

    // Une relivraison — un compteur qui ne dépasse pas le curseur — est
    // refusée sans bruit : c'est idempotent (§5.3).
    let recule = base
        .appliquer(
            pair(),
            &Cadre::Operation {
                estampille: est(pair(), 5),
                operation: Operation::Compte {
                    compte: compte1,
                    enregistrement: compte(est(pair(), 5), None),
                },
            },
            false,
        )
        .expect("lisible");
    assert!(matches!(recule, Applique::Refusee(MotifDeRefus::Recule)));

    // Une opération qui porte NOTRE propre identifiant de racine est un rejeu.
    let rejeu = base
        .appliquer(
            pair(),
            &Cadre::Operation {
                estampille: est(locale(), 6),
                operation: Operation::Compte {
                    compte: un(Genre::Utilisateur, 10),
                    enregistrement: compte(est(locale(), 6), None),
                },
            },
            false,
        )
        .expect("lisible");
    assert!(matches!(rejeu, Applique::Refusee(MotifDeRefus::Rejeu)));

    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn un_lot_s_applique_en_une_transaction_et_rend_chaque_verdict_a_son_rang() {
    // **UN LOT EST LE GRAIN DE L'ATOMICITÉ** : `n` cadres et le curseur au
    // dernier appliqué, en une transaction. Un cadre refusé ne fait pas
    // échouer le lot ; il est rendu à son rang, et le curseur AVANCE dans le
    // lot — le cadre qui suit un refus se juge contre le curseur que le
    // précédent a posé.
    let (base, chemin) = entrepot("lot");
    let c1 = un(Genre::Utilisateur, 21);
    let c2 = un(Genre::Utilisateur, 22);
    let c3 = un(Genre::Utilisateur, 23);
    let lot = [
        Cadre::Operation {
            estampille: est(pair(), 7),
            operation: Operation::Compte {
                compte: c1,
                enregistrement: compte(est(pair(), 7), None),
            },
        },
        // Un rejeu au milieu : refusé à son rang, sans arrêter le lot.
        Cadre::Operation {
            estampille: est(locale(), 8),
            operation: Operation::Compte {
                compte: c2,
                enregistrement: compte(est(locale(), 8), None),
            },
        },
        // Et un recul CONTRE LE CURSEUR DU LOT : sept vient d'être posé par
        // le premier cadre, dans la même transaction.
        Cadre::Operation {
            estampille: est(pair(), 7),
            operation: Operation::Compte {
                compte: c2,
                enregistrement: compte(est(pair(), 7), None),
            },
        },
        Cadre::Operation {
            estampille: est(pair(), 9),
            operation: Operation::Compte {
                compte: c3,
                enregistrement: compte(est(pair(), 9), None),
            },
        },
    ];
    let verdicts = base
        .appliquer_la_suite(pair(), &lot, false)
        .expect("lisible");
    assert_eq!(verdicts.len(), 4);
    assert!(matches!(verdicts[0], Applique::Faite { curseur: 7, .. }));
    assert!(matches!(
        verdicts[1],
        Applique::Refusee(MotifDeRefus::Rejeu)
    ));
    assert!(matches!(
        verdicts[2],
        Applique::Refusee(MotifDeRefus::Recule)
    ));
    assert!(matches!(verdicts[3], Applique::Faite { curseur: 9, .. }));
    assert_eq!(base.curseur(pair()).expect("lisible"), 9);
    assert!(base.compte(c1).expect("lisible").is_some());
    assert!(
        base.compte(c2).expect("lisible").is_none(),
        "refusé deux fois"
    );
    assert!(base.compte(c3).expect("lisible").is_some());

    // En mode instantané, un lot qui finit par le cadre de fin pose le curseur
    // à la coupe — et seulement là.
    let suite = [
        Cadre::Operation {
            estampille: est(pair(), 3),
            operation: Operation::Compte {
                compte: c2,
                enregistrement: compte(est(pair(), 3), None),
            },
        },
        Cadre::Fin {
            coupe: est(pair(), 12),
        },
    ];
    let verdicts = base
        .appliquer_la_suite(pair(), &suite, true)
        .expect("lisible");
    assert!(matches!(verdicts[0], Applique::Faite { curseur: 0, .. }));
    assert!(matches!(verdicts[1], Applique::Fin { curseur: 12 }));
    assert_eq!(base.curseur(pair()).expect("lisible"), 12);
    assert!(base.compte(c2).expect("lisible").is_some());
    assert!(base.compteur().expect("lisible") >= 12);

    // Un lot vide ne fait rien, et ne rend rien.
    assert!(
        base.appliquer_la_suite(pair(), &[], false)
            .expect("lisible")
            .is_empty()
    );
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn ce_qui_n_est_pas_de_provenance_locale_est_refuse() {
    // C11 : la voie entre racines ne transporte que des enregistrements de
    // provenance locale (§7).
    let (base, chemin) = entrepot("provenance");
    let ailleurs = Compte {
        provenance: Provenance::Annuaire(un(Genre::Annuaire, 7)),
        estampille: est(pair(), 3),
        alias: None,
        reclamation: est(pair(), 3),
        efface: None,
    };
    let refus = base
        .appliquer(
            pair(),
            &Cadre::Operation {
                estampille: est(pair(), 3),
                operation: Operation::Compte {
                    compte: un(Genre::Utilisateur, 11),
                    enregistrement: ailleurs,
                },
            },
            false,
        )
        .expect("lisible");
    assert!(matches!(
        refus,
        Applique::Refusee(MotifDeRefus::HorsProvenance)
    ));
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn appliquer_avance_le_compteur_et_ferme_ce_qui_doit_l_etre() {
    let (base, chemin) = entrepot("effets");
    let m = un(Genre::Machine, 5);
    // Une machine avec une clé, appliquée depuis le pair.
    appliquer(
        &base,
        est(pair(), 3),
        Operation::Machine {
            machine: m,
            enregistrement: machine(est(pair(), 3), un(Genre::Utilisateur, 1), "m"),
        },
    );
    appliquer(
        &base,
        est(pair(), 4),
        Operation::CleMachine {
            machine: m,
            cle: [0xC3; 32],
            empreinte: [0; 32],
            code: est(pair(), 2),
        },
    );
    // Le compteur s'est hissé au-dessus de ce qu'on a reçu (§4).
    assert!(base.compteur().expect("lisible") >= 4);

    // Révoquer la clé ferme les connexions de cette machine ici (§3.3).
    let applique = base
        .appliquer(
            pair(),
            &Cadre::Operation {
                estampille: est(pair(), 5),
                operation: Operation::CleMachineRevoquee {
                    machine: m,
                    cle: [0xC3; 32],
                },
            },
            false,
        )
        .expect("lisible");
    match applique {
        Applique::Faite { effets, .. } => {
            assert_eq!(
                effets.a_fermer,
                vec![m],
                "une clé révoquée ferme sa machine ici"
            )
        }
        autre => panic!("attendu appliquée : {autre:?}"),
    }
    // La clé est partie.
    assert!(
        base.machine(m).expect("lisible").expect("m").cle.is_none(),
        "la clé révoquée s'efface"
    );
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn appliquer_un_effacement_ferme_ce_que_le_compte_tenait_et_marque_un_inconnu() {
    // §3.3 : la racine qui applique `compte-efface` ferme ICI les connexions
    // des machines et appareils du compte — un daemon qui tenait son bail
    // chez elle part par le chemin ordinaire.
    let (base, chemin) = entrepot("efface-effets");
    let c = un(Genre::Utilisateur, 7);
    let m = un(Genre::Machine, 7);
    let d = un(Genre::Appareil, 7);
    appliquer(
        &base,
        est(pair(), 1),
        Operation::Compte {
            compte: c,
            enregistrement: compte(est(pair(), 1), Some("sept")),
        },
    );
    appliquer(
        &base,
        est(pair(), 2),
        Operation::Machine {
            machine: m,
            enregistrement: machine(est(pair(), 2), c, "m"),
        },
    );
    appliquer(
        &base,
        est(pair(), 3),
        Operation::Appareil {
            appareil: d,
            enregistrement: appareil(est(pair(), 3), c),
        },
    );
    let applique = base
        .appliquer(
            pair(),
            &Cadre::Operation {
                estampille: est(pair(), 4),
                operation: Operation::CompteEfface {
                    compte: c,
                    efface_le: 9_000,
                    cause: Cause::Titulaire,
                },
            },
            false,
        )
        .expect("lisible");
    match applique {
        Applique::Faite { effets, .. } => {
            let mut a_fermer = effets.a_fermer;
            a_fermer.sort();
            let mut attendus = vec![m, d];
            attendus.sort();
            assert_eq!(a_fermer, attendus, "la machine et l'appareil du compte");
        }
        autre => panic!("attendu appliquée : {autre:?}"),
    }
    assert!(base.compte_vivant(c).expect("lisible").is_none());
    assert!(base.compte_par_alias("sept").expect("lisible").is_none());
    // Un second effacement du même compte ne ferme plus rien : il n'y a plus
    // rien à retirer.
    let encore = base
        .appliquer(
            pair(),
            &Cadre::Operation {
                estampille: est(pair(), 5),
                operation: Operation::CompteEfface {
                    compte: c,
                    efface_le: 9_500,
                    cause: Cause::Orphelin,
                },
            },
            false,
        )
        .expect("lisible");
    assert!(matches!(encore, Applique::Faite { effets, .. } if effets.a_fermer.is_empty()));
    assert_eq!(
        base.compte(c).expect("lisible").expect("là").efface,
        Some(Effacement {
            le: 9_000,
            cause: Cause::Titulaire
        }),
        "la marque de la plus petite estampille reste"
    );

    // **UN COMPTE INCONNU EST MARQUÉ QUAND MÊME** (§5.2) : son `compte`, qui
    // arrive après, est refusé — sans alias à l'index, sans rien.
    let inconnu = un(Genre::Utilisateur, 8);
    appliquer(
        &base,
        est(pair(), 6),
        Operation::CompteEfface {
            compte: inconnu,
            efface_le: 9_600,
            cause: Cause::Exploitant,
        },
    );
    let marque = base.compte(inconnu).expect("lisible").expect("marqué");
    assert_eq!(
        marque.efface,
        Some(Effacement {
            le: 9_600,
            cause: Cause::Exploitant
        })
    );
    appliquer(
        &base,
        est(pair(), 7),
        Operation::Compte {
            compte: inconnu,
            enregistrement: compte(est(pair(), 7), Some("huit")),
        },
    );
    assert!(base.compte_vivant(inconnu).expect("lisible").is_none());
    assert!(base.compte_par_alias("huit").expect("lisible").is_none());
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn une_emission_apres_sa_consommation_reparait_le_temps_du_flux() {
    // §3.2, ligne 4 : « un code consommé est supprimé partout dès que la
    // consommation est répliquée ; entre-temps, l'autre racine ne peut pas
    // refuser ce qu'elle ne sait pas ». Ce n'est PAS un conflit réordonnable —
    // sur une même racine la consommation suit l'émission —, et l'ordre
    // d'arrivée entre racines n'est qu'une fenêtre. On le montre plutôt que de
    // le cacher : appliqués dans l'ordre naturel (émission, puis consommation),
    // le code disparaît.
    let (base, chemin) = entrepot("fenetre");
    let m = un(Genre::Machine, 6);
    appliquer(
        &base,
        est(pair(), 3),
        Operation::Machine {
            machine: m,
            enregistrement: machine(est(pair(), 3), un(Genre::Utilisateur, 1), "m"),
        },
    );
    let emp = empreinte(0x70);
    appliquer(
        &base,
        est(pair(), 4),
        Operation::Enrolement {
            empreinte: emp,
            enregistrement: enrolement(est(pair(), 4), m),
        },
    );
    // La consommation retire le code et lie la clé.
    appliquer(
        &base,
        est(pair(), 5),
        Operation::CleMachine {
            machine: m,
            cle: [0xD4; 32],
            empreinte: emp,
            code: est(pair(), 4),
        },
    );
    assert!(
        base.consommer_enrolement(&emp).expect("lisible").is_none(),
        "le code consommé n'est plus là"
    );
    assert_eq!(
        base.machine(m)
            .expect("lisible")
            .expect("m")
            .cle
            .map(|liee| liee.cle),
        Some([0xD4; 32]),
        "la clé est liée"
    );
    let _ = std::fs::remove_file(&chemin);
}

// ── Les invitations (décision 26) ───────────────────────────────────────────

/// L'empreinte d'un code d'invitation, reproductible.
fn code(graine: u8) -> [u8; asl_registre::EMPREINTE_OCTETS] {
    [graine; asl_registre::EMPREINTE_OCTETS]
}

/// Une invitation telle qu'elle voyage : **de provenance locale**, C11 ne
/// laissant passer que cela entre racines (§7). C'est l'entrepôt qui la
/// marquera comme reçue.
fn invitation(estampille: Estampille, expire_a: u64) -> asl_registre::Invitation {
    asl_registre::Invitation {
        provenance: Provenance::Ici,
        estampille,
        expire_a,
    }
}

#[test]
fn une_invitation_consommee_avant_d_etre_connue_ne_ressuscite_pas() {
    // **L'ORDRE D'ARRIVÉE NE DOIT RIEN CHANGER** (`replication.md` §5.4) :
    // `invitation-consommee` peut précéder `invitation` — deux tables, un
    // amorçage, aucun ordre garanti entre elles. Dans les DEUX ordres, le code
    // doit finir absent : un code dépensé ne revit pas.
    let (base, chemin) = entrepot("invitation-hors-ordre");
    let quel = code(0x2E);

    // Ordre « à l'envers » : la consommation d'abord.
    appliquer(
        &base,
        est(pair(), 4),
        Operation::InvitationConsommee { empreinte: quel },
    );
    appliquer(
        &base,
        est(pair(), 3),
        Operation::Invitation {
            empreinte: quel,
            enregistrement: invitation(est(pair(), 3), 10_000),
        },
    );

    // Le code ne doit ouvrir aucun compte : il a été dépensé chez le pair.
    assert!(
        !base
            .creer_compte_sur_invitation(
                un(Genre::Utilisateur, 1),
                un(Genre::Appareil, 1),
                [7; 33],
                &quel,
                1_000,
            )
            .expect("lisible"),
        "une émission arrivée en retard ne ressuscite pas un code consommé"
    );
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn une_invitation_s_applique_une_fois_et_ne_se_prolonge_pas() {
    // **INSÉRER SI ABSENTE** (§5.2) : une émission rejouée — un amorçage qui
    // repasse — ne doit pas réécrire l'expiration. Sans quoi un instantané
    // prolongerait des codes en vol.
    let (base, chemin) = entrepot("invitation-rejouee");
    let quel = code(0x4E);

    appliquer(
        &base,
        est(pair(), 3),
        Operation::Invitation {
            empreinte: quel,
            enregistrement: invitation(est(pair(), 3), 5_000),
        },
    );
    // La même, rejouée avec une expiration PLUS LOINTAINE : elle ne prend pas.
    appliquer(
        &base,
        est(pair(), 3),
        Operation::Invitation {
            empreinte: quel,
            enregistrement: invitation(est(pair(), 3), 90_000),
        },
    );

    // À 6 000, la première expiration est passée : si le rejeu l'avait
    // prolongée, le compte s'ouvrirait.
    assert!(
        !base
            .creer_compte_sur_invitation(
                un(Genre::Utilisateur, 1),
                un(Genre::Appareil, 1),
                [7; 33],
                &quel,
                6_000,
            )
            .expect("lisible"),
        "un rejeu ne prolonge pas un code en vol"
    );
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn deux_comptes_sur_un_code_vivent_tous_les_deux() {
    // **DÉCISION 26** : un même code consommé des deux côtés de la fenêtre
    // donne deux comptes, et on ne les départage PAS. Quand la consommation de
    // l'autre racine arrive, le compte ouvert ici reste entier — un effacement
    // automatique déclenché par une course serait une arme.
    let (base, chemin) = entrepot("invitation-deux-comptes");
    let quel = code(0x3E);
    let ici = un(Genre::Utilisateur, 1);
    let appareil = un(Genre::Appareil, 1);

    base.emettre_invitation(&quel, Provenance::Ici, 10_000)
        .expect("émise");
    assert!(
        base.creer_compte_sur_invitation(ici, appareil, [7; 33], &quel, 1_000)
            .expect("lisible"),
        "notre compte s'ouvre"
    );

    appliquer(
        &base,
        est(pair(), 9),
        Operation::InvitationConsommee { empreinte: quel },
    );

    assert!(
        base.compte(ici).expect("lisible").is_some(),
        "aucune règle de conflit n'efface un compte"
    );
    assert_eq!(
        base.appareil(appareil)
            .expect("lisible")
            .expect("là")
            .atteste,
        Attestation::Invitation,
        "et il reste entré sous invitation"
    );
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn un_instantane_rend_nos_propres_estampilles_et_l_ecrit_les_compte() {
    // ── CE QUE CET ESSAI PROUVE ─────────────────────────────────────────────
    //
    // `replication.md` §5.4 : un instantané rend les estampilles d'origine, **y
    // compris les nôtres** — c'est le seul chemin par lequel nos écritures nous
    // reviennent quand notre journal ne les porte plus. Elles comptent donc pour
    // `ecrit` (§8).
    //
    // Sans cela, une racine amorcée dirait n'avoir jamais rien écrit ; son pair,
    // qui compare son curseur à ce nombre, conclurait qu'il lui manque quelque
    // chose alors qu'il a tout — et l'exploitant chercherait une panne qui
    // n'existe pas.
    let (base, chemin) = entrepot("instantane-ecrit");
    assert_eq!(base.ecrit().expect("lisible"), 0);

    // Ce qui vient du pair ne compte pas pour nous, si haut soit-il.
    let leur = est(pair(), 90);
    appliquer(
        &base,
        leur,
        Operation::Compte {
            compte: un(Genre::Utilisateur, 90),
            enregistrement: compte(leur, None),
        },
    );
    assert_eq!(
        base.ecrit().expect("lisible"),
        0,
        "l'écriture d'un autre n'est pas la nôtre"
    );

    // Une estampille À NOUS, revenue par l'instantané : elle compte.
    let notre = est(locale(), 42);
    appliquer(
        &base,
        notre,
        Operation::Compte {
            compte: un(Genre::Utilisateur, 42),
            enregistrement: compte(notre, None),
        },
    );
    assert_eq!(
        base.ecrit().expect("lisible"),
        42,
        "nos écritures nous reviennent, et restent les nôtres"
    );

    // Une plus ancienne ne le fait pas reculer : c'est un `max`, et un
    // instantané ne promet pas l'ordre.
    let ancienne = est(locale(), 7);
    appliquer(
        &base,
        ancienne,
        Operation::Compte {
            compte: un(Genre::Utilisateur, 7),
            enregistrement: compte(ancienne, None),
        },
    );
    assert_eq!(base.ecrit().expect("lisible"), 42, "il ne recule jamais");

    drop(base);
    let _ = std::fs::remove_file(&chemin);
}
