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
    Appareil, Attestation, Autorisation, Cadre, Capacites, Compte, Description, Enrolement,
    Estampille, JetonPoussee, JetonRange, Machine, NomRange, Operation, Plateforme, Portee,
    Provenance, Service, Systeme,
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
        revoque: false,
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
    vec![
        (
            est(pair(), 1),
            Operation::Compte {
                compte: c1,
                enregistrement: compte(est(pair(), 1), None),
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

/// Les conflits — un par ligne de §3.2 qui se résout par une règle
/// indépendante de l'ordre. La ligne « code consommé d'un côté, présenté de
/// l'autre » n'y est pas : c'est une FENÊTRE, pas un conflit réordonnable — la
/// consommation suit toujours l'émission sur une même racine —, et
/// [`une_emission_apres_sa_consommation_reparait_le_temps_du_flux`] la couvre à
/// part.
fn conflits() -> Vec<(Estampille, Operation)> {
    let c1 = un(Genre::Utilisateur, 1);
    let c2 = un(Genre::Utilisateur, 2);
    let m1 = un(Genre::Machine, 1);
    let m3 = un(Genre::Machine, 3);
    let m4 = un(Genre::Machine, 4);
    let d1 = un(Genre::Appareil, 1);
    let d2 = un(Genre::Appareil, 2);
    vec![
        // Ligne 1 — révocation d'un côté, écriture de l'autre (appareil).
        (
            est(autre(), 100),
            Operation::AppareilRevoque { appareil: d1 },
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
    assert!(d1.revoque, "l'appareil est révoqué");
    assert!(
        base.jeton(un(Genre::Appareil, 1))
            .expect("lisible")
            .is_none(),
        "le jeton déposé pendant la fenêtre est parti avec la révocation"
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
fn ce_qui_n_est_pas_de_provenance_locale_est_refuse() {
    // C11 : la voie entre racines ne transporte que des enregistrements de
    // provenance locale (§7).
    let (base, chemin) = entrepot("provenance");
    let ailleurs = Compte {
        provenance: Provenance::Annuaire(un(Genre::Annuaire, 7)),
        estampille: est(pair(), 3),
        alias: None,
        reclamation: est(pair(), 3),
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
