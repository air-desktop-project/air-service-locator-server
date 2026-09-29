//! Les `s-…` dérivés et la migration de la 0.37.0 (`docs/annuaires.md` §2 ter ;
//! `docs/replication.md` décisions 66 et 72).
//!
//! # LA FIXTURE A ÉTÉ ÉCRITE PAR LA 0.36.0
//!
//! `tests/fixtures/entrepot-0.36.0.redb` a été écrite par le code de la
//! 0.36.0 (`290b583`), par ses propres fonctions publiques, puis compactée —
//! comme `entrepot-0.4.3.redb` l'a été par la 0.4.3. Elle porte, sous la
//! racine `[0xEE; 16]` :
//!
//! - deux comptes, `thierry` et `lea` ; deux machines de `thierry`, `grenier`
//!   (dont la clé est `CleSecrete::depuis_entropie([0x10; 32])`) et
//!   `portable` ;
//! - trois services, sous des `s-…` TIRÉS : `depot` et `imap` sur `grenier`,
//!   `ssh` sur `portable` ;
//! - deux droits `voir` au groupe personnel de `lea` : l'un sur le service
//!   `depot`, l'autre sur la machine `grenier` ;
//! - un service du pair `n-…[0xA0; 16]`, `nas` sur une machine `cave` que
//!   l'entrepôt ne connaît pas : il attend dans `services-en-attente`.

use std::path::PathBuf;

use asl_id::{Genre, Identifiant};
use asl_registre::{
    Cadre, Droit, Droits, Estampille, MachineFederee, NomRange, Operation, Provenance, Service,
    service_derive,
};
use asl_store::{Applique, Entrepot, MigrationDesIdentifiants};

/// La racine de la fixture.
fn racine() -> Identifiant {
    Identifiant::depuis_entropie(Genre::Annuaire, [0xEE; 16])
}

/// Le pair de la fixture.
fn pair() -> Identifiant {
    Identifiant::depuis_entropie(Genre::Annuaire, [0xA0; 16])
}

/// Un identifiant de la fixture, par son texte.
fn lu(texte: &str) -> Identifiant {
    Identifiant::analyser(texte).expect("bien formé")
}

/// Un nom rangé.
fn nom(texte: &str) -> NomRange {
    NomRange::nouveau(texte).expect("il tient")
}

/// Ce que la fixture tient, sous les identifiants que la 0.36.0 a frappés.
struct Fixture {
    grenier: Identifiant,
    portable: Identifiant,
    cave: Identifiant,
    depot: Identifiant,
    imap: Identifiant,
    ssh: Identifiant,
    attend: Identifiant,
    lea: Identifiant,
    sur_depot: Identifiant,
    sur_grenier: Identifiant,
}

fn fixture() -> Fixture {
    Fixture {
        grenier: lu("m-1P7N24PMJSC1KPWXBWGE59364Z"),
        portable: lu("m-2NBHHPMWBRFY38V54VMAMV1DXY"),
        cave: lu("m-3MFE18K44QKTJTSCXTR74CZNPX"),
        depot: lu("s-52N6RBFFP5SK9XNRF8XZVFT10B"),
        imap: lu("s-61S37XDQF4XFSFJ0071RAHR8SA"),
        ssh: lu("s-70WZQFBZ03188HG7S65MT3PGJ9"),
        attend: lu("s-7Z0R6H86S254R3EFJ59H9NMRB8"),
        lea: lu("u-1Y8N656PK1D1QQCZC4HE99K857"),
        sur_depot: lu("g-6RVZKEVX7V084H05RY4MP36EJ1"),
        sur_grenier: lu("g-7QZR2GR4RT44M2YDHX8H5N4PB0"),
    }
}

/// Une copie de la fixture, à nous.
fn base_de_la_0_36_0(quoi: &str) -> PathBuf {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/entrepot-0.36.0.redb");
    let copie =
        std::env::temp_dir().join(format!("asl-derivation-{}-{quoi}.redb", std::process::id()));
    let _ = std::fs::remove_file(&copie);
    std::fs::copy(&fixture, &copie).expect("la fixture se copie");
    copie
}

/// Ce que la fixture doit tenir APRÈS la migration — vérifié tel quel à la
/// première ouverture et à la seconde.
fn verifier_la_migration(base: &Entrepot, f: &Fixture) {
    let depot = service_derive(f.grenier, b"depot");
    let imap = service_derive(f.grenier, b"imap");
    let ssh = service_derive(f.portable, b"ssh");

    // ── LES SERVICES : sous leur dérivé, et plus sous l'aléa ────────────────
    for (machine, texte, derive, ancien) in [
        (f.grenier, "depot", depot, f.depot),
        (f.grenier, "imap", imap, f.imap),
        (f.portable, "ssh", ssh, f.ssh),
    ] {
        assert_eq!(
            base.service_par_nom(machine, texte).expect("lisible"),
            Some(derive),
            "{texte} : l'index nomme le dérivé"
        );
        let service = base.service(derive).expect("lisible").expect("rangé");
        assert_eq!(service.machine, machine);
        assert_eq!(service.nom.octets(), texte.as_bytes());
        // L'estampille de la déclaration ne change pas : la migration ne
        // déclare rien, elle renomme.
        assert_eq!(service.estampille.racine, racine());
        assert_eq!(
            base.service(ancien).expect("lisible"),
            None,
            "{texte} : l'aléa est parti"
        );
    }
    let du_grenier: Vec<Identifiant> = base
        .services_de_machine(f.grenier)
        .expect("lisible")
        .into_iter()
        .map(|(quel, _)| quel)
        .collect();
    assert_eq!(du_grenier.len(), 2);
    assert!(du_grenier.contains(&depot) && du_grenier.contains(&imap));

    // ── LES DROITS : celui sur le service le suit ; celui sur la machine ne
    // bouge pas ─────────────────────────────────────────────────────────────
    let droit = base
        .droit(f.sur_depot)
        .expect("lisible")
        .expect("le droit est là");
    assert_eq!(droit.element, depot, "le droit vise le dérivé");
    assert_eq!(
        base.droits_sur(depot)
            .expect("lisible")
            .into_iter()
            .map(|(quel, _)| quel)
            .collect::<Vec<_>>(),
        vec![f.sur_depot],
        "et l'index par élément aussi"
    );
    assert!(base.droits_sur(f.depot).expect("lisible").is_empty());
    assert_eq!(
        base.machine_de_l_element(depot).expect("lisible"),
        Some(f.grenier)
    );
    assert_eq!(
        base.droit(f.sur_grenier)
            .expect("lisible")
            .expect("là")
            .element,
        f.grenier
    );
    assert!(
        base.droits_recus_sur(f.lea, depot)
            .expect("lisible")
            .permettent_de_voir(),
        "lea voit toujours le dépôt"
    );

    // ── CE QUI ATTEND SA MACHINE attend toujours ────────────────────────────
    assert_eq!(base.services_en_attente().expect("lisible"), 1);
}

#[test]
fn une_base_de_la_0_36_0_migre_ses_services_une_fois() {
    let chemin = base_de_la_0_36_0("migration");
    let f = fixture();
    let base = Entrepot::ouvrir(&chemin, racine()).expect("la base de la 0.36.0 se migre");
    assert_eq!(
        base.migration_des_identifiants(),
        Some(MigrationDesIdentifiants {
            services: 3,
            reidentifies: 3,
            droits: 1,
            en_attente: 1,
        })
    );
    verifier_la_migration(&base, &f);
    drop(base);

    // **UNE FOIS** : la seconde ouverture ne migre rien, ne dit rien, et
    // trouve tout à sa place.
    let base = Entrepot::ouvrir(&chemin, racine()).expect("la base migrée se rouvre");
    assert_eq!(base.migration_des_identifiants(), None);
    verifier_la_migration(&base, &f);

    // **CE QUI ATTENDAIT SE RANGE SOUS LE DÉRIVÉ** quand sa machine arrive
    // des racines — et ne dit aucun écart : il a été re-dérivé à la migration.
    // La cave arrive des racines — l'enregistrement du grenier fait
    // l'affaire : seul l'identifiant compte ici.
    let cave = base
        .machine(f.grenier)
        .expect("lisible")
        .expect("le grenier");
    let rangement = base
        .ranger_les_machines_federees(&[MachineFederee {
            machine: f.cave,
            enregistrement: cave,
        }])
        .expect("rangée");
    assert_eq!(rangement.rejoues, 1);
    assert!(rangement.effets.reidentifies.is_empty());
    assert!(rangement.effets.remplaces.is_empty());
    let nas = service_derive(f.cave, b"nas");
    assert_eq!(
        base.service_par_nom(f.cave, "nas").expect("lisible"),
        Some(nas)
    );
    assert_eq!(base.service(f.attend).expect("lisible"), None);

    // **UNE NOUVELLE ANNONCE DÉRIVE AUSSI**, et retrouve un service existant.
    assert_eq!(
        base.service_par_nom(f.grenier, "depot").expect("lisible"),
        Some(service_derive(f.grenier, b"depot"))
    );
    assert_eq!(
        base.declarer_service(Provenance::Ici, f.grenier, nom("sauvegarde"))
            .expect("déclaré"),
        service_derive(f.grenier, b"sauvegarde")
    );
    drop(base);
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn l_instantane_d_une_base_migree_ne_porte_que_des_derives() {
    // Ce qu'un pair qui s'amorce reçoit — en 0.36.0 comme en 0.37.0 — nomme
    // les services, et les droits qui les visent, sous leur dérivé.
    let chemin = base_de_la_0_36_0("instantane");
    let f = fixture();
    let base = Entrepot::ouvrir(&chemin, racine()).expect("migrée");
    let mut services = 0_usize;
    let mut droit_sur_service = None;
    for brut in base.instantane().expect("l'instantané") {
        let (cadre, _) = Cadre::lire(&brut).expect("un cadre");
        match cadre {
            Cadre::Operation {
                operation:
                    Operation::Service {
                        service,
                        enregistrement,
                    },
                ..
            } => {
                assert_eq!(
                    service,
                    service_derive(enregistrement.machine, enregistrement.nom.octets())
                );
                services = services.saturating_add(1);
            }
            Cadre::Operation {
                operation:
                    Operation::Droit {
                        droit,
                        enregistrement,
                    },
                ..
            } if droit == f.sur_depot => droit_sur_service = Some(enregistrement.element),
            _ => {}
        }
    }
    assert_eq!(services, 3);
    assert_eq!(droit_sur_service, Some(service_derive(f.grenier, b"depot")));
    drop(base);
    let _ = std::fs::remove_file(&chemin);
}

/// Applique une opération du pair, dans le flux — au-delà du curseur que
/// la fixture tient déjà pour lui (5).
fn appliquer(base: &Entrepot, compteur: u64, operation: Operation) -> Applique {
    base.appliquer(
        pair(),
        &Cadre::Operation {
            estampille: Estampille {
                compteur: compteur.saturating_add(10),
                racine: pair(),
            },
            operation,
        },
        false,
    )
    .expect("appliquée")
}

#[test]
fn un_pair_encore_en_0_36_0_ne_dedouble_rien_et_ses_droits_trouvent_leur_service() {
    // **LA RÉPLICATION MIXTE, CÔTÉ MIGRÉ** : le pair tient encore les aléas.
    // Ses opérations nomment (a) un service que nous avions sous le MÊME aléa
    // avant de migrer — le cas d'une paire ou de deux racines qui avaient
    // convergé —, (b) un service nouveau, sous un aléa que nous n'avons jamais
    // vu. Chacun se range sous le dérivé, un seul par `(machine, nom)`, et un
    // droit qui nomme l'aléa trouve le service.
    let chemin = base_de_la_0_36_0("mixte");
    let f = fixture();
    let base = Entrepot::ouvrir(&chemin, racine()).expect("migrée");
    let depot = service_derive(f.grenier, b"depot");
    let tenu = base.service(depot).expect("lisible").expect("là");

    // (a) Le pair relivre `depot` sous l'aléa d'hier — plus ancien que le
    // nôtre : rien ne se dédouble, l'estampille la plus ancienne reste.
    let ancienne = Estampille {
        compteur: 1,
        racine: pair(),
    };
    assert!(ancienne < tenu.estampille);
    let fait = appliquer(
        &base,
        1,
        Operation::Service {
            service: f.depot,
            enregistrement: Service {
                provenance: Provenance::Ici,
                estampille: ancienne,
                machine: f.grenier,
                nom: nom("depot"),
            },
        },
    );
    let Applique::Faite { effets, .. } = fait else {
        panic!("{fait:?}");
    };
    assert_eq!(effets.reidentifies, vec![(f.depot, depot)]);
    assert!(effets.remplaces.is_empty());
    assert_eq!(
        base.services_de_machine(f.grenier).expect("lisible").len(),
        2
    );
    assert_eq!(
        base.service(depot)
            .expect("lisible")
            .expect("là")
            .estampille,
        ancienne
    );
    assert_eq!(base.service(f.depot).expect("lisible"), None);

    // Un droit du pair sur l'aléa d'hier de `depot` : la correspondance de
    // la migration le traduit.
    let lea = asl_registre::groupe_personnel(f.lea);
    let proprietaire = base
        .machine(f.grenier)
        .expect("lisible")
        .expect("là")
        .proprietaire;
    let droit_pair = Identifiant::depuis_entropie(Genre::Autorisation, [0x51; 16]);
    let droit = |element: Identifiant, compteur: u64| Operation::Droit {
        droit: droit_pair,
        enregistrement: Droit {
            provenance: Provenance::Ici,
            estampille: Estampille {
                compteur,
                racine: pair(),
            },
            par: proprietaire,
            groupe: lea,
            element,
            droits: Droits::LOCALISER,
            retire: None,
            etiquette: nom("du pair"),
        },
    };
    assert!(matches!(
        appliquer(&base, 2, droit(f.depot, 2)),
        Applique::Faite { .. }
    ));
    assert_eq!(
        base.droit(droit_pair)
            .expect("lisible")
            .expect("le droit du pair est entré")
            .element,
        depot
    );

    // (b) Un service NOUVEAU du pair, sous un aléa jamais vu, puis un droit
    // qui le nomme : l'opération `service` a appris la correspondance.
    let alea = Identifiant::depuis_entropie(Genre::Service, [0x52; 16]);
    let sauvegarde = service_derive(f.grenier, b"sauvegarde");
    let fait = appliquer(
        &base,
        3,
        Operation::Service {
            service: alea,
            enregistrement: Service {
                provenance: Provenance::Ici,
                estampille: Estampille {
                    compteur: 3,
                    racine: pair(),
                },
                machine: f.grenier,
                nom: nom("sauvegarde"),
            },
        },
    );
    let Applique::Faite { effets, .. } = fait else {
        panic!("{fait:?}");
    };
    assert_eq!(effets.reidentifies, vec![(alea, sauvegarde)]);
    assert_eq!(
        base.service_par_nom(f.grenier, "sauvegarde")
            .expect("lisible"),
        Some(sauvegarde)
    );
    let second = Identifiant::depuis_entropie(Genre::Autorisation, [0x53; 16]);
    assert!(matches!(
        appliquer(
            &base,
            4,
            Operation::Droit {
                droit: second,
                enregistrement: Droit {
                    element: alea,
                    ..match droit(alea, 4) {
                        Operation::Droit { enregistrement, .. } => enregistrement,
                        _ => unreachable!(),
                    }
                },
            }
        ),
        Applique::Faite { .. }
    ));
    assert_eq!(
        base.droit(second).expect("lisible").expect("entré").element,
        sauvegarde
    );

    // **ET CE QUI N'A JAMAIS ÉTÉ UN SERVICE** reste refusé comme avant : un
    // droit sur un `s-…` que personne ne connaît n'entre pas.
    let inconnu = Identifiant::depuis_entropie(Genre::Service, [0x54; 16]);
    let troisieme = Identifiant::depuis_entropie(Genre::Autorisation, [0x55; 16]);
    let Operation::Droit { enregistrement, .. } = droit(inconnu, 5) else {
        unreachable!()
    };
    let _ = appliquer(
        &base,
        5,
        Operation::Droit {
            droit: troisieme,
            enregistrement,
        },
    );
    assert_eq!(base.droit(troisieme).expect("lisible"), None);

    // **APRÈS LA MIGRATION DU PAIR**, ses opérations portent le dérivé : rien
    // n'est plus dit.
    let fait = appliquer(
        &base,
        6,
        Operation::Service {
            service: service_derive(f.portable, b"ssh"),
            enregistrement: Service {
                provenance: Provenance::Ici,
                estampille: Estampille {
                    compteur: 6,
                    racine: pair(),
                },
                machine: f.portable,
                nom: nom("ssh"),
            },
        },
    );
    let Applique::Faite { effets, .. } = fait else {
        panic!("{fait:?}");
    };
    assert!(effets.reidentifies.is_empty());
    assert!(effets.remplaces.is_empty());
    drop(base);
    let _ = std::fs::remove_file(&chemin);
}

#[test]
fn deux_entrepots_qui_ne_se_parlent_pas_frappent_le_meme_service() {
    // **I1 SANS AUCUN ÉCHANGE** : deux membres d'une paire — ou deux racines
    // —, chacun sa racine d'estampille, la même machine reçue des racines,
    // le même nom annoncé : le même `s-…`. Puis chacun applique l'opération
    // de l'autre : un seul service, les mêmes octets des deux côtés.
    let machine = lu("m-32Q2JXER1HTVRZQ956T7V3GE0S");
    let membres = [
        lu("n-7MSV5RPCXBZH25PQM4ZPE5X87P"),
        lu("n-4EQRD1VWYQQB1Y9C3T49Z8F8Z9"),
    ];
    let aux_racines = Estampille {
        compteur: 1,
        racine: lu("n-3K3P6H252W8K9370QG1YYTWBWB"),
    };
    let bases: Vec<Entrepot> = membres
        .iter()
        .map(|membre| {
            let base = Entrepot::en_memoire(*membre).expect("en mémoire");
            base.se_savoir_annuaire_local();
            base.ranger_les_machines_federees(&[MachineFederee {
                machine,
                enregistrement: asl_registre::Machine {
                    provenance: Provenance::Ici,
                    estampille: aux_racines,
                    proprietaire: Identifiant::depuis_entropie(Genre::Utilisateur, [1; 16]),
                    nom: nom("speedy"),
                    nom_estampille: aux_racines,
                    annonce: true,
                    lecture: true,
                    capacites_estampille: aux_racines,
                    cle: None,
                },
            }])
            .expect("reçue");
            base
        })
        .collect();
    let frappes: Vec<Identifiant> = bases
        .iter()
        .map(|base| {
            base.declarer_service(Provenance::Ici, machine, nom("essai-federation"))
                .expect("déclaré")
        })
        .collect();
    assert_eq!(frappes[0], frappes[1]);
    // Le vecteur du constat du 2026-09-28 : ce que speedy et helium rendront.
    assert_eq!(frappes[0], lu("s-7ANMGMZPJ3EGA41WA129KAJTWE"));

    // Chacun reçoit l'opération de l'autre.
    let operations: Vec<Vec<Vec<u8>>> = bases
        .iter()
        .map(|base| match base.operations_apres(0).expect("le journal") {
            asl_store::Rattrapage::Operations(cadres) => cadres,
            asl_store::Rattrapage::HorsJournal { .. } => panic!("rien d'expiré"),
        })
        .collect();
    for (rang, base) in bases.iter().enumerate() {
        let autre = 1 - rang;
        for brut in &operations[autre] {
            let (cadre, _) = Cadre::lire(brut).expect("un cadre");
            let fait = base
                .appliquer(membres[autre], &cadre, false)
                .expect("appliqué");
            let Applique::Faite { effets, .. } = fait else {
                panic!("{fait:?}");
            };
            assert!(effets.reidentifies.is_empty(), "rien à ré-identifier");
            assert!(effets.remplaces.is_empty(), "rien à remplacer");
        }
    }
    let lus: Vec<Service> = bases
        .iter()
        .map(|base| {
            assert_eq!(base.services_de_machine(machine).expect("lisible").len(), 1);
            base.service(frappes[0]).expect("lisible").expect("là")
        })
        .collect();
    assert_eq!(lus[0], lus[1], "les mêmes octets des deux côtés");
}
