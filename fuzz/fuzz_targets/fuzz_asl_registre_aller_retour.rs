//! **Cible : les enregistrements durables** — des octets quelconques vers un
//! enregistrement, et retour.
//!
//! # POURQUOI CELLE-CI, ALORS QUE CES OCTETS SONT LES NÔTRES
//!
//! C'est l'objection qu'il faut traiter d'emblée : rien de ce que ce codec relit
//! ne vient du réseau. Un attaquant ne choisit pas ces octets.
//!
//! **Il y a pourtant deux sources de désordre, et la seconde est la pire.**
//!
//!   1. **Un disque qui ment**, un fichier tronqué, un secteur retourné. C'est
//!      rare, et c'est le cas qu'on imagine.
//!   2. **Une version future relue par une version ancienne.** Celui-là n'est
//!      pas rare du tout : il arrive à chaque retour arrière de déploiement. Un
//!      champ ajouté demain sera lu par le binaire d'hier, et il faut qu'il soit
//!      REFUSÉ plutôt qu'interprété de travers.
//!
//! Et surtout : **une faute d'encodage ne se voit pas.** Un codec réseau se
//! rattrape à la connexion suivante ; celui-ci écrit sur un disque, et rend un
//! enregistrement faux durablement.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, sur n'importe quels octets.
//! 2. **CE QUI SE RELIT SE RÉÉCRIT OCTET POUR OCTET.** C'est la propriété
//!    centrale, et elle est plus forte qu'un simple aller-retour de VALEURS :
//!    les octets eux-mêmes doivent revenir identiques.
//!
//!    **C'est cette cible qui l'a obtenue.** Elle ne tenait pas : l'écriture
//!    mettait le bourrage à zéro, la lecture l'ignorait, et deux suites d'octets
//!    différentes rendaient donc la même valeur. Coût : un encodage non
//!    canonique, un canal caché dans le bourrage, et surtout un enregistrement
//!    d'une version FUTURE relu en silence par une version ancienne, amputé et
//!    se croyant entier. `asl_registre::Faute::Bourrage` ferme les trois.
//! 3. **CE QUI S'ÉCRIT SE RELIT.** L'autre sens, depuis des valeurs construites :
//!    il attrape ce qu'un aller-retour depuis des octets ne peut pas atteindre.
//! 4. **UN REFUS EST TOUJOURS L'UNE DES FAUTES NOMMÉES**, jamais une panique
//!    ni un enregistrement à moitié lu.
//! 5. **UNE OPÉRATION EST UN CADRE, ET LE CADRE SE RELIT** — depuis des octets
//!    quelconques (rien ne panique, et ce qui se relit se réécrit à
//!    l'identique, sur exactement les octets que le genre annonce), et depuis
//!    des valeurs construites. C'est ce que l'autre racine tirera sur le fil
//!    (`docs/replication.md` §5), et **le fil ne porte aucune longueur** : le
//!    genre dit tout, et une tranche trop courte est refusée, jamais devinée.
//! 6. **UN CADRE EST UNE OPÉRATION OU LA FIN D'UN INSTANTANÉ, ET JAMAIS LES
//!    DEUX.** `Cadre::lire` relit exactement ce qu'`Operation::lire` relit, sur
//!    les mêmes octets, et reconnaît la fin — que `Operation::lire` refuse —
//!    sans jamais la prendre pour une opération. Ce qui applique ne verra donc
//!    jamais un signal de coupe comme un fait.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asl_id::{Genre, Identifiant};
use asl_registre::{
    ALIAS_OCTETS_MAX, APPAREIL_OCTETS, AUTORISATION_OCTETS, AliasRange, Appareil, Attestation,
    Autorisation, CADRE_DE_FIN_OCTETS, COMPTE_OCTETS, Cadre, Capacites, CleLiee, Compte,
    DESCRIPTION_OCTETS, Description, ENROLEMENT_OCTETS, ENTREE_OCTETS, ETIQUETTE_DE_FIN,
    Enrolement, EntreeJournal, Estampille, Faute, MACHINE_OCTETS, Machine, NOM_OCTETS_MAX,
    NomRange, OPERATION_OCTETS_MAX, Operation, Portee, Provenance, SERVICE_OCTETS, Service,
    Systeme, Verdict,
};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree {
    /// Les octets d'un compte.
    compte: [u8; COMPTE_OCTETS],
    /// Les octets d'une machine.
    machine: [u8; MACHINE_OCTETS],
    /// Les octets d'une entrée de journal.
    journal: [u8; ENTREE_OCTETS],
    /// Les octets d'un service.
    service_brut: [u8; SERVICE_OCTETS],
    /// Les octets d'une autorisation.
    autorisation: [u8; AUTORISATION_OCTETS],
    /// Quelle portée construire, pour l'autre sens.
    quelle_portee: u8,
    /// De quoi construire des valeurs, pour l'autre sens.
    graine: u8,
    /// Un alias quelconque.
    alias: String,
    /// Un nom de service quelconque.
    service: String,
    /// Un nom de machine quelconque.
    nom_de_machine: String,
    /// Les octets d'un appareil.
    appareil: [u8; APPAREIL_OCTETS],
    /// Les octets d'un enrôlement.
    enrolement: [u8; ENROLEMENT_OCTETS],
    /// Les octets d'une description d'appareil.
    description: [u8; DESCRIPTION_OCTETS],
    /// Le verdict, choisi parmi trois.
    verdict: u8,
    /// L'instant.
    quand: u64,
    /// Le rang.
    rang: u64,
    /// La provenance est-elle distante ?
    distante: bool,
    /// Les octets d'une opération — un cadre, et ce qui le suit.
    operation: Vec<u8>,
    /// Le compteur d'une estampille.
    compteur: u64,
    /// Quelle opération construire, pour l'autre sens.
    quelle_operation: u8,
}

/// Une faute d'enregistrement est toujours l'une des cinq, et jamais une
/// panique. `Tronquee` n'en fait pas partie : un enregistrement se lit dans un
/// tableau de sa taille, et ne peut pas l'être.
fn nommee(faute: Faute) {
    assert!(matches!(
        faute,
        Faute::Etiquette { .. }
            | Faute::Genre { .. }
            | Faute::Longueur { .. }
            | Faute::Bourrage
            | Faute::NonImprimable { .. }
    ));
}

fuzz_target!(|entree: Entree| {
    // ── PROPRIÉTÉ 2 : ce qui se relit se réécrit à l'identique ──────────────
    match Compte::lire(&entree.compte) {
        Ok(compte) => {
            let mut refait = [0_u8; COMPTE_OCTETS];
            compte.ecrire(&mut refait);
            assert_eq!(
                refait, entree.compte,
                "un compte relu ne se réécrit pas octet pour octet"
            );
            assert_eq!(Compte::lire(&refait), Ok(compte));
        }
        Err(faute) => nommee(faute),
    }

    match Appareil::lire(&entree.appareil) {
        Ok(appareil) => {
            let mut refait = [0_u8; APPAREIL_OCTETS];
            appareil.ecrire(&mut refait);
            assert_eq!(
                refait, entree.appareil,
                "un appareil relu ne se réécrit pas octet pour octet"
            );
            assert_eq!(Appareil::lire(&refait), Ok(appareil));
        }
        Err(faute) => nommee(faute),
    }

    match Enrolement::lire(&entree.enrolement) {
        Ok(enrolement) => {
            let mut refait = [0_u8; ENROLEMENT_OCTETS];
            enrolement.ecrire(&mut refait);
            assert_eq!(
                refait, entree.enrolement,
                "un enrôlement relu ne se réécrit pas octet pour octet"
            );
            assert_eq!(Enrolement::lire(&refait), Ok(enrolement));
        }
        Err(faute) => nommee(faute),
    }

    match Description::lire(&entree.description) {
        Ok(description) => {
            let mut refait = [0_u8; DESCRIPTION_OCTETS];
            description.ecrire(&mut refait);
            assert_eq!(
                refait, entree.description,
                "une description relue ne se réécrit pas octet pour octet"
            );
            assert_eq!(Description::lire(&refait), Ok(description));
        }
        Err(faute) => nommee(faute),
    }

    match Machine::lire(&entree.machine) {
        Ok(machine) => {
            let mut refait = [0_u8; MACHINE_OCTETS];
            machine.ecrire(&mut refait);
            assert_eq!(
                refait, entree.machine,
                "une machine relue ne se réécrit pas octet pour octet"
            );
            assert_eq!(Machine::lire(&refait), Ok(machine));
        }
        Err(faute) => nommee(faute),
    }

    match EntreeJournal::lire(&entree.journal) {
        Ok(journalisee) => {
            let mut refait = [0_u8; ENTREE_OCTETS];
            journalisee.ecrire(&mut refait);
            assert_eq!(
                refait, entree.journal,
                "une entrée relue ne se réécrit pas octet pour octet"
            );
            assert_eq!(EntreeJournal::lire(&refait), Ok(journalisee));
            // **L'ORDRE DES CLÉS EST L'ORDRE DU TEMPS**, quoi qu'on ait lu.
            // C'est ce qui rend l'expiration de C18 exprimable.
            let tot = journalisee.clef(entree.rang);
            let mut plus_tard = journalisee;
            plus_tard.quand = journalisee.quand.saturating_add(1);
            assert!(
                tot < plus_tard.clef(entree.rang) || journalisee.quand == u64::MAX,
                "l'horodatage n'ordonne pas les clés"
            );
        }
        Err(faute) => nommee(faute),
    }

    match Service::lire(&entree.service_brut) {
        Ok(service) => {
            let mut refait = [0_u8; SERVICE_OCTETS];
            service.ecrire(&mut refait);
            assert_eq!(
                refait, entree.service_brut,
                "un service relu ne se réécrit pas octet pour octet"
            );
            assert_eq!(Service::lire(&refait), Ok(service));
        }
        Err(faute) => nommee(faute),
    }

    match Autorisation::lire(&entree.autorisation) {
        Ok(autorisation) => {
            let mut refait = [0_u8; AUTORISATION_OCTETS];
            autorisation.ecrire(&mut refait);
            assert_eq!(
                refait, entree.autorisation,
                "une autorisation relue ne se réécrit pas octet pour octet"
            );
            assert_eq!(Autorisation::lire(&refait), Ok(autorisation));
            // **UNE AUTORISATION NE S'ACCORDE JAMAIS À SOI-MÊME.** Le registre
            // ne l'impose pas — c'est `asl_auth::Autorisation::nouvelle` qui le
            // fait —, mais une paire identique relue serait le signe qu'un
            // enregistrement a franchi cette règle.
            let _ = (autorisation.par, autorisation.a);
        }
        Err(faute) => nommee(faute),
    }

    // ── PROPRIÉTÉ 3 : ce qui s'écrit se relit ───────────────────────────────
    let provenance = if entree.distante {
        Provenance::Annuaire(Identifiant::depuis_entropie(
            Genre::Annuaire,
            [entree.graine; 16],
        ))
    } else {
        Provenance::Ici
    };
    // **L'ESTAMPILLE EST UNE HORLOGE DE LAMPORT** : un compteur et une racine,
    // et rien d'autre ne la contraint. Tout compteur est une estampille.
    let estampille = Estampille {
        compteur: entree.compteur,
        racine: Identifiant::depuis_entropie(Genre::Annuaire, [entree.graine ^ 0x5A; 16]),
    };

    if let Ok(alias) = AliasRange::nouveau(&entree.alias) {
        assert!(alias.longueur() <= ALIAS_OCTETS_MAX);
        let compte = Compte {
            provenance,
            estampille,
            alias: Some(alias),
            reclamation: Estampille {
                compteur: entree.quand,
                ..estampille
            },
        };
        let mut octets = [0_u8; COMPTE_OCTETS];
        compte.ecrire(&mut octets);
        assert_eq!(Compte::lire(&octets), Ok(compte));
    }

    if let Ok(service) = NomRange::nouveau(&entree.service) {
        assert!(service.longueur() <= NOM_OCTETS_MAX);
        let verdict = match entree.verdict % 3 {
            0 => Verdict::Servi,
            1 => Verdict::Refuse,
            _ => Verdict::Introuvable,
        };
        let journalisee = EntreeJournal {
            quand: entree.quand,
            demandeur: Identifiant::depuis_entropie(Genre::Machine, [entree.graine; 16]),
            visee: Identifiant::depuis_entropie(Genre::Machine, [entree.graine ^ 0xFF; 16]),
            service,
            verdict,
            provenance,
        };
        let mut octets = [0_u8; ENTREE_OCTETS];
        journalisee.ecrire(&mut octets);
        assert_eq!(EntreeJournal::lire(&octets), Ok(journalisee));
    }

    if let Ok(nom) = NomRange::nouveau(&entree.service) {
        let service = Service {
            provenance,
            estampille,
            machine: Identifiant::depuis_entropie(Genre::Machine, [entree.graine; 16]),
            nom,
        };
        let mut octets = [0_u8; SERVICE_OCTETS];
        service.ecrire(&mut octets);
        assert_eq!(Service::lire(&octets), Ok(service));
    }

    let portee = match entree.quelle_portee % 3 {
        0 => Portee::ToutLeCompte,
        1 => Portee::UneMachine(Identifiant::depuis_entropie(
            Genre::Machine,
            [entree.graine; 16],
        )),
        _ => Portee::UnService(Identifiant::depuis_entropie(
            Genre::Service,
            [entree.graine; 16],
        )),
    };
    let autorisation = Autorisation {
        provenance,
        estampille,
        par: Identifiant::depuis_entropie(Genre::Utilisateur, [entree.graine; 16]),
        a: Identifiant::depuis_entropie(Genre::Utilisateur, [entree.graine ^ 0xFF; 16]),
        portee,
        revoquee: entree.graine & 4 != 0,
        // **L'ÉTIQUETTE EST DU TEXTE LIBRE**, comme un nom de machine : ce qui
        // est éprouvé ici est son RANGEMENT, le refus se prend dans `asl-api`.
        etiquette: match NomRange::nouveau(&entree.nom_de_machine) {
            Ok(etiquette) => etiquette,
            Err(_) => return,
        },
    };
    let mut octets = [0_u8; AUTORISATION_OCTETS];
    autorisation.ecrire(&mut octets);
    assert_eq!(Autorisation::lire(&octets), Ok(autorisation));

    let machine = Machine {
        provenance,
        estampille,
        proprietaire: Identifiant::depuis_entropie(Genre::Utilisateur, [entree.graine; 16]),
        // **LES DEUX ÉTATS D'UNE CLÉ**, et le second n'est pas cosmétique : une
        // machine déclarée et pas encore enrôlée n'en a pas, et l'absence doit
        // faire l'aller-retour aussi bien que la présence.
        cle: (entree.graine & 8 != 0).then_some(CleLiee {
            cle: [entree.graine; 32],
            liaison: estampille,
            code: Estampille {
                compteur: entree.quand,
                ..estampille
            },
        }),
        annonce: entree.graine & 1 != 0,
        lecture: entree.graine & 2 != 0,
        capacites_estampille: estampille,
        // **UN NOM DE MACHINE EST DU TEXTE LIBRE**, donc n'importe quelle suite
        // d'octets valides en UTF-8 et assez courte. Le refus se prend ailleurs
        // (`asl-api`) ; ce qui est éprouvé ici est le RANGEMENT.
        nom: match NomRange::nouveau(&entree.nom_de_machine) {
            Ok(nom) => nom,
            Err(_) => return,
        },
        nom_estampille: Estampille {
            compteur: entree.rang,
            ..estampille
        },
    };
    let mut octets = [0_u8; MACHINE_OCTETS];
    machine.ecrire(&mut octets);
    assert_eq!(Machine::lire(&octets), Ok(machine));

    // ── L'APPAREIL ET LE CODE D'ENRÔLEMENT ──────────────────────────────────
    let atteste = match entree.graine % 3 {
        0 => Attestation::Aucune,
        1 => Attestation::Apple,
        _ => Attestation::Android,
    };
    let appareil = Appareil {
        provenance,
        estampille,
        proprietaire: Identifiant::depuis_entropie(Genre::Utilisateur, [entree.graine; 16]),
        cle: [entree.graine; 33],
        atteste,
        revoque: entree.graine & 16 != 0,
    };
    let mut octets = [0_u8; APPAREIL_OCTETS];
    appareil.ecrire(&mut octets);
    assert_eq!(Appareil::lire(&octets), Ok(appareil));

    let enrolement = Enrolement {
        provenance,
        estampille,
        machine: Identifiant::depuis_entropie(Genre::Machine, [entree.graine; 16]),
        expire_a: entree.quand,
    };
    let mut octets = [0_u8; ENROLEMENT_OCTETS];
    enrolement.ecrire(&mut octets);
    assert_eq!(Enrolement::lire(&octets), Ok(enrolement));

    // ── LA DESCRIPTION D'UN APPAREIL ────────────────────────────────────────
    //
    // Le modèle est du texte libre aux règles du nom de machine : ce qui est
    // éprouvé ici est son RANGEMENT, le refus se prend dans `asl-api`.
    if let Ok(modele) = NomRange::nouveau(&entree.nom_de_machine) {
        let description = Description {
            provenance,
            estampille,
            systeme: match entree.graine % 3 {
                0 => Systeme::Ios,
                1 => Systeme::Android,
                _ => Systeme::Macos,
            },
            modele,
        };
        let mut octets = [0_u8; DESCRIPTION_OCTETS];
        description.ecrire(&mut octets);
        assert_eq!(Description::lire(&octets), Ok(description));
    }

    // ── PROPRIÉTÉ 5 : une opération est un cadre, et le cadre se relit ─────
    //
    // Depuis des octets quelconques : rien ne panique, un refus est nommé, et
    // ce qui se relit se réécrit à l'identique sur EXACTEMENT les octets que
    // le genre annonce — ce qui suit n'est pas regardé.
    match Operation::lire(&entree.operation) {
        Ok((lue, operation, combien)) => {
            assert_eq!(combien, operation.genre().octets());
            let mut refait = [0_u8; OPERATION_OCTETS_MAX];
            let ecrit = operation.ecrire(lue, &mut refait);
            assert_eq!(ecrit, combien);
            assert_eq!(
                &refait[..ecrit],
                &entree.operation[..combien],
                "une opération relue ne se réécrit pas octet pour octet"
            );
        }
        Err(Faute::Tronquee { attendus, obtenus }) => {
            assert_eq!(obtenus, entree.operation.len());
            assert!(obtenus < attendus);
        }
        Err(faute) => nommee(faute),
    }

    // Depuis des valeurs construites : une de chaque genre qui ne demande pas
    // un enregistrement — ceux-là sont déjà éprouvés ci-dessus, et l'opération
    // n'y ajoute qu'un identifiant.
    let identifiant = |genre| Identifiant::depuis_entropie(genre, [entree.graine; 16]);
    let operation = match entree.quelle_operation % 5 {
        0 => Operation::Alias {
            compte: identifiant(Genre::Utilisateur),
            alias: AliasRange::nouveau(&entree.alias).ok(),
        },
        1 => Operation::MachineModifiee {
            machine: identifiant(Genre::Machine),
            nom: NomRange::nouveau(&entree.nom_de_machine).ok(),
            capacites: (entree.graine & 32 != 0).then_some(Capacites {
                annonce: entree.graine & 1 != 0,
                lecture: entree.graine & 2 != 0,
            }),
        },
        2 => Operation::CleMachine {
            machine: identifiant(Genre::Machine),
            cle: [entree.graine; 32],
            empreinte: [entree.graine ^ 0xFF; 32],
            code: Estampille {
                compteur: entree.quand,
                ..estampille
            },
        },
        3 => Operation::AppareilRevoque {
            appareil: identifiant(Genre::Appareil),
        },
        _ => Operation::Machine {
            machine: identifiant(Genre::Machine),
            enregistrement: machine,
        },
    };
    let mut cadre = [0_u8; OPERATION_OCTETS_MAX];
    let combien = operation.ecrire(estampille, &mut cadre);
    assert_eq!(
        Operation::lire(&cadre[..combien]),
        Ok((estampille, operation, combien))
    );
    // Un octet de moins, et ce n'est plus une opération — jamais une
    // opération plus courte relue avec ce qui manque deviné.
    assert_eq!(
        Operation::lire(&cadre[..combien - 1]),
        Err(Faute::Tronquee {
            attendus: combien,
            obtenus: combien - 1,
        })
    );

    // ── PROPRIÉTÉ 6 : un cadre est une opération ou une fin ─────────────────
    //
    // Sur les mêmes octets quelconques : ce qu'`Operation::lire` accepte,
    // `Cadre::lire` le rend en `Operation` ; ce qui commence par l'étiquette
    // de fin est une fin, ou tronqué, ou une racine qui n'en est pas une ; et
    // rien ne panique.
    match (
        Cadre::lire(&entree.operation),
        Operation::lire(&entree.operation),
    ) {
        (
            Ok((
                Cadre::Operation {
                    estampille,
                    operation,
                },
                lu,
            )),
            Ok((e, o, combien)),
        ) => {
            assert_eq!((estampille, operation, lu), (e, o, combien));
        }
        (Ok((Cadre::Fin { coupe }, lu)), Err(Faute::Etiquette { lue })) => {
            assert_eq!(lue, ETIQUETTE_DE_FIN);
            assert_eq!(lu, CADRE_DE_FIN_OCTETS);
            let mut refait = [0_u8; OPERATION_OCTETS_MAX];
            assert_eq!(Cadre::Fin { coupe }.ecrire(&mut refait), lu);
            assert_eq!(
                &refait[..lu],
                &entree.operation[..lu],
                "une fin relue ne se réécrit pas octet pour octet"
            );
        }
        (Err(Faute::Tronquee { attendus, obtenus }), _) => {
            assert_eq!(obtenus, entree.operation.len());
            assert!(obtenus < attendus);
        }
        (Err(faute), Err(autre)) => {
            nommee(faute);
            // Une fin dont la racine n'est pas un annuaire est une faute de
            // genre, que l'opération lit comme une étiquette inconnue ; tout
            // le reste est la même faute des deux côtés.
            if entree.operation.first() != Some(&ETIQUETTE_DE_FIN) {
                assert_eq!(faute, autre);
            }
        }
        (cadre, operation) => panic!("les deux lecteurs divergent : {cadre:?} / {operation:?}"),
    }

    // Depuis une valeur construite : la fin se relit, et un octet de moins
    // est tronqué.
    let fin = Cadre::Fin { coupe: estampille };
    let mut cadre = [0_u8; OPERATION_OCTETS_MAX];
    let combien = fin.ecrire(&mut cadre);
    assert_eq!(combien, CADRE_DE_FIN_OCTETS);
    assert_eq!(Cadre::lire(&cadre[..combien]), Ok((fin, combien)));
    assert_eq!(
        Cadre::lire(&cadre[..combien - 1]),
        Err(Faute::Tronquee {
            attendus: combien,
            obtenus: combien - 1,
        })
    );
});
