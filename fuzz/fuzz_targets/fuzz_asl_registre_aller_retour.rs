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
//! 4. **UN REFUS EST TOUJOURS L'UNE DES QUATRE FAUTES NOMMÉES**, jamais une
//!    panique ni un enregistrement à moitié lu.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asl_id::{Genre, Identifiant};
use asl_registre::{
    ALIAS_OCTETS_MAX, APPAREIL_OCTETS, AUTORISATION_OCTETS, AliasRange, Appareil, Attestation,
    Autorisation, COMPTE_OCTETS, Compte, ENROLEMENT_OCTETS, ENTREE_OCTETS, Enrolement,
    EntreeJournal, Faute, MACHINE_OCTETS, Machine, NOM_OCTETS_MAX, NomRange, Portee, Provenance,
    SERVICE_OCTETS, Service, Verdict,
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
    /// Le verdict, choisi parmi trois.
    verdict: u8,
    /// L'instant.
    quand: u64,
    /// Le rang.
    rang: u64,
    /// La provenance est-elle distante ?
    distante: bool,
}

/// Une faute est toujours l'une des quatre, et jamais une panique.
fn nommee(faute: Faute) {
    assert!(matches!(
        faute,
        Faute::Etiquette { .. } | Faute::Genre { .. } | Faute::Longueur { .. } | Faute::Bourrage
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

    if let Ok(alias) = AliasRange::nouveau(&entree.alias) {
        assert!(alias.longueur() <= ALIAS_OCTETS_MAX);
        let compte = Compte {
            provenance,
            alias: Some(alias),
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
        par: Identifiant::depuis_entropie(Genre::Utilisateur, [entree.graine; 16]),
        a: Identifiant::depuis_entropie(Genre::Utilisateur, [entree.graine ^ 0xFF; 16]),
        portee,
        revoquee: entree.graine & 4 != 0,
    };
    let mut octets = [0_u8; AUTORISATION_OCTETS];
    autorisation.ecrire(&mut octets);
    assert_eq!(Autorisation::lire(&octets), Ok(autorisation));

    let machine = Machine {
        provenance,
        proprietaire: Identifiant::depuis_entropie(Genre::Utilisateur, [entree.graine; 16]),
        // **LES DEUX ÉTATS D'UNE CLÉ**, et le second n'est pas cosmétique : une
        // machine déclarée et pas encore enrôlée n'en a pas, et l'absence doit
        // faire l'aller-retour aussi bien que la présence.
        cle: (entree.graine & 8 != 0).then_some([entree.graine; 32]),
        annonce: entree.graine & 1 != 0,
        lecture: entree.graine & 2 != 0,
        // **UN NOM DE MACHINE EST DU TEXTE LIBRE**, donc n'importe quelle suite
        // d'octets valides en UTF-8 et assez courte. Le refus se prend ailleurs
        // (`asl-api`) ; ce qui est éprouvé ici est le RANGEMENT.
        nom: match NomRange::nouveau(&entree.nom_de_machine) {
            Ok(nom) => nom,
            Err(_) => return,
        },
    };
    let mut octets = [0_u8; MACHINE_OCTETS];
    machine.ecrire(&mut octets);
    assert_eq!(Machine::lire(&octets), Ok(machine));

    // ── L'APPAREIL ET LE CODE D'ENRÔLEMENT ──────────────────────────────────
    let atteste = match entree.graine % 3 {
        0 => Attestation::Aucune,
        1 => Attestation::Apple,
        _ => Attestation::Google,
    };
    let appareil = Appareil {
        provenance,
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
        machine: Identifiant::depuis_entropie(Genre::Machine, [entree.graine; 16]),
        expire_a: entree.quand,
    };
    let mut octets = [0_u8; ENROLEMENT_OCTETS];
    enrolement.ecrire(&mut octets);
    assert_eq!(Enrolement::lire(&octets), Ok(enrolement));
});
