//! **Cible : les décisions d'autorisation** — C10 sur des faits quelconques.
//!
//! # Ce qu'elle éprouve
//!
//! **La propriété qui, si elle tombe, est la faille entière du produit** : un
//! service ne se rend qu'à qui y a droit. Le harnais la RECALCULE lui-même, à
//! partir des faits, et la compare à ce que la fonction a décidé.
//!
//! **Recalculer plutôt que relire la fonction** est ce qui rend cet essai utile.
//! Un harnais qui appellerait la même logique ne vérifierait que sa propre
//! cohérence : il passerait aussi le jour où les deux seraient fausses de la
//! même manière.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique.**
//! 2. **`Servir` implique un droit qui existe** : soit le demandeur est le
//!    propriétaire, soit une arête vivante, accordée PAR le propriétaire de la
//!    cible ET AU propriétaire du demandeur, couvre cette cible.
//! 3. **`Refuser` implique qu'aucun tel droit n'existe.** L'implication dans les
//!    deux sens : ni faux positif, ni faux négatif.
//! 4. **Sans la capacité `lecture`, jamais `Servir`** — quoi qu'il y ait dans la
//!    liste d'autorisations.
//! 5. **La décision ne dépend PAS de l'ordre des autorisations.**
//! 6. **Une autorisation révoquée n'ouvre jamais rien**, même si l'appelant a
//!    mal filtré.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asl_auth::{
    Autorisation, Capacites, Cible, Decision, Machine, Portee, decider_annonce, decider_resolution,
};
use asl_id::{Genre, Identifiant};

/// Un compte, désigné par un petit numéro pour que les collisions arrivent.
#[derive(Arbitrary, Debug, Clone, Copy)]
struct Compte(u8);

/// Une portée, telle que le fuzzer sait la fabriquer.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum PorteeBrute {
    Tout,
    Machine(u8),
    Service(u8),
}

/// Une arête.
#[derive(Arbitrary, Debug, Clone, Copy)]
struct AreteBrute {
    par: Compte,
    a: Compte,
    portee: PorteeBrute,
    revoquee: bool,
}

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree {
    proprietaire_demandeur: Compte,
    machine_demandeur: u8,
    annonce: bool,
    lecture: bool,
    proprietaire_cible: Compte,
    machine_cible: u8,
    service_cible: u8,
    aretes: Vec<AreteBrute>,
}

/// Un identifiant du genre voulu, distinct par son octet de tête.
fn ident(genre: Genre, marque: u8) -> Identifiant {
    let mut octets = [0x00; 16];
    octets[0] = marque;
    Identifiant::depuis_entropie(genre, octets)
}

fn compte(Compte(marque): Compte) -> Identifiant {
    ident(Genre::Utilisateur, marque)
}

fn portee(brute: PorteeBrute) -> Portee {
    match brute {
        PorteeBrute::Tout => Portee::ToutLeCompte,
        PorteeBrute::Machine(marque) => Portee::UneMachine(ident(Genre::Machine, marque)),
        PorteeBrute::Service(marque) => Portee::UnService(ident(Genre::Service, marque)),
    }
}

/// La règle, RÉÉCRITE ICI à partir des specs, et non appelée depuis la crate.
fn droit_attendu(
    proprietaire_demandeur: Identifiant,
    lecture: bool,
    cible: &Cible,
    aretes: &[Autorisation],
) -> bool {
    if !lecture {
        return false;
    }
    if proprietaire_demandeur == cible.proprietaire() {
        return true;
    }
    aretes.iter().any(|arete| {
        !arete.revoquee()
            && arete.a() == proprietaire_demandeur
            && arete.par() == cible.proprietaire()
            && match arete.portee() {
                Portee::ToutLeCompte => true,
                Portee::UneMachine(machine) => machine == cible.machine(),
                Portee::UnService(service) => service == cible.service(),
            }
    })
}

fuzz_target!(|entree: Entree| {
    let proprietaire_demandeur = compte(entree.proprietaire_demandeur);
    let capacites = Capacites {
        annonce: entree.annonce,
        lecture: entree.lecture,
    };
    let Ok(demandeur) = Machine::nouvelle(
        ident(Genre::Machine, entree.machine_demandeur),
        proprietaire_demandeur,
        capacites,
    ) else {
        return;
    };

    let Ok(cible) = Cible::nouvelle(
        ident(Genre::Service, entree.service_cible),
        ident(Genre::Machine, entree.machine_cible),
        compte(entree.proprietaire_cible),
    ) else {
        return;
    };

    let aretes: Vec<Autorisation> = entree
        .aretes
        .iter()
        .filter_map(|brute| {
            Autorisation::nouvelle(
                compte(brute.par),
                compte(brute.a),
                portee(brute.portee),
                brute.revoquee,
            )
            .ok()
        })
        .collect();

    let decision = decider_resolution(&demandeur, &cible, &aretes);
    let attendu = droit_attendu(proprietaire_demandeur, entree.lecture, &cible, &aretes);

    // PROPRIÉTÉS 2, 3 et 6 : l'implication dans les deux sens.
    assert_eq!(
        decision.permet(),
        attendu,
        "la décision ne suit pas la règle : {decision:?} pour {demandeur:?} sur {cible:?}"
    );

    // PROPRIÉTÉ 4 : sans `lecture`, jamais `Servir`.
    if !entree.lecture {
        assert_eq!(
            decision,
            Decision::Refuser,
            "servi sans capacité de lecture"
        );
    }

    // PROPRIÉTÉ 5 : l'ordre des autorisations ne change rien.
    let mut inverses = aretes.clone();
    inverses.reverse();
    assert_eq!(
        decider_resolution(&demandeur, &cible, &inverses),
        decision,
        "la décision dépend de l'ordre des autorisations"
    );

    // Et l'annonce ne dépend QUE de sa capacité.
    assert_eq!(
        decider_annonce(&demandeur).permet(),
        entree.annonce,
        "la décision d'annonce ne suit pas la capacité"
    );
});
