//! **Cible : le message signé et sa vérification.**
//!
//! # Ce qu'elle éprouve, et ce qu'elle n'éprouve pas
//!
//! **Elle n'éprouve pas Ed25519** : `ed25519-dalek` s'en charge, et le refaire
//! ici mesurerait leur travail, pas le nôtre.
//!
//! Elle éprouve **ce que NOTRE message lie** : qu'aucun des quatre champs ne
//! peut changer sans invalider la signature. Un champ qui n'entrerait pas
//! réellement dans le message serait un champ qu'un attaquant peut modifier
//! librement — et c'est une faute qu'aucune bibliothèque de crypto n'attrape,
//! parce qu'elle est dans la composition, pas dans la primitive.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, sur n'importe quels octets de clé ou de signature.
//! 2. **Une signature juste vérifie**, toujours.
//! 3. **CHANGER UN SEUL CHAMP L'INVALIDE** — machine, défi, ou liaison de canal.
//!    C'est la propriété entière de ce module.
//! 4. **Deux messages différents ont toujours la MÊME LONGUEUR** : les champs
//!    sont de taille fixe, donc aucune frontière ne se déplace.
//! 5. **Une signature d'une autre clé ne vérifie jamais.**
//! 6. **LES MÊMES CINQ, POUR LA CLÉ P-256 D'UN APPAREIL** — et une de plus :
//!    une signature d'appareil ne vérifie jamais sous un identifiant de
//!    machine, ni l'inverse. Le genre entre dans le message, et la courbe n'y
//!    entre pas ; c'est le refus explicite de `CleAppareil::verifie` qui tient
//!    la frontière, et c'est lui qu'on éprouve.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asl_cle::{
    CleAppareil, ClePublique, CleSecrete, CleSecreteAppareil, Defi, LiaisonDeCanal, MESSAGE_OCTETS,
    Signature, SignatureAppareil, message_a_signer,
};
use asl_id::{Genre, Identifiant};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree {
    /// L'entropie de la clé de la machine.
    entropie: [u8; 32],
    /// L'entropie d'une autre clé.
    entropie_autre: [u8; 32],
    /// L'identifiant de la machine.
    machine: [u8; 16],
    /// Un second identifiant, pour éprouver le changement de champ.
    autre_machine: [u8; 16],
    /// Le défi.
    defi: [u8; 32],
    /// Un autre défi.
    autre_defi: [u8; 32],
    /// La liaison de canal.
    liaison: [u8; 32],
    /// Une autre liaison.
    autre_liaison: [u8; 32],
    /// Des octets quelconques, pris pour une clé publique.
    cle_quelconque: [u8; 32],
    /// Des octets quelconques, pris pour une signature.
    signature_quelconque: [u8; 64],
    /// L'entropie de la clé d'un appareil.
    entropie_appareil: [u8; 32],
    /// L'identifiant de l'appareil.
    appareil: [u8; 16],
    /// Des octets quelconques, pris pour une clé d'appareil.
    cle_appareil_quelconque: [u8; 33],
    /// Des octets quelconques, pris pour une signature d'appareil.
    signature_appareil_quelconque: [u8; 64],
}

fuzz_target!(|entree: Entree| {
    let machine = Identifiant::depuis_entropie(Genre::Machine, entree.machine);
    let autre_machine = Identifiant::depuis_entropie(Genre::Machine, entree.autre_machine);
    let defi = Defi::depuis_octets(entree.defi);
    let autre_defi = Defi::depuis_octets(entree.autre_defi);
    let liaison = LiaisonDeCanal::depuis_octets(entree.liaison);
    let autre_liaison = LiaisonDeCanal::depuis_octets(entree.autre_liaison);

    let secrete = CleSecrete::depuis_entropie(entree.entropie);
    let publique = secrete.publique();

    // PROPRIÉTÉ 2 : une signature juste vérifie.
    let signature = secrete
        .signer(machine, &defi, &liaison)
        .expect("un identifiant de machine est toujours accepté");
    assert!(
        publique.verifie(machine, &defi, &liaison, &signature),
        "une signature juste ne vérifie pas"
    );

    // PROPRIÉTÉ 3 : changer un champ invalide.
    if autre_machine != machine {
        assert!(
            !publique.verifie(autre_machine, &defi, &liaison, &signature),
            "la machine n'entre pas dans le message signé"
        );
    }
    if autre_defi != defi {
        assert!(
            !publique.verifie(machine, &autre_defi, &liaison, &signature),
            "le défi n'entre pas dans le message signé : le REJEU est ouvert"
        );
    }
    if autre_liaison != liaison {
        assert!(
            !publique.verifie(machine, &defi, &autre_liaison, &signature),
            "la liaison de canal n'entre pas dans le message signé : le RELAIS est ouvert"
        );
    }

    // PROPRIÉTÉ 4 : la longueur ne bouge jamais.
    let message = message_a_signer(machine, &defi, &liaison);
    let autre = message_a_signer(autre_machine, &autre_defi, &autre_liaison);
    assert_eq!(message.len(), MESSAGE_OCTETS);
    assert_eq!(autre.len(), MESSAGE_OCTETS);
    if machine != autre_machine || defi != autre_defi || liaison != autre_liaison {
        assert_ne!(message, autre, "deux messages différents se confondent");
    }

    // PROPRIÉTÉ 5 : une autre clé ne vérifie pas.
    let autre_cle = CleSecrete::depuis_entropie(entree.entropie_autre);
    if autre_cle.publique() != publique {
        assert!(
            !autre_cle
                .publique()
                .verifie(machine, &defi, &liaison, &signature),
            "une autre clé a vérifié"
        );
    }

    // PROPRIÉTÉ 1 : des octets quelconques ne paniquent pas.
    let quelconque = Signature::depuis_octets(entree.signature_quelconque);
    let _ = publique.verifie(machine, &defi, &liaison, &quelconque);
    if let Ok(lue) = ClePublique::depuis_octets(entree.cle_quelconque) {
        let _ = lue.verifie(machine, &defi, &liaison, &signature);
        // Une clé lue se réécrit et se relit à l'identique.
        assert_eq!(
            ClePublique::depuis_octets(lue.octets()).expect("une clé valide se relit"),
            lue
        );
    }

    // ── PROPRIÉTÉ 6 : l'appareil, sur P-256 ────────────────────────────────
    let appareil = Identifiant::depuis_entropie(Genre::Appareil, entree.appareil);
    let Ok(secrete_appareil) = CleSecreteAppareil::depuis_entropie(entree.entropie_appareil) else {
        // Zéro, ou au-delà de l'ordre : refusé, pas de panique, et rien à
        // signer avec.
        return;
    };
    let publique_appareil = secrete_appareil.publique();
    let signature_appareil = secrete_appareil
        .signer(appareil, &defi, &liaison)
        .expect("un identifiant d'appareil est toujours accepté");
    assert!(
        publique_appareil.verifie(appareil, &defi, &liaison, &signature_appareil),
        "une signature d'appareil juste ne vérifie pas"
    );
    if autre_defi != defi {
        assert!(
            !publique_appareil.verifie(appareil, &autre_defi, &liaison, &signature_appareil),
            "le défi n'entre pas dans le message d'un appareil : le REJEU est ouvert"
        );
    }
    if autre_liaison != liaison {
        assert!(
            !publique_appareil.verifie(appareil, &defi, &autre_liaison, &signature_appareil),
            "la liaison n'entre pas dans le message d'un appareil : le RELAIS est ouvert"
        );
    }
    // Le même identifiant, pris pour une machine : refusé, quoi que dise la
    // signature. Et signer pour lui est refusé aussi.
    let comme_machine = Identifiant::depuis_entropie(Genre::Machine, entree.appareil);
    assert!(
        !publique_appareil.verifie(comme_machine, &defi, &liaison, &signature_appareil),
        "une clé d'appareil a vérifié pour une machine"
    );
    assert!(
        secrete_appareil
            .signer(comme_machine, &defi, &liaison)
            .is_err()
    );

    // La possession : juste, puis liée.
    let preuve = secrete_appareil.prouver_la_possession(&defi, &liaison);
    assert!(publique_appareil.prouve_sa_possession(&defi, &liaison, &preuve));
    if autre_defi != defi {
        assert!(!publique_appareil.prouve_sa_possession(&autre_defi, &liaison, &preuve));
    }
    // Une preuve n'est pas une authentification, ni l'inverse.
    assert!(!publique_appareil.verifie(appareil, &defi, &liaison, &preuve));
    assert!(!publique_appareil.prouve_sa_possession(&defi, &liaison, &signature_appareil));

    // Des octets quelconques ne paniquent pas, et une clé lue se relit.
    let quelconque = SignatureAppareil::depuis_octets(entree.signature_appareil_quelconque);
    let _ = publique_appareil.verifie(appareil, &defi, &liaison, &quelconque);
    if let Ok(lue) = CleAppareil::depuis_octets(entree.cle_appareil_quelconque) {
        let _ = lue.verifie(appareil, &defi, &liaison, &signature_appareil);
        assert_eq!(
            CleAppareil::depuis_octets(lue.octets()).expect("une clé valide se relit"),
            lue
        );
        if lue != publique_appareil {
            assert!(
                !lue.verifie(appareil, &defi, &liaison, &signature_appareil),
                "une autre clé d'appareil a vérifié"
            );
        }
    }
});
