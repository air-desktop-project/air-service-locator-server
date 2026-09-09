//! Les décisions d'autorisation, et les deux contraintes qu'elles arment.
//!
//! **C10** : rien ne se lit sans autorisation nominative, et la décision se
//! calcule à partir du compte propriétaire de la machine qui demande — jamais à
//! partir de ce que la requête désigne.
//!
//! **C9** : un refus ne dit pas pourquoi, et les chemins d'autorisation ne
//! renseignent pas par leur durée.

use asl_auth::{
    Autorisation, Capacites, Cible, CodeEnrolement, Decision, EtatCode, Faute, Machine, Politique,
    Portee, decider_annonce, decider_attestation, decider_enrolement, decider_gestion,
    decider_resolution, decider_revocation_d_appareil,
};
use asl_id::{Genre, Identifiant};

/// Un identifiant du genre voulu, distinct par son octet de tête.
fn ident(genre: Genre, marque: u8) -> Identifiant {
    let mut octets = [0x11; 16];
    octets[0] = marque;
    Identifiant::depuis_entropie(genre, octets)
}

fn alice() -> Identifiant {
    ident(Genre::Utilisateur, 0xA1)
}

fn bob() -> Identifiant {
    ident(Genre::Utilisateur, 0xB0)
}

fn carole() -> Identifiant {
    ident(Genre::Utilisateur, 0xC0)
}

/// Une machine de `proprietaire`, avec ces capacités.
fn machine(proprietaire: Identifiant, marque: u8, capacites: Capacites) -> Machine {
    Machine::nouvelle(ident(Genre::Machine, marque), proprietaire, capacites)
        .expect("machine d'essai")
}

/// Un service d'Alice, sur sa machine.
fn cible_d_alice() -> Cible {
    Cible::nouvelle(
        ident(Genre::Service, 0x51),
        ident(Genre::Machine, 0x11),
        alice(),
    )
    .expect("cible d'essai")
}

// ── Les faits mal formés ────────────────────────────────────────────────────

#[test]
fn chaque_genre_est_verifie_a_la_construction() {
    // Un identifiant du mauvais genre passé pour un autre est une faute de
    // l'appelant, pas un refus d'autorisation.
    assert_eq!(
        Machine::nouvelle(alice(), alice(), Capacites::LECTURE).map(|_| ()),
        Err(Faute::PasUneMachine {
            obtenu: Genre::Utilisateur
        })
    );
    assert_eq!(
        Machine::nouvelle(
            ident(Genre::Machine, 1),
            ident(Genre::Machine, 2),
            Capacites::LECTURE
        )
        .map(|_| ()),
        Err(Faute::PasUnUtilisateur {
            obtenu: Genre::Machine
        })
    );
    assert_eq!(
        Cible::nouvelle(alice(), ident(Genre::Machine, 1), alice()).map(|_| ()),
        Err(Faute::PasUnService {
            obtenu: Genre::Utilisateur
        })
    );
    assert_eq!(
        Cible::nouvelle(ident(Genre::Service, 1), alice(), alice()).map(|_| ()),
        Err(Faute::PasUneMachine {
            obtenu: Genre::Utilisateur
        })
    );
    assert_eq!(
        Cible::nouvelle(
            ident(Genre::Service, 1),
            ident(Genre::Machine, 1),
            ident(Genre::Service, 2)
        )
        .map(|_| ()),
        Err(Faute::PasUnUtilisateur {
            obtenu: Genre::Service
        })
    );
}

#[test]
fn une_portee_du_mauvais_genre_est_refusee() {
    for mauvaise in [
        Portee::UneMachine(ident(Genre::Service, 1)),
        Portee::UnService(ident(Genre::Machine, 1)),
    ] {
        assert!(matches!(
            Autorisation::nouvelle(alice(), bob(), mauvaise, false),
            Err(Faute::PorteeIncoherente { .. })
        ));
    }
    // Les portées cohérentes passent.
    for bonne in [
        Portee::ToutLeCompte,
        Portee::UneMachine(ident(Genre::Machine, 1)),
        Portee::UnService(ident(Genre::Service, 1)),
    ] {
        assert!(Autorisation::nouvelle(alice(), bob(), bonne, false).is_ok());
    }
}

#[test]
fn un_compte_ne_s_autorise_pas_lui_meme() {
    // Deux chemins vers le même droit, c'est un qu'on oublie de révoquer.
    assert_eq!(
        Autorisation::nouvelle(alice(), alice(), Portee::ToutLeCompte, false).map(|_| ()),
        Err(Faute::AutorisationASoiMeme)
    );
}

#[test]
fn les_autorisations_exigent_des_comptes() {
    assert!(matches!(
        Autorisation::nouvelle(ident(Genre::Machine, 1), bob(), Portee::ToutLeCompte, false),
        Err(Faute::PasUnUtilisateur { .. })
    ));
    assert!(matches!(
        Autorisation::nouvelle(
            alice(),
            ident(Genre::Machine, 1),
            Portee::ToutLeCompte,
            false
        ),
        Err(Faute::PasUnUtilisateur { .. })
    ));
}

// ── L'annonce ───────────────────────────────────────────────────────────────

#[test]
fn seule_une_machine_avec_annonce_peut_annoncer() {
    assert_eq!(
        decider_annonce(&machine(alice(), 1, Capacites::ANNONCE)),
        Decision::Servir
    );
    for sans in [Capacites::AUCUNE, Capacites::LECTURE] {
        assert_eq!(
            decider_annonce(&machine(alice(), 1, sans)),
            Decision::Refuser
        );
    }
}

// ── La résolution : C10 ─────────────────────────────────────────────────────

#[test]
fn sans_la_capacite_de_lecture_rien_n_est_meme_examine() {
    // Une machine qui n'a pas le droit de lire n'a pas de compte à faire valoir.
    let autorisation = Autorisation::nouvelle(alice(), bob(), Portee::ToutLeCompte, false).unwrap();
    for sans in [Capacites::AUCUNE, Capacites::ANNONCE] {
        assert_eq!(
            decider_resolution(&machine(bob(), 2, sans), &cible_d_alice(), &[autorisation]),
            Decision::Refuser
        );
    }
}

#[test]
fn ses_propres_services_passent_sans_autorisation() {
    // Le propriétaire n'a pas besoin de s'autoriser lui-même — et il ne le
    // pourrait pas.
    assert_eq!(
        decider_resolution(
            &machine(alice(), 2, Capacites::LECTURE),
            &cible_d_alice(),
            &[]
        ),
        Decision::Servir
    );
}

#[test]
fn un_tiers_sans_autorisation_est_refuse() {
    // **L'ESSAI QUI COMPTE POUR C10** : un compte tiers, une cible qui existe,
    // et aucune arête. Un chemin qui rendrait le service parce que son
    // identifiant a été fourni passerait tous les autres essais.
    assert_eq!(
        decider_resolution(
            &machine(bob(), 2, Capacites::LECTURE),
            &cible_d_alice(),
            &[]
        ),
        Decision::Refuser
    );
}

#[test]
fn les_trois_portees_ouvrent_ce_qu_elles_nomment() {
    let demandeur = machine(bob(), 2, Capacites::LECTURE);
    let cible = cible_d_alice();

    for portee in [
        Portee::ToutLeCompte,
        Portee::UneMachine(cible.machine()),
        Portee::UnService(cible.service()),
    ] {
        let arete = Autorisation::nouvelle(alice(), bob(), portee, false).unwrap();
        assert_eq!(
            decider_resolution(&demandeur, &cible, &[arete]),
            Decision::Servir,
            "{portee:?}"
        );
    }
}

#[test]
fn une_portee_qui_nomme_autre_chose_n_ouvre_rien() {
    let demandeur = machine(bob(), 2, Capacites::LECTURE);
    let cible = cible_d_alice();

    for portee in [
        Portee::UneMachine(ident(Genre::Machine, 0x99)),
        Portee::UnService(ident(Genre::Service, 0x99)),
    ] {
        let arete = Autorisation::nouvelle(alice(), bob(), portee, false).unwrap();
        assert_eq!(
            decider_resolution(&demandeur, &cible, &[arete]),
            Decision::Refuser,
            "{portee:?}"
        );
    }
}

#[test]
fn une_autorisation_revoquee_n_ouvre_rien() {
    // Vérifié ICI, même si le magasin est censé l'avoir filtrée : la fonction
    // reste sûre quand l'appelant a mal filtré.
    let arete = Autorisation::nouvelle(alice(), bob(), Portee::ToutLeCompte, true).unwrap();
    assert!(arete.revoquee());
    assert_eq!(
        decider_resolution(
            &machine(bob(), 2, Capacites::LECTURE),
            &cible_d_alice(),
            &[arete]
        ),
        Decision::Refuser
    );
}

#[test]
fn les_deux_bouts_de_l_arete_sont_verifies() {
    let demandeur = machine(bob(), 2, Capacites::LECTURE);
    let cible = cible_d_alice();

    // Une arête accordée par quelqu'un d'AUTRE que le propriétaire de la cible
    // ouvrirait les services d'un compte sur la signature d'un autre.
    let par_carole = Autorisation::nouvelle(carole(), bob(), Portee::ToutLeCompte, false).unwrap();
    assert_eq!(
        decider_resolution(&demandeur, &cible, &[par_carole]),
        Decision::Refuser
    );

    // Une arête accordée à quelqu'un d'AUTRE que le demandeur non plus.
    let a_carole = Autorisation::nouvelle(alice(), carole(), Portee::ToutLeCompte, false).unwrap();
    assert_eq!(
        decider_resolution(&demandeur, &cible, &[a_carole]),
        Decision::Refuser
    );
}

#[test]
fn une_arete_valide_parmi_plusieurs_suffit() {
    let demandeur = machine(bob(), 2, Capacites::LECTURE);
    let cible = cible_d_alice();
    let aretes = [
        Autorisation::nouvelle(carole(), bob(), Portee::ToutLeCompte, false).unwrap(),
        Autorisation::nouvelle(alice(), bob(), Portee::ToutLeCompte, true).unwrap(),
        Autorisation::nouvelle(alice(), bob(), Portee::UnService(cible.service()), false).unwrap(),
    ];
    assert_eq!(
        decider_resolution(&demandeur, &cible, &aretes),
        Decision::Servir
    );
}

// ── C9 : le refus ne dit pas pourquoi ───────────────────────────────────────

#[test]
fn tous_les_refus_sont_le_meme_refus() {
    // **C9 DANS LE TYPE.** Une raison finirait un jour dans une réponse, et
    // « vous n'avez pas le droit » distingué de « ce service n'existe pas » est
    // exactement la fuite qu'on ferme.
    let cible = cible_d_alice();
    let refus = [
        decider_resolution(&machine(bob(), 2, Capacites::AUCUNE), &cible, &[]),
        decider_resolution(&machine(bob(), 2, Capacites::LECTURE), &cible, &[]),
        decider_resolution(
            &machine(bob(), 2, Capacites::LECTURE),
            &cible,
            &[Autorisation::nouvelle(alice(), bob(), Portee::ToutLeCompte, true).unwrap()],
        ),
        decider_annonce(&machine(alice(), 1, Capacites::LECTURE)),
    ];
    for verdict in refus {
        assert_eq!(verdict, Decision::Refuser);
        assert!(!verdict.permet());
    }
    assert!(Decision::Servir.permet());
}

// ── Le code d'enrôlement ────────────────────────────────────────────────────

#[test]
fn un_code_se_fabrique_se_lit_et_se_relit() {
    let code = CodeEnrolement::depuis_entropie([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]);
    let texte = code.texte();
    assert_eq!(texte.len(), 10);
    assert!(texte.bytes().all(|o| asl_id::base32::valeur(o).is_some()));

    let relu = CodeEnrolement::analyser(texte).expect("un code canonique se relit");
    assert_eq!(relu.texte(), texte);
    // **C'EST L'EMPREINTE QUI IDENTIFIE**, puisque c'est elle qu'on range.
    assert_eq!(relu.empreinte(), code.empreinte());
}

#[test]
fn la_forme_groupee_s_affiche_et_se_retape() {
    let code = CodeEnrolement::analyser("4K9M2P7R1T").unwrap();
    let groupe = code.texte_groupe();
    assert_eq!(groupe.as_str(), "4K9M2-P7R1T");

    // Ce qu'on AFFICHE se retape tel quel, et vaut ce qu'on a affiché.
    let retape = CodeEnrolement::analyser(groupe.as_str()).expect("la forme groupée se relit");
    assert_eq!(retape.empreinte(), code.empreinte());
    assert_eq!(retape.texte(), "4K9M2P7R1T");
}

#[test]
fn un_tiret_egare_ne_passe_pas() {
    // La bonne longueur, mais le tiret ailleurs qu'à sa place.
    assert_eq!(
        CodeEnrolement::analyser("4K9M2P-7R1T").map(|_| ()),
        Err(Faute::CodeLongueur {
            attendue: 10,
            obtenue: 11
        })
    );
}

#[test]
fn deux_codes_differents_ont_deux_empreintes() {
    let un = CodeEnrolement::analyser("0123456789").unwrap();
    let autre = CodeEnrolement::analyser("9876543210").unwrap();
    assert_ne!(un.empreinte(), autre.empreinte());
    assert_eq!(un.empreinte().len(), 32);
}

#[test]
fn le_rattrapage_de_crockford_vaut_aussi_pour_un_code() {
    // C'est un humain qui le tape sur un terminal.
    let reference = CodeEnrolement::analyser("0123456789").unwrap();
    for variante in ["O123456789", "o123456789", "0I23456789", "0L23456789"] {
        let lu = CodeEnrolement::analyser(variante).unwrap();
        assert_eq!(
            lu.empreinte(),
            reference.empreinte(),
            "{variante} devrait valoir la référence"
        );
        // Et ce qu'on range est la forme CANONIQUE.
        assert_eq!(lu.texte(), "0123456789");
    }
}

#[test]
fn un_code_mal_forme_est_refuse() {
    for texte in ["", "012345678", "01234567890"] {
        assert_eq!(
            CodeEnrolement::analyser(texte).map(|_| ()),
            Err(Faute::CodeLongueur {
                attendue: 10,
                obtenue: texte.len()
            }),
            "{texte:?}"
        );
    }
    assert_eq!(
        CodeEnrolement::analyser("01234U6789").map(|_| ()),
        Err(Faute::CodeSymboleInvalide { position: 5 })
    );
    assert_eq!(
        CodeEnrolement::analyser("!123456789").map(|_| ()),
        Err(Faute::CodeSymboleInvalide { position: 0 })
    );
}

#[test]
fn les_cinquante_bits_de_poids_fort_sont_employes() {
    // Changer un bit de POIDS FORT change le code ; changer les quatorze bits
    // de poids faible ne le change pas.
    let base = CodeEnrolement::depuis_entropie([0x00; 8]);
    let poids_fort = CodeEnrolement::depuis_entropie([0x80, 0, 0, 0, 0, 0, 0, 0]);
    let poids_faible = CodeEnrolement::depuis_entropie([0, 0, 0, 0, 0, 0, 0x3F, 0xFF]);

    assert_ne!(base.empreinte(), poids_fort.empreinte());
    assert_eq!(base.empreinte(), poids_faible.empreinte());
}

#[test]
fn seul_un_code_utilisable_lie_une_cle() {
    assert_eq!(decider_enrolement(EtatCode::Utilisable), Decision::Servir);

    // **LES DEUX REFUS SONT LE MÊME REFUS** : un code qu'on ne trouve pas et un
    // code périmé. Rien dans la réponse ne les distingue, et il n'y a plus de
    // comparaison à écourter — l'annuaire cherche par empreinte, il ne compare
    // plus rien (C9).
    for etat in [EtatCode::Inconnu, EtatCode::Expire] {
        assert_eq!(decider_enrolement(etat), Decision::Refuser, "{etat:?}");
    }
}

// ── L'administration, et l'attestation ──────────────────────────────────────

#[test]
fn un_compte_n_administre_que_ce_qu_il_possede() {
    let moi = alice();
    let toi = bob();

    assert_eq!(decider_gestion(moi, moi), Decision::Servir);
    assert_eq!(decider_gestion(moi, toi), Decision::Refuser);
    assert_eq!(decider_gestion(toi, moi), Decision::Refuser);
}

#[test]
fn l_attestation_exigee_refuse_ce_qui_n_est_pas_atteste() {
    // C'est la posture de `protocole.md` §2.1, et elle refuse TOUT aujourd'hui :
    // rien ne sait encore établir `atteste`.
    assert_eq!(
        decider_attestation(false, Politique::AttestationExigee),
        Decision::Refuser
    );
    assert_eq!(
        decider_attestation(true, Politique::AttestationExigee),
        Decision::Servir
    );
}

#[test]
fn l_attestation_facultative_laisse_passer_les_deux() {
    for atteste in [false, true] {
        assert_eq!(
            decider_attestation(atteste, Politique::AttestationFacultative),
            Decision::Servir,
            "{atteste}"
        );
    }
}

// ── Les accesseurs ──────────────────────────────────────────────────────────

#[test]
fn les_enregistrements_rendent_ce_qu_on_leur_a_donne() {
    let m = machine(alice(), 7, Capacites::ANNONCE);
    assert_eq!(m.identifiant(), ident(Genre::Machine, 7));
    assert_eq!(m.proprietaire(), alice());
    assert_eq!(m.capacites(), Capacites::ANNONCE);
    assert_eq!(Capacites::default(), Capacites::AUCUNE);

    let arete = Autorisation::nouvelle(alice(), bob(), Portee::ToutLeCompte, false).unwrap();
    assert_eq!(arete.par(), alice());
    assert_eq!(arete.a(), bob());
    assert_eq!(arete.portee(), Portee::ToutLeCompte);
    assert!(!arete.revoquee());

    let cible = cible_d_alice();
    assert_eq!(cible.service(), ident(Genre::Service, 0x51));
    assert_eq!(cible.machine(), ident(Genre::Machine, 0x11));
    assert_eq!(cible.proprietaire(), alice());
}

#[test]
fn le_texte_groupe_s_affiche() {
    // Il se recopie d'un écran vers un terminal : il doit s'écrire.
    let code = CodeEnrolement::analyser("4K9M2P7R1T").unwrap();
    assert_eq!(code.texte_groupe().to_string(), "4K9M2-P7R1T");
}

// ── Révoquer un appareil ────────────────────────────────────────────────────

#[test]
fn un_appareil_ne_se_revoque_pas_lui_meme() {
    // **UN TÉLÉPHONE VOLÉ ET DÉVERROUILLÉ NE DOIT PAS CONFISQUER LE COMPTE.**
    // S'il pouvait révoquer les autres ET lui-même, il ne resterait rien au
    // propriétaire pour le lui reprendre.
    let moi = ident(Genre::Appareil, 1);
    let autre = ident(Genre::Appareil, 2);

    assert_eq!(decider_revocation_d_appareil(moi, moi), Decision::Refuser);
    assert_eq!(decider_revocation_d_appareil(moi, autre), Decision::Servir);
    assert_eq!(decider_revocation_d_appareil(autre, moi), Decision::Servir);
}

#[test]
fn un_compte_ne_peut_pas_se_retrouver_sans_appareil() {
    // Ce n'est pas une règle de plus : c'est une CONSÉQUENCE de la précédente.
    // Il faut deux appareils pour qu'une révocation soit possible, donc il en
    // reste toujours un après. Un compte à un seul appareil ne peut que tenter
    // de se révoquer lui-même — et c'est refusé.
    let seul = ident(Genre::Appareil, 1);
    assert_eq!(decider_revocation_d_appareil(seul, seul), Decision::Refuser);
}
