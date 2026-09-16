//! Le lecteur de `KeyDescription` lit ce que le schéma dit, saute ce qu'il ne
//! connaît pas, refuse ce qui n'a pas la forme — et ne panique jamais.
//!
//! Comme pour le marcheur X.509 : la `KeyDescription` RÉELLE du Fairphone 5
//! est tronquée à chaque longueur et abîmée à chaque octet, et tout ce qui
//! sort est soit un refus nommé, soit une description dont chaque tranche est
//! bien une tranche de l'entrée.

mod forge;

use std::path::PathBuf;

use asl_keystore::der;
use asl_keystore::description::{Application, Description, Faute, ListeAutorisations, lire};
use asl_keystore::x509;
use forge::{
    Portrait, application, booleen, champ, element, ensemble, entier, enumere, nul, octets,
    racine_de_confiance, sequence,
};

fn description_reelle() -> Vec<u8> {
    let mut chemin = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    chemin.push("../../docs/attestation/captures/keystore-fp5-2026-09-16/cert0.der");
    let feuille = std::fs::read(&chemin).expect("la capture est dans le dépôt");
    x509::lire(&feuille)
        .expect("la feuille se lit")
        .description
        .expect("l'extension y est")
        .to_vec()
}

/// Chaque tranche rendue est-elle DANS l'entrée ?
fn dans(entree: &[u8], tranche: &[u8]) -> bool {
    let debut = entree.as_ptr() as usize;
    let fin = debut.saturating_add(entree.len());
    let t = tranche.as_ptr() as usize;
    tranche.is_empty() || (t >= debut && t.saturating_add(tranche.len()) <= fin)
}

fn plausible(entree: &[u8], resultat: Result<Description<'_>, Faute>) {
    if let Ok(lue) = resultat {
        assert!(dans(entree, lue.defi));
        assert!(dans(entree, lue.identifiant_unique));
        for liste in [&lue.logiciel, &lue.materiel] {
            if let Some(racine) = liste.racine_de_confiance {
                assert!(dans(entree, racine.cle_de_demarrage));
                assert!(dans(entree, racine.empreinte_de_demarrage));
            }
            if let Some(app) = &liste.application {
                for paquet in &app.paquets {
                    assert!(dans(entree, paquet.nom));
                }
                for empreinte in &app.empreintes {
                    assert!(dans(entree, empreinte));
                }
            }
        }
    }
}

#[test]
fn chaque_prefixe_est_refuse_sans_panique() {
    let reelle = description_reelle();
    for n in 0..reelle.len() {
        assert!(lire(&reelle[..n]).is_err(), "tronquée à {n}");
    }
}

#[test]
fn chaque_octet_abime_est_refuse_ou_lu_sans_panique() {
    let reelle = description_reelle();
    for i in 0..reelle.len() {
        for valeur in [
            reelle[i] ^ 0xFF,
            0x00,
            0x01,
            0x30,
            0x7F,
            0x80,
            0x81,
            0x82,
            0xBF,
            0xFF,
        ] {
            let mut abimee = reelle.clone();
            abimee[i] = valeur;
            plausible(&abimee, lire(&abimee));
        }
    }
}

#[test]
fn le_portrait_du_banc_se_lit_tel_qu_il_a_ete_ecrit() {
    let portrait = Portrait::coherent(b"defi");
    let der = portrait.encoder();
    let lue = lire(&der).expect("il se lit");
    assert_eq!(lue.version, 3);
    assert_eq!(lue.defi, b"defi");
    assert_eq!(lue.materiel.finalites, Some(vec![2]));
    assert_eq!(lue.materiel.condensats, Some(vec![4]));
    assert!(lue.materiel.sans_authentification);
    assert_eq!(
        lue.logiciel.application,
        Some(Application {
            paquets: vec![asl_keystore::description::Paquet {
                nom: forge::PAQUET.as_bytes(),
                version: 6
            }],
            empreintes: vec![&forge::EMPREINTE[..]],
        })
    );
    assert_eq!(lue.clone(), lue);
    assert_eq!(ListeAutorisations::default().sautees, 0);
}

#[test]
fn les_surplus_sont_refuses_partout_ou_le_schema_dit_tout() {
    let portrait = Portrait::coherent(b"defi");
    // Après la KeyDescription.
    let mut der = portrait.encoder();
    der.push(0x00);
    assert_eq!(lire(&der), Err(Faute::Surplus));
    // Dans la KeyDescription, après teeEnforced.
    let mut interieur = portrait.encoder()[4..].to_vec();
    interieur.extend_from_slice(&nul());
    assert_eq!(lire(&sequence(&[&interieur])), Err(Faute::Surplus));
    // Dans un `[n] EXPLICIT INTEGER`, un second élément.
    let mut deux = entier(3);
    deux.extend_from_slice(&entier(4));
    let p = portrait.clone().avec_materiel(2, &deux);
    assert_eq!(lire(&p.encoder()), Err(Faute::Surplus));
    // Dans un `[n] EXPLICIT SET OF`, un second élément après le SET.
    let mut deux = ensemble(&[&entier(2)]);
    deux.extend_from_slice(&nul());
    let p = portrait.clone().avec_materiel(1, &deux);
    assert_eq!(lire(&p.encoder()), Err(Faute::Surplus));
    // Un NULL qui n'est pas vide, ou suivi.
    let p = portrait.clone().avec_materiel(503, &[0x05, 0x01, 0x00]);
    assert_eq!(lire(&p.encoder()), Err(Faute::Surplus));
    // Dans un rootOfTrust : un cinquième champ, ou un second SEQUENCE.
    let mut cinq = racine_de_confiance(true, 0);
    let contenu = cinq[2..].to_vec();
    let mut contenu_cinq = contenu.clone();
    contenu_cinq.extend_from_slice(&nul());
    cinq = sequence(&[&contenu_cinq]);
    let p = portrait.clone().avec_materiel(704, &cinq);
    assert_eq!(lire(&p.encoder()), Err(Faute::Surplus));
    let mut deux_racines = racine_de_confiance(true, 0);
    deux_racines.extend_from_slice(&nul());
    let p = portrait.clone().avec_materiel(704, &deux_racines);
    assert_eq!(lire(&p.encoder()), Err(Faute::Surplus));
    // Dans un attestationApplicationId : à chaque enveloppe.
    let app = application(&[("a", 1)], &[b"e"]);
    let mut suivi = app.clone();
    suivi.extend_from_slice(&nul());
    let p = portrait.clone().avec_logiciel(709, &suivi);
    assert_eq!(lire(&p.encoder()), Err(Faute::Surplus));
    let interieur_app = app[2..].to_vec(); // le DER dans l'OCTET STRING
    let mut interieur_suivi = interieur_app.clone();
    interieur_suivi.extend_from_slice(&nul());
    let p = portrait
        .clone()
        .avec_logiciel(709, &octets(&interieur_suivi));
    assert_eq!(lire(&p.encoder()), Err(Faute::Surplus));
    let mut sequence_app = interieur_app[2..].to_vec(); // { SET, SET }
    sequence_app.extend_from_slice(&nul());
    let p = portrait
        .clone()
        .avec_logiciel(709, &octets(&sequence(&[&sequence_app])));
    assert_eq!(lire(&p.encoder()), Err(Faute::Surplus));
    let paquet_trois = sequence(&[&octets(b"a"), &entier(1), &nul()]);
    let p = portrait.clone().avec_logiciel(
        709,
        &octets(&sequence(&[&ensemble(&[&paquet_trois]), &ensemble(&[])])),
    );
    assert_eq!(lire(&p.encoder()), Err(Faute::Surplus));
}

#[test]
fn un_doublon_et_une_balise_qui_n_est_pas_explicite_sont_refuses() {
    let portrait = Portrait::coherent(b"defi");
    for numero in [1, 2, 3, 5, 10, 701, 702, 704, 705, 706, 709, 718, 719] {
        let mut p = portrait.clone();
        // Le champ est répété dans la liste qui le porte déjà.
        let balise = forge::balise_contextuelle(numero);
        let liste = if p.materiel.iter().any(|c| c.starts_with(&balise)) {
            &mut p.materiel
        } else {
            &mut p.logiciel
        };
        let deja = liste
            .iter()
            .find(|c| c.starts_with(&balise))
            .expect("le portrait cohérent porte ce champ")
            .clone();
        liste.push(deja);
        assert_eq!(
            lire(&p.encoder()),
            Err(Faute::Doublon(numero)),
            "[{numero}]"
        );
    }
    let mut p = portrait.clone();
    p.materiel.push(champ(503, &nul()));
    assert_eq!(lire(&p.encoder()), Err(Faute::Doublon(503)));
    // Une balise universelle là où le schéma veut `[n]`, et une `[n]`
    // primitive.
    let mut p = portrait.clone();
    p.materiel.push(entier(1));
    assert_eq!(lire(&p.encoder()), Err(Faute::BaliseInattendue));
    let mut p = portrait.clone();
    let primitive = element(&[0x9F, 0x85, 0x3D], &[0x01]);
    p.materiel.push(primitive);
    assert_eq!(lire(&p.encoder()), Err(Faute::BaliseInattendue));
}

#[test]
fn les_fautes_der_remontent_avec_leur_nom() {
    let portrait = Portrait::coherent(b"defi");
    // Un entier négatif, un entier vide, un booléen sur deux octets.
    let p = portrait.clone().avec_materiel(2, &[0x02, 0x01, 0x80]);
    assert_eq!(lire(&p.encoder()), Err(Faute::Der(der::Faute::Entier)));
    let p = portrait.clone().avec_materiel(2, &[0x02, 0x00]);
    assert_eq!(lire(&p.encoder()), Err(Faute::Der(der::Faute::Entier)));
    let mut racine = sequence(&[
        &octets(&[0xC3; 32]),
        &[0x01, 0x02, 0xFF, 0xFF],
        &enumere(0),
        &octets(&[0x9B; 32]),
    ]);
    let p = portrait.clone().avec_materiel(704, &racine);
    assert_eq!(lire(&p.encoder()), Err(Faute::Der(der::Faute::Booleen)));
    // Une balise inattendue dans le rootOfTrust.
    racine = sequence(&[&entier(1), &booleen(true), &enumere(0), &octets(&[])]);
    let p = portrait.clone().avec_materiel(704, &racine);
    assert_eq!(lire(&p.encoder()), Err(Faute::Der(der::Faute::Inattendu)));
    // Un `[n]` qui n'enveloppe rien.
    let p = portrait.clone().avec_materiel(702, &[]);
    assert_eq!(lire(&p.encoder()), Err(Faute::Der(der::Faute::Tronque)));
    for faute in [
        Faute::Der(der::Faute::Tronque),
        Faute::Surplus,
        Faute::Doublon(1),
        Faute::BaliseInattendue,
    ] {
        assert!(!faute.to_string().is_empty());
    }
}

#[test]
fn les_valeurs_inconnues_des_enumeres_sont_rendues_telles_quelles() {
    let mut portrait = Portrait::coherent(b"defi");
    portrait.niveau_attestation = 9;
    let portrait = portrait
        .avec_materiel(702, &entier(42))
        .avec_materiel(704, &racine_de_confiance(false, 77));
    let der = portrait.encoder();
    let lue = lire(&der).expect("il se lit");
    assert_eq!(lue.niveau_attestation, asl_keystore::Niveau::Autre(9));
    assert!(!lue.niveau_attestation.est_materiel());
    assert_eq!(lue.materiel.origine, Some(asl_keystore::Origine::Autre(42)));
    let racine = lue.materiel.racine_de_confiance.expect("[704]");
    assert!(!racine.verrouille);
    assert_eq!(racine.demarrage, asl_keystore::Demarrage::Autre(77));
}
