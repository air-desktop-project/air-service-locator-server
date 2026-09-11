//! Les clés P-256 des appareils, et ce que leur message LIE.
//!
//! Même plan que `signature.rs` : ce qui compte n'est pas qu'une signature juste
//! passe, c'est qu'un champ changé la fasse tomber. Et deux choses de plus,
//! qu'Ed25519 n'avait pas : un scalaire secret peut être invalide, et un point
//! public compressé peut ne pas être sur la courbe.

use asl_cle::{
    CLE_APPAREIL_OCTETS, CleAppareil, CleSecreteAppareil, DOMAINE_POSSESSION, Defi, Faute,
    LiaisonDeCanal, MESSAGE_POSSESSION_APPAREIL_OCTETS, SIGNATURE_APPAREIL_OCTETS,
    SignatureAppareil, message_a_signer, message_de_possession_appareil,
};
use asl_id::{Genre, Identifiant};

fn appareil(marque: u8) -> Identifiant {
    let mut octets = [0x11; 16];
    octets[0] = marque;
    Identifiant::depuis_entropie(Genre::Appareil, octets)
}

fn cle() -> CleSecreteAppareil {
    CleSecreteAppareil::depuis_entropie([0x42; 32]).expect("un scalaire valide")
}

fn defi(marque: u8) -> Defi {
    let mut octets = [0x01; 32];
    octets[0] = marque;
    Defi::depuis_octets(octets)
}

fn liaison(marque: u8) -> LiaisonDeCanal {
    let mut octets = [0x02; 32];
    octets[0] = marque;
    LiaisonDeCanal::depuis_octets(octets)
}

// ── Le tour normal ──────────────────────────────────────────────────────────

#[test]
fn une_signature_juste_verifie() {
    let secrete = cle();
    let publique = secrete.publique();
    let signature = secrete.signer(appareil(1), &defi(1), &liaison(1)).unwrap();
    assert!(publique.verifie(appareil(1), &defi(1), &liaison(1), &signature));
    assert_eq!(signature.octets().len(), SIGNATURE_APPAREIL_OCTETS);
}

#[test]
fn la_cle_publique_se_relit_compressee() {
    let publique = cle().publique();
    let octets = publique.octets();
    assert_eq!(octets.len(), CLE_APPAREIL_OCTETS);
    assert!(
        matches!(octets[0], 0x02 | 0x03),
        "SEC1 compressé commence par 02 ou 03"
    );
    let relue = CleAppareil::depuis_octets(octets).unwrap();
    assert_eq!(relue, publique);
}

#[test]
fn la_signature_est_deterministe() {
    // RFC 6979 : pas d'aléa à fournir, et une signature qui ne dépend que de la
    // clé et du message. Deux appels rendent les mêmes octets.
    let secrete = cle();
    let une = secrete.signer(appareil(1), &defi(1), &liaison(1)).unwrap();
    let deux = secrete.signer(appareil(1), &defi(1), &liaison(1)).unwrap();
    assert_eq!(une, deux);
    assert_eq!(SignatureAppareil::depuis_octets(*une.octets()), une);
}

// ── Ce que le message LIE ───────────────────────────────────────────────────

#[test]
fn changer_l_appareil_invalide_la_signature() {
    let secrete = cle();
    let signature = secrete.signer(appareil(1), &defi(1), &liaison(1)).unwrap();
    assert!(
        !secrete
            .publique()
            .verifie(appareil(2), &defi(1), &liaison(1), &signature)
    );
}

#[test]
fn changer_le_defi_invalide_la_signature() {
    // Sans ce champ, le REJEU est ouvert.
    let secrete = cle();
    let signature = secrete.signer(appareil(1), &defi(1), &liaison(1)).unwrap();
    assert!(
        !secrete
            .publique()
            .verifie(appareil(1), &defi(2), &liaison(1), &signature)
    );
}

#[test]
fn changer_la_liaison_invalide_la_signature() {
    // Sans ce champ, le RELAIS est ouvert.
    let secrete = cle();
    let signature = secrete.signer(appareil(1), &defi(1), &liaison(1)).unwrap();
    assert!(
        !secrete
            .publique()
            .verifie(appareil(1), &defi(1), &liaison(2), &signature)
    );
}

#[test]
fn une_autre_cle_ne_verifie_pas() {
    let secrete = cle();
    let autre = CleSecreteAppareil::depuis_entropie([0x43; 32]).unwrap();
    let signature = secrete.signer(appareil(1), &defi(1), &liaison(1)).unwrap();
    assert!(
        !autre
            .publique()
            .verifie(appareil(1), &defi(1), &liaison(1), &signature)
    );
}

#[test]
fn le_message_est_celui_des_machines() {
    // Rien dans le message ne désigne la courbe : c'est la clé rangée dans
    // l'annuaire qui dit comment vérifier. Un appareil et une machine qui
    // auraient le même identifiant signeraient les mêmes octets — et c'est
    // le GENRE, dans le message, qui fait qu'ils ne l'ont jamais.
    let m = message_a_signer(appareil(1), &defi(1), &liaison(1));
    assert!(m.starts_with(asl_cle::DOMAINE));
    assert_eq!(m[asl_cle::DOMAINE.len()], Genre::Appareil.prefixe());
}

// ── Le genre ────────────────────────────────────────────────────────────────

#[test]
fn signer_pour_une_machine_est_refuse_a_la_signature() {
    let machine = Identifiant::depuis_entropie(Genre::Machine, [0x11; 16]);
    assert_eq!(
        cle().signer(machine, &defi(1), &liaison(1)).unwrap_err(),
        Faute::PasUnAppareil {
            obtenu: Genre::Machine
        }
    );
}

#[test]
fn verifier_pour_une_machine_est_refuse_meme_avec_une_signature_juste() {
    // On fabrique la signature qu'un appareil ferait, puis on la présente
    // sous un identifiant de machine de mêmes octets. Le genre entre dans le
    // message, donc ce n'est pas le même — mais on refuse AVANT de vérifier,
    // pour que la faute se voie.
    let secrete = cle();
    let signature = secrete.signer(appareil(1), &defi(1), &liaison(1)).unwrap();
    let mut octets = [0x11; 16];
    octets[0] = 1;
    let machine = Identifiant::depuis_entropie(Genre::Machine, octets);
    assert!(
        !secrete
            .publique()
            .verifie(machine, &defi(1), &liaison(1), &signature)
    );
}

// ── La possession ───────────────────────────────────────────────────────────

#[test]
fn une_preuve_de_possession_juste_verifie() {
    let secrete = cle();
    let preuve = secrete.prouver_la_possession(&defi(1), &liaison(1));
    assert!(
        secrete
            .publique()
            .prouve_sa_possession(&defi(1), &liaison(1), &preuve)
    );
}

#[test]
fn la_preuve_de_possession_lie_le_defi_la_liaison_et_la_cle() {
    let secrete = cle();
    let preuve = secrete.prouver_la_possession(&defi(1), &liaison(1));
    let publique = secrete.publique();
    assert!(!publique.prouve_sa_possession(&defi(2), &liaison(1), &preuve));
    assert!(!publique.prouve_sa_possession(&defi(1), &liaison(2), &preuve));
    let autre = CleSecreteAppareil::depuis_entropie([0x43; 32]).unwrap();
    assert!(
        !autre
            .publique()
            .prouve_sa_possession(&defi(1), &liaison(1), &preuve)
    );
}

#[test]
fn une_preuve_de_possession_ne_vaut_pas_authentification_ni_l_inverse() {
    // Deux domaines, deux messages : une signature de l'un ne vérifie pas
    // comme l'autre, même clé, même défi, même liaison.
    let secrete = cle();
    let preuve = secrete.prouver_la_possession(&defi(1), &liaison(1));
    let signature = secrete.signer(appareil(1), &defi(1), &liaison(1)).unwrap();
    let publique = secrete.publique();
    assert!(!publique.verifie(appareil(1), &defi(1), &liaison(1), &preuve));
    assert!(!publique.prouve_sa_possession(&defi(1), &liaison(1), &signature));
}

#[test]
fn le_message_de_possession_a_la_taille_annoncee_et_porte_la_cle() {
    let publique = cle().publique();
    let m = message_de_possession_appareil(&publique, &defi(1), &liaison(1));
    assert_eq!(m.len(), MESSAGE_POSSESSION_APPAREIL_OCTETS);
    assert!(m.starts_with(DOMAINE_POSSESSION));
    let debut = DOMAINE_POSSESSION.len();
    assert_eq!(
        &m[debut..debut + CLE_APPAREIL_OCTETS],
        &publique.octets()[..]
    );
}

// ── Ce qu'Ed25519 n'avait pas ───────────────────────────────────────────────

#[test]
fn un_scalaire_nul_n_est_pas_une_cle_secrete() {
    assert!(matches!(
        CleSecreteAppareil::depuis_entropie([0; 32]),
        Err(Faute::CleSecreteInvalide)
    ));
    // Et l'ordre de la courbe non plus — le plus grand scalaire invalide qui
    // ne soit pas « tout à 0xff ».
    let ordre: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    assert!(matches!(
        CleSecreteAppareil::depuis_entropie(ordre),
        Err(Faute::CleSecreteInvalide)
    ));
}

#[test]
fn un_point_hors_de_la_courbe_n_est_pas_une_cle_publique() {
    // Un préfixe qui n'est pas SEC1.
    let mut octets = cle().publique().octets();
    octets[0] = 0x04;
    assert!(matches!(
        CleAppareil::depuis_octets(octets),
        Err(Faute::ClePubliqueInvalide)
    ));
    // Un x pour lequel x³ − 3x + b n'est pas un carré : environ un sur deux.
    // On cherche le premier, pour que l'essai ne dépende pas d'une constante
    // qu'on aurait eu tort de croire hors courbe.
    let mut trouve = false;
    for x in 0_u8..=255 {
        let mut candidat = [0_u8; CLE_APPAREIL_OCTETS];
        candidat[0] = 0x02;
        candidat[32] = x;
        if CleAppareil::depuis_octets(candidat).is_err() {
            trouve = true;
            break;
        }
    }
    assert!(trouve, "aucun x sur 256 hors de la courbe : improbable");
}

#[test]
fn soixante_quatre_octets_qui_ne_sont_pas_une_signature_ne_verifient_pas() {
    // r = 0 n'est pas une signature : `from_slice` le refuse, et c'est là que
    // ces octets sont jugés — pas à `depuis_octets`, qui ne juge rien.
    let nulle = SignatureAppareil::depuis_octets([0; SIGNATURE_APPAREIL_OCTETS]);
    let publique = cle().publique();
    assert!(!publique.verifie(appareil(1), &defi(1), &liaison(1), &nulle));
    assert!(!publique.prouve_sa_possession(&defi(1), &liaison(1), &nulle));
}
