//! Les vecteurs figés : ce que le codec écrit, octet pour octet, calculé
//! AILLEURS — par `fixtures/vecteurs.py`, depuis `docs/protocole.md` §3 quater
//! seulement, avec une autre bibliothèque Ed25519.
//!
//! **Un aller-retour ne suffit pas** : écrit puis relu par le même code, il
//! passe même quand les deux se trompent de la même façon. Ici, un champ
//! inversé, un séparateur mal recopié, un bourrage déplacé, une IPv4 mal
//! enfouie changent les octets — et l'essai tombe. Si ces constantes doivent
//! changer, c'est que le FORMAT a changé : une rupture, qui se décide.

use core::net::SocketAddr;

use asl_cle::{ClePublique, CleSecrete, identifiant_de_racine};
use asl_echo::{
    Adresse, DefiEcho, Jeton, REPONSE_OCTETS, REQUETE_OCTETS, Reponse, SondeAnnuaire, SondeJeton,
    accepter,
};
use asl_id::{Genre, Identifiant};

const RACINE_ID: &str = "5cd2d858eba0643c13973421f6820160";
const JETON: &str = "015cd2d858eba0643c13973421f6820160707172737475767778797a7b7c7d7e7f17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce808182838485868788898a8b8c8d8e8fd759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48000001a095aff1b8000001a095b0dc186eecc3005e84eb27d997da01503a929e920dbded2e5b0ebde67ca7e699c2277f476947041d98193c810030df7d62b1fccd641c837c63a45ea764ab9245a73b0e";
const SONDE_ANNUAIRE: &str = "0a01d0d1d2d3d4d5d6d7d8d9dadbdcdddedf5cd2d858eba0643c13973421f6820160707172737475767778797a7b7c7d7e7f000001a095b03fd851059c05525104256396a3ea89bc43de9785a7f466d6dcb723f45cd0014fc366371ea91833f263ff03d006dc12c31e6009cea4edaa1b92f582c33474b6f14f0600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const SONDE_JETON: &str = "0a02e0e1e2e3e4e5e6e7e8e9eaebecedeeef015cd2d858eba0643c13973421f6820160707172737475767778797a7b7c7d7e7f17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce808182838485868788898a8b8c8d8e8fd759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48000001a095aff1b8000001a095b0dc186eecc3005e84eb27d997da01503a929e920dbded2e5b0ebde67ca7e699c2277f476947041d98193c810030df7d62b1fccd641c837c63a45ea764ab9245a73b0e958a293e45c6835181f9c488d609917c540621c2a832e1fd99489d5ac0fb0e322e13395bc2fc544c1dcef186bde14a1772130dc51eed43f434f7c976aedc370100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const REPONSE_ANNUAIRE: &str = "0a81d0d1d2d3d4d5d6d7d8d9dadbdcdddedf707172737475767778797a7b7c7d7e7f00000000000000000000ffffcb007107cfdb5cd2d858eba0643c13973421f68201606857f63acf77a46d3d85c68c59225e7faa53ef9163001170e659c612bf2bdf708efb123f61e549b5bd30755cef2b70e296286a15760b6cf03028f73b7e9ae50a";
const REPONSE_JETON: &str = "0a81e0e1e2e3e4e5e6e7e8e9eaebecedeeef707172737475767778797a7b7c7d7e7f20010db8000000000000000000001c2da395808182838485868788898a8b8c8d8e8fba8497df3e9c525a6413c42754bc87df53520cb1b1bf466713101470e894264cb6a755573baaa0efa05254929a1f036cec66005823bcf80713dc2fb1a464750d";

fn octets(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks(2)
        .map(|paire| u8::from_str_radix(std::str::from_utf8(paire).unwrap(), 16).unwrap())
        .collect()
}

fn racine() -> CleSecrete {
    CleSecrete::depuis_entropie([0x11; 32])
}

fn cible() -> CleSecrete {
    CleSecrete::depuis_entropie([0x33; 32])
}

fn sondeur() -> CleSecrete {
    CleSecrete::depuis_entropie([0x44; 32])
}

fn m(premier: u8) -> Identifiant {
    let mut seize = [0; 16];
    for (place, octet) in seize.iter_mut().zip(premier..) {
        *place = octet;
    }
    Identifiant::depuis_entropie(Genre::Machine, seize)
}

fn defi(premier: u8) -> DefiEcho {
    let mut seize = [0; 16];
    for (place, octet) in seize.iter_mut().zip(premier..) {
        *place = octet;
    }
    DefiEcho::depuis_octets(seize)
}

const EMIS_A: u64 = 1_789_217_731_000;
const EMISE_A: u64 = 1_789_217_751_000;

fn jeton() -> Jeton {
    Jeton::emettre(
        &racine(),
        m(0x70),
        cible().publique(),
        m(0x80),
        sondeur().publique(),
        EMIS_A,
    )
    .unwrap()
}

#[test]
fn la_racine_du_vecteur_est_celle_qu_asl_cle_deduit() {
    assert_eq!(
        identifiant_de_racine(&racine().publique())
            .octets()
            .as_slice(),
        octets(RACINE_ID)
    );
}

#[test]
fn le_jeton_est_celui_du_vecteur() {
    let jeton = jeton();
    assert_eq!(jeton.octets().as_slice(), octets(JETON));
    assert_eq!(jeton.hex().as_str(), JETON);
    // Et il se relit à l'identique, en octets comme en hexadécimal.
    assert_eq!(Jeton::lire(&octets(JETON)).unwrap(), jeton);
    assert_eq!(Jeton::lire_hex(JETON).unwrap(), jeton);
    assert_eq!(Jeton::lire_hex(&JETON.to_uppercase()).unwrap(), jeton);
    assert_eq!(jeton.expire_a(), 1_789_217_791_000);
}

#[test]
fn la_sonde_d_annuaire_est_celle_du_vecteur() {
    let annuaire = identifiant_de_racine(&racine().publique());
    let sonde = SondeAnnuaire::signer(defi(0xD0), annuaire, m(0x70), EMISE_A, &racine()).unwrap();
    let attendu = octets(SONDE_ANNUAIRE);
    assert_eq!(attendu.len(), REQUETE_OCTETS);
    assert_eq!(sonde.octets().as_slice(), attendu);
    assert_eq!(SondeAnnuaire::lire(&attendu).unwrap(), sonde);
}

#[test]
fn la_sonde_munie_du_jeton_est_celle_du_vecteur() {
    let sonde = SondeJeton::signer(defi(0xE0), jeton(), &sondeur());
    let attendu = octets(SONDE_JETON);
    assert_eq!(attendu.len(), REQUETE_OCTETS);
    assert_eq!(sonde.octets().as_slice(), attendu);
    assert_eq!(SondeJeton::lire(&attendu).unwrap(), sonde);
}

#[test]
fn les_reponses_sont_celles_des_vecteurs() {
    let racine_id = identifiant_de_racine(&racine().publique());
    let vue: SocketAddr = "203.0.113.7:53211".parse().unwrap();
    let reponse = Reponse::signer(
        defi(0xD0),
        m(0x70),
        Adresse::depuis_source(vue),
        racine_id,
        &cible(),
    )
    .unwrap();
    let attendu = octets(REPONSE_ANNUAIRE);
    assert_eq!(attendu.len(), REPONSE_OCTETS);
    assert_eq!(reponse.octets().as_slice(), attendu);
    let relue = Reponse::lire(&attendu).unwrap();
    assert_eq!(relue, reponse);
    assert_eq!(relue.adresse().source(), vue, "une IPv4 se relit en IPv4");

    let vue: SocketAddr = "[2001:db8::1c2d]:41877".parse().unwrap();
    let reponse = Reponse::signer(
        defi(0xE0),
        m(0x70),
        Adresse::depuis_source(vue),
        m(0x80),
        &cible(),
    )
    .unwrap();
    assert_eq!(reponse.octets().as_slice(), octets(REPONSE_JETON));
    assert_eq!(
        Reponse::lire(&octets(REPONSE_JETON))
            .unwrap()
            .adresse()
            .source(),
        vue
    );
}

/// **Le tour entier, sur les octets du vecteur** : l'écho accepte la sonde
/// lue du fil, sa réponse est celle du vecteur, et le sondeur la vérifie sous
/// la clé que le jeton porte.
#[test]
fn le_tour_entier_sur_les_vecteurs() {
    let moi = m(0x70);
    let ma_cle = cible().publique();
    let racine_id = identifiant_de_racine(&racine().publique());
    let racines = |n: Identifiant| (n == racine_id).then(|| racine().publique());
    let aucun = |_: Identifiant| -> Option<ClePublique> { None };

    // asl ping.
    let acceptee = accepter(
        &octets(SONDE_JETON),
        moi,
        &ma_cle,
        &aucun,
        &racines,
        EMIS_A + 1_000,
    )
    .expect("la sonde du vecteur est acceptée");
    assert_eq!(acceptee.sondeur(), m(0x80));
    let vue: SocketAddr = "[2001:db8::1c2d]:41877".parse().unwrap();
    let reponse = acceptee.repondre(vue, &cible());
    assert_eq!(reponse.octets().as_slice(), octets(REPONSE_JETON));
    let jeton = Jeton::lire_hex(JETON).unwrap();
    Reponse::lire(&octets(REPONSE_JETON))
        .unwrap()
        .verifier(&defi(0xE0), moi, m(0x80), &jeton.cle_cible())
        .expect("la preuve tient sous la clé que le jeton porte");

    // La sonde de la racine.
    let acceptee = accepter(
        &octets(SONDE_ANNUAIRE),
        moi,
        &ma_cle,
        &racines,
        &aucun,
        EMISE_A,
    )
    .expect("la sonde d'annuaire du vecteur est acceptée");
    assert_eq!(acceptee.sondeur(), racine_id);
    assert_eq!(acceptee.defi(), defi(0xD0));
    let vue: SocketAddr = "203.0.113.7:53211".parse().unwrap();
    assert_eq!(
        acceptee.repondre(vue, &cible()).octets().as_slice(),
        octets(REPONSE_ANNUAIRE)
    );
}
