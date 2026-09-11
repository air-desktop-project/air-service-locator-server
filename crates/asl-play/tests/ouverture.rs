//! Ouvrir un jeton Play Integrity : le tour normal, et chaque refus.

mod forge;

extern crate alloc;

use asl_play::{Clefs, Refus, ouvrir};
use forge::{Banc, b64, emballer};

const VERDICT: &[u8] = br#"{"requestDetails":{"nonce":"abc"},"deviceIntegrity":{}}"#;

fn clefs<'a>(kek: &'a [u8; 32], spki: &'a [u8]) -> Clefs<'a> {
    Clefs {
        dechiffrement: kek,
        verification: spki,
    }
}

#[test]
fn un_jeton_bien_forme_s_ouvre_sur_son_verdict() {
    let banc = Banc::nouveau();
    let spki = banc.verification_spki();
    let jeton = banc.jeton(VERDICT);
    let charge = ouvrir(jeton.as_bytes(), &clefs(&banc.kek, &spki)).expect("il s'ouvre");
    assert_eq!(charge, VERDICT);
}

#[test]
fn une_cle_emballee_de_mauvaise_taille_est_refusee() {
    // On remplace le segment de clé par un plus court : `deballer` refuse sur
    // la longueur, avant tout déchiffrement.
    let banc = Banc::nouveau();
    let spki = banc.verification_spki();
    let jeton = banc.jeton(VERDICT);
    let mut segments: alloc::vec::Vec<alloc::string::String> = jeton
        .split('.')
        .map(alloc::string::ToString::to_string)
        .collect();
    segments[1] = b64(&[0x00_u8; 16]); // 16 octets au lieu de 40
    let jeton = segments.join(".");
    assert_eq!(
        ouvrir(jeton.as_bytes(), &clefs(&banc.kek, &spki)),
        Err(Refus::Deballage(asl_play::FauteDeballage::Longueur {
            obtenue: 16
        }))
    );
    let _ = emballer(&[0; 32], &[0; 32]);
}

#[test]
fn une_signature_fausse_est_refusee() {
    let banc = Banc::nouveau();
    let spki = banc.verification_spki();
    // On abîme la charge après signature : le JWS ne vérifie plus.
    let jws = banc.signer(VERDICT);
    let mut octets = jws.into_bytes();
    let dernier = octets.len() - 1;
    octets[dernier] ^= 0x01;
    let jeton = banc.envelopper(&octets, &banc.kek);
    assert_eq!(
        ouvrir(jeton.as_bytes(), &clefs(&banc.kek, &spki)),
        Err(Refus::SignatureFausse)
    );
}

#[test]
fn une_autre_cle_de_google_ne_verifie_pas() {
    let banc = Banc::nouveau();
    let autre = Banc::nouveau_avec(0x99);
    let jeton = banc.jeton(VERDICT);
    // Le jeton est de `banc`, mais on présente la clé d'`autre`.
    let spki = autre.verification_spki();
    assert_eq!(
        ouvrir(jeton.as_bytes(), &clefs(&banc.kek, &spki)),
        Err(Refus::SignatureFausse)
    );
}

#[test]
fn une_mauvaise_cle_de_dechiffrement_est_refusee() {
    let banc = Banc::nouveau();
    let spki = banc.verification_spki();
    let jeton = banc.jeton(VERDICT);
    let mauvaise = [0x00_u8; 32];
    assert_eq!(
        ouvrir(jeton.as_bytes(), &clefs(&mauvaise, &spki)),
        Err(Refus::Deballage(asl_play::FauteDeballage::TemoinFaux))
    );
}

#[test]
fn un_chiffre_modifie_echoue_a_l_authentification() {
    let banc = Banc::nouveau();
    let spki = banc.verification_spki();
    let jeton = banc.jeton(VERDICT);
    // Changer le premier symbole du segment chiffré (le quatrième) pour un
    // autre symbole base64url valide fait échouer l'authentification du GCM.
    let mut segments: alloc::vec::Vec<alloc::string::String> = jeton
        .split('.')
        .map(alloc::string::ToString::to_string)
        .collect();
    let premier = segments[3].as_bytes()[0];
    let remplace = if premier == b'A' { 'B' } else { 'A' };
    segments[3] = alloc::format!("{remplace}{}", &segments[3][1..]);
    let jeton = segments.join(".");
    assert_eq!(
        ouvrir(jeton.as_bytes(), &clefs(&banc.kek, &spki)),
        Err(Refus::Dechiffrement)
    );
}

#[test]
fn une_enveloppe_d_un_autre_algorithme_est_refusee() {
    let banc = Banc::nouveau();
    let spki = banc.verification_spki();
    // Un JWE dont l'en-tête annonce `dir` au lieu de `A256KW`.
    let entete = b64(br#"{"alg":"dir","enc":"A256GCM"}"#);
    let jeton = alloc::format!("{entete}.aa.bb.cc.dd");
    assert_eq!(
        ouvrir(jeton.as_bytes(), &clefs(&banc.kek, &spki)),
        Err(Refus::EnveloppeInattendue)
    );
}

#[test]
fn ce_qui_n_est_pas_un_jwe_est_refuse() {
    let banc = Banc::nouveau();
    let spki = banc.verification_spki();
    assert!(matches!(
        ouvrir(b"pas.un.jwe", &clefs(&banc.kek, &spki)),
        Err(Refus::Jwe(_))
    ));
}

#[test]
fn un_jeton_trop_long_est_refuse_sans_etre_lu() {
    let banc = Banc::nouveau();
    let spki = banc.verification_spki();
    let enorme = alloc::vec![b'a'; asl_play::JETON_MAX + 1];
    assert_eq!(
        ouvrir(&enorme, &clefs(&banc.kek, &spki)),
        Err(Refus::TropLong {
            octets: asl_play::JETON_MAX + 1
        })
    );
}

#[test]
fn une_cle_de_google_illisible_est_refusee() {
    let banc = Banc::nouveau();
    let jeton = banc.jeton(VERDICT);
    // Un SPKI qui n'en est pas un : la signature ne peut pas se vérifier.
    assert_eq!(
        ouvrir(jeton.as_bytes(), &clefs(&banc.kek, &[0x30, 0x00])),
        Err(Refus::CleIllisible)
    );
}

#[test]
fn chaque_refus_a_sa_phrase() {
    let refus = [
        Refus::TropLong { octets: 9000 },
        Refus::Jwe(asl_jwt::Erreur::SegmentVide { rang: 0 }),
        Refus::Jws(asl_jwt::Erreur::SegmentVide { rang: 0 }),
        Refus::EnveloppeInattendue,
        Refus::IvInvalide,
        Refus::EtiquetteInvalide,
        Refus::Deballage(asl_play::FauteDeballage::TemoinFaux),
        Refus::Dechiffrement,
        Refus::SignatureInattendue,
        Refus::CleIllisible,
        Refus::SignatureFausse,
    ];
    let mut phrases: alloc::vec::Vec<alloc::string::String> = refus
        .iter()
        .map(alloc::string::ToString::to_string)
        .collect();
    assert!(phrases.iter().all(|p| !p.is_empty()));
    phrases.sort();
    phrases.dedup();
    assert_eq!(phrases.len(), refus.len());
}

// ── Les refus qui demandent un jeton fabriqué exprès ────────────────────────

/// Un remplaçant de champ dans un en-tête, pour dépasser 256 octets décodés.
fn bourrage(n: usize) -> alloc::string::String {
    core::iter::repeat_n('x', n).collect()
}

#[test]
fn une_signature_de_mauvaise_longueur_est_refusee() {
    let banc = Banc::nouveau();
    let spki = banc.verification_spki();
    let jws = banc.jws_signature_courte(VERDICT);
    let jeton = banc.envelopper(jws.as_bytes(), &banc.kek);
    assert_eq!(
        ouvrir(jeton.as_bytes(), &clefs(&banc.kek, &spki)),
        Err(Refus::SignatureFausse)
    );
}

#[test]
fn un_jws_d_un_autre_algorithme_est_refuse() {
    let banc = Banc::nouveau();
    let spki = banc.verification_spki();
    let jws = banc.signer_avec_entete(br#"{"alg":"RS256"}"#, VERDICT);
    let jeton = banc.envelopper(jws.as_bytes(), &banc.kek);
    assert_eq!(
        ouvrir(jeton.as_bytes(), &clefs(&banc.kek, &spki)),
        Err(Refus::SignatureInattendue)
    );
}

#[test]
fn un_en_tete_de_jws_demesure_est_refuse() {
    // Plus de 256 octets décodés : le lecteur d'en-tête renonce, et le jeton
    // est traité comme n'annonçant pas ES256.
    let banc = Banc::nouveau();
    let spki = banc.verification_spki();
    let entete = alloc::format!(r#"{{"alg":"ES256","x":"{}"}}"#, bourrage(300));
    let jws = banc.signer_avec_entete(entete.as_bytes(), VERDICT);
    let jeton = banc.envelopper(jws.as_bytes(), &banc.kek);
    assert_eq!(
        ouvrir(jeton.as_bytes(), &clefs(&banc.kek, &spki)),
        Err(Refus::SignatureInattendue)
    );
}

#[test]
fn un_en_tete_de_jwe_demesure_est_refuse() {
    let banc = Banc::nouveau();
    let spki = banc.verification_spki();
    let entete = alloc::format!(
        r#"{{"alg":"A256KW","enc":"A256GCM","x":"{}"}}"#,
        bourrage(300)
    );
    let jeton = banc.envelopper_avec_entete(entete.as_bytes(), b"peu importe", &banc.kek);
    assert_eq!(
        ouvrir(jeton.as_bytes(), &clefs(&banc.kek, &spki)),
        Err(Refus::EnveloppeInattendue)
    );
}

#[test]
fn un_en_tete_de_jwe_sans_alg_est_refuse() {
    let banc = Banc::nouveau();
    let spki = banc.verification_spki();
    let jeton = banc.envelopper_avec_entete(br#"{"enc":"A256GCM"}"#, b"x", &banc.kek);
    assert_eq!(
        ouvrir(jeton.as_bytes(), &clefs(&banc.kek, &spki)),
        Err(Refus::EnveloppeInattendue)
    );
}

#[test]
fn un_iv_de_mauvaise_taille_est_refuse() {
    // On remplace le segment iv (le troisième) par un plus court.
    let banc = Banc::nouveau();
    let spki = banc.verification_spki();
    let jeton = banc.jeton(VERDICT);
    let mut segments: alloc::vec::Vec<alloc::string::String> = jeton
        .split('.')
        .map(alloc::string::ToString::to_string)
        .collect();
    segments[2] = b64(&[0x00_u8; 8]); // 8 octets au lieu de 12
    let jeton = segments.join(".");
    assert_eq!(
        ouvrir(jeton.as_bytes(), &clefs(&banc.kek, &spki)),
        Err(Refus::IvInvalide)
    );
}

#[test]
fn une_etiquette_de_mauvaise_taille_est_refusee() {
    let banc = Banc::nouveau();
    let spki = banc.verification_spki();
    let jeton = banc.jeton(VERDICT);
    let mut segments: alloc::vec::Vec<alloc::string::String> = jeton
        .split('.')
        .map(alloc::string::ToString::to_string)
        .collect();
    segments[4] = b64(&[0x00_u8; 8]); // 8 octets au lieu de 16
    let jeton = segments.join(".");
    assert_eq!(
        ouvrir(jeton.as_bytes(), &clefs(&banc.kek, &spki)),
        Err(Refus::EtiquetteInvalide)
    );
}

#[test]
fn un_en_tete_dont_la_valeur_est_trop_courte_est_refuse() {
    // `enc` est présent, mais ce qui le suit est plus court que « A256GCM » :
    // la recherche s'arrête faute de place, et l'enveloppe est refusée.
    let banc = Banc::nouveau();
    let spki = banc.verification_spki();
    let jeton = banc.envelopper_avec_entete(br#"{"alg":"A256KW","enc":"A"}"#, b"x", &banc.kek);
    assert_eq!(
        ouvrir(jeton.as_bytes(), &clefs(&banc.kek, &spki)),
        Err(Refus::EnveloppeInattendue)
    );
}

#[test]
fn un_segment_de_jwe_illisible_est_refuse() {
    // `Jwe::lire` ne valide pas le base64url des segments — le décodage le
    // fait. Un `+` (hors alphabet base64url) dans la clé, l'iv, le chiffré ou
    // l'étiquette est donc refusé au décodage de CE segment.
    let banc = Banc::nouveau();
    let spki = banc.verification_spki();
    let jeton = banc.jeton(VERDICT);
    for rang in [1_usize, 2, 3, 4] {
        let mut segments: alloc::vec::Vec<alloc::string::String> = jeton
            .split('.')
            .map(alloc::string::ToString::to_string)
            .collect();
        segments[rang] = alloc::string::String::from("c+c");
        let abime = segments.join(".");
        assert!(
            matches!(
                ouvrir(abime.as_bytes(), &clefs(&banc.kek, &spki)),
                Err(Refus::Jwe(_))
            ),
            "segment {rang}"
        );
    }
}

#[test]
fn un_contenu_dechiffre_qui_n_est_pas_un_jws_est_refuse() {
    // On enveloppe des octets qui ne forment pas un JWS : le déchiffrement
    // réussit, mais le découpage du contenu échoue.
    let banc = Banc::nouveau();
    let spki = banc.verification_spki();
    let jeton = banc.envelopper(b"ceci n'est pas un jws", &banc.kek);
    assert!(matches!(
        ouvrir(jeton.as_bytes(), &clefs(&banc.kek, &spki)),
        Err(Refus::Jws(_))
    ));
}

#[test]
fn une_signature_a_scalaire_nul_est_refusee() {
    // Soixante-quatre octets à zéro font une signature de la bonne LONGUEUR,
    // mais `r = s = 0` n'est pas une signature : `from_slice` la refuse.
    let banc = Banc::nouveau();
    let spki = banc.verification_spki();
    let entete = b64(br#"{"alg":"ES256"}"#);
    let charge = b64(VERDICT);
    let jws = alloc::format!("{entete}.{charge}.{}", b64(&[0x00_u8; 64]));
    let jeton = banc.envelopper(jws.as_bytes(), &banc.kek);
    assert_eq!(
        ouvrir(jeton.as_bytes(), &clefs(&banc.kek, &spki)),
        Err(Refus::SignatureFausse)
    );
}

#[test]
fn une_charge_illisible_est_refusee() {
    // Le JWS est bien signé (la signature couvre l'ASCII du fil), mais la
    // charge n'est pas du base64url : elle ne se décode pas.
    let banc = Banc::nouveau();
    let spki = banc.verification_spki();
    let entete = b64(br#"{"alg":"ES256"}"#);
    let charge = alloc::string::String::from("ch+rge");
    let signe = alloc::format!("{entete}.{charge}");
    use p256::ecdsa::signature::Signer;
    let signature: p256::ecdsa::Signature = banc.signature.sign(signe.as_bytes());
    let jws = alloc::format!("{signe}.{}", b64(&signature.to_bytes()));
    let jeton = banc.envelopper(jws.as_bytes(), &banc.kek);
    assert!(matches!(
        ouvrir(jeton.as_bytes(), &clefs(&banc.kek, &spki)),
        Err(Refus::Jws(_))
    ));
}
