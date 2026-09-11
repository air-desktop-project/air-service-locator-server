//! Le découpage d'un JWS compact.

extern crate alloc;
use alloc::string::String;
use alloc::vec;

use asl_jwt::{Erreur, Jws};

/// base64url sans remplissage, pour fabriquer des segments.
fn b64(source: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    let (mut m, mut b) = (0_u32, 0_u32);
    for octet in source {
        m = m << 8 | u32::from(*octet);
        b = b.saturating_add(8);
        while b >= 6 {
            b = b.saturating_sub(6);
            let index = usize::try_from((m >> b) & 0x3F).expect("six bits");
            s.push(char::from(A[index]));
        }
    }
    if b > 0 {
        let reste = 6_u32.saturating_sub(b);
        let index = usize::try_from((m << reste) & 0x3F).expect("six bits");
        s.push(char::from(A[index]));
    }
    s
}

/// Un jeton `en-tête.charge.signature`.
fn jeton(entete: &[u8], charge: &[u8], signature: &[u8]) -> alloc::string::String {
    alloc::format!("{}.{}.{}", b64(entete), b64(charge), b64(signature))
}

#[test]
fn un_jeton_bien_forme_se_decoupe_et_ses_segments_se_decodent() {
    let entete = br#"{"alg":"ES256"}"#;
    let charge = br#"{"nonce":"abc"}"#;
    let signature = &[0x11_u8; 64][..];
    let brut = jeton(entete, charge, signature);
    let jws = Jws::lire(brut.as_bytes()).expect("un JWS bien formé");

    let mut tampon = [0_u8; 128];
    let n = jws.decoder_entete(&mut tampon).expect("l'en-tête");
    assert_eq!(&tampon[..n], entete);
    let n = jws.decoder_charge(&mut tampon).expect("la charge");
    assert_eq!(&tampon[..n], charge);
    let n = jws.decoder_signature(&mut tampon).expect("la signature");
    assert_eq!(&tampon[..n], signature);
}

#[test]
fn la_partie_signee_est_l_en_tete_et_la_charge_telles_qu_ecrites() {
    // **PAS LES OCTETS DÉCODÉS** : ES256 hache le base64url du fil.
    let brut = jeton(b"h", b"charge", b"sig");
    let jws = Jws::lire(brut.as_bytes()).expect("un JWS");
    let attendu = &brut.as_bytes()[..brut.rfind('.').unwrap()];
    assert_eq!(jws.signe(), attendu);
    // Et c'est exactement `en-tête_b64 . charge_b64`.
    let recompose = alloc::format!(
        "{}.{}",
        core::str::from_utf8(jws.entete_b64()).unwrap(),
        core::str::from_utf8(jws.charge_b64()).unwrap()
    );
    assert_eq!(jws.signe(), recompose.as_bytes());
}

#[test]
fn les_trois_segments_bruts_sont_les_bonnes_tranches() {
    let brut = jeton(b"a", b"bb", b"ccc");
    let jws = Jws::lire(brut.as_bytes()).expect("un JWS");
    assert_eq!(jws.entete_b64(), b64(b"a").as_bytes());
    assert_eq!(jws.charge_b64(), b64(b"bb").as_bytes());
    assert_eq!(jws.signature_b64(), b64(b"ccc").as_bytes());
}

#[test]
fn un_nombre_de_segments_autre_que_trois_est_refuse() {
    for (brut, comptes) in [
        (&b"a"[..], 1),
        (&b"a.b"[..], 2),
        (&b"a.b.c.d"[..], 4),
        (&b"a.b.c.d.e"[..], 5),
    ] {
        assert_eq!(Jws::lire(brut), Err(Erreur::PasTroisSegments { comptes }));
    }
}

#[test]
fn un_segment_vide_est_refuse_par_son_rang() {
    assert_eq!(Jws::lire(b".b.c"), Err(Erreur::SegmentVide { rang: 0 }));
    assert_eq!(Jws::lire(b"a..c"), Err(Erreur::SegmentVide { rang: 1 }));
    assert_eq!(Jws::lire(b"a.b."), Err(Erreur::SegmentVide { rang: 2 }));
}

#[test]
fn un_jeton_vide_n_a_pas_trois_segments() {
    assert_eq!(Jws::lire(b""), Err(Erreur::PasTroisSegments { comptes: 1 }));
}

#[test]
fn un_segment_illisible_remonte_sa_faute_au_decodage() {
    // Le découpage réussit ; c'est le décodage d'un segment qui refuse, et la
    // position est celle du jeton entier.
    let brut = b"aa.b+b.cc";
    let jws = Jws::lire(brut).expect("le découpage passe");
    let mut tampon = [0_u8; 8];
    assert_eq!(
        jws.decoder_charge(&mut tampon),
        Err(Erreur::SymboleInvalide { position: 4 })
    );
}

#[test]
fn chaque_faute_a_sa_phrase() {
    let fautes = [
        Erreur::PasTroisSegments { comptes: 2 },
        Erreur::SegmentVide { rang: 1 },
        Erreur::SymboleInvalide { position: 4 },
        Erreur::LongueurImpossible { rang: 0 },
        Erreur::TamponTropPetit { attendu: 3 },
        Erreur::RemplissageRefuse { position: 7 },
        Erreur::BitsNonNuls { rang: 2 },
    ];
    let mut phrases: vec::Vec<String> = fautes
        .iter()
        .map(alloc::string::ToString::to_string)
        .collect();
    assert!(phrases.iter().all(|p| !p.is_empty()));
    phrases.sort();
    phrases.dedup();
    assert_eq!(phrases.len(), fautes.len());
}
