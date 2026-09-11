//! Le découpage d'un JWE compact.

extern crate alloc;
use alloc::string::String;
use alloc::vec;

use asl_jwt::{Erreur, Jwe};

fn b64(source: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    let (mut m, mut b) = (0_u32, 0_u32);
    for octet in source {
        m = m << 8 | u32::from(*octet);
        b = b.saturating_add(8);
        while b >= 6 {
            b = b.saturating_sub(6);
            s.push(char::from(
                A[usize::try_from((m >> b) & 0x3F).expect("six bits")],
            ));
        }
    }
    if b > 0 {
        let reste = 6_u32.saturating_sub(b);
        s.push(char::from(
            A[usize::try_from((m << reste) & 0x3F).expect("six bits")],
        ));
    }
    s
}

/// Un JWE `en-tête.clé.iv.chiffré.étiquette`.
fn jwe(entete: &[u8], cle: &[u8], iv: &[u8], chiffre: &[u8], etiquette: &[u8]) -> String {
    alloc::format!(
        "{}.{}.{}.{}.{}",
        b64(entete),
        b64(cle),
        b64(iv),
        b64(chiffre),
        b64(etiquette)
    )
}

#[test]
fn un_jwe_bien_forme_se_decoupe_et_ses_segments_se_decodent() {
    let entete = br#"{"alg":"A256KW","enc":"A256GCM"}"#;
    let cle = &[0x11_u8; 40][..];
    let iv = &[0x22_u8; 12][..];
    let chiffre = &[0x33_u8; 80][..];
    let etiquette = &[0x44_u8; 16][..];
    let brut = jwe(entete, cle, iv, chiffre, etiquette);
    let jwe = Jwe::lire(brut.as_bytes()).expect("un JWE bien formé");

    let mut tampon = [0_u8; 128];
    let n = jwe.decoder_entete(&mut tampon).expect("en-tête");
    assert_eq!(&tampon[..n], entete);
    let n = jwe.decoder_cle(&mut tampon).expect("clé");
    assert_eq!(&tampon[..n], cle);
    let n = jwe.decoder_iv(&mut tampon).expect("iv");
    assert_eq!(&tampon[..n], iv);
    let n = jwe.decoder_chiffre(&mut tampon).expect("chiffré");
    assert_eq!(&tampon[..n], chiffre);
    let n = jwe.decoder_etiquette(&mut tampon).expect("étiquette");
    assert_eq!(&tampon[..n], etiquette);
}

#[test]
fn l_en_tete_brut_est_la_donnee_authentifiee() {
    // Rendu tel quel : c'est l'AAD du GCM.
    let brut = jwe(b"tete", b"cle", b"iv", b"ct", b"tag");
    let jwe = Jwe::lire(brut.as_bytes()).expect("un JWE");
    assert_eq!(jwe.entete_b64(), b64(b"tete").as_bytes());
    assert_eq!(
        jwe.entete_b64(),
        &brut.as_bytes()[..brut.find('.').unwrap()]
    );
}

#[test]
fn une_cle_vide_est_permise_c_est_le_mode_dir() {
    // `alg=dir` n'a pas de clé à déballer : le segment est vide, et le
    // découpage l'accepte. C'est le déchiffrement qui dira si `dir` passe.
    let brut = alloc::format!(
        "{}..{}.{}.{}",
        b64(b"tete"),
        b64(b"iv"),
        b64(b"ct"),
        b64(b"tag")
    );
    let jwe = Jwe::lire(brut.as_bytes()).expect("clé vide permise");
    let mut tampon = [0_u8; 8];
    assert_eq!(jwe.decoder_cle(&mut tampon), Ok(0));
}

#[test]
fn un_nombre_de_segments_autre_que_cinq_est_refuse() {
    for (brut, comptes) in [
        (&b"a.b.c"[..], 3),
        (&b"a.b.c.d"[..], 4),
        (&b"a.b.c.d.e.f"[..], 6),
    ] {
        assert_eq!(Jwe::lire(brut), Err(Erreur::PasCinqSegments { comptes }));
    }
}

#[test]
fn un_segment_obligatoire_vide_est_refuse_par_son_rang() {
    assert_eq!(Jwe::lire(b".b.c.d.e"), Err(Erreur::SegmentVide { rang: 0 }));
    assert_eq!(Jwe::lire(b"a.b..d.e"), Err(Erreur::SegmentVide { rang: 2 }));
    assert_eq!(Jwe::lire(b"a.b.c..e"), Err(Erreur::SegmentVide { rang: 3 }));
    assert_eq!(Jwe::lire(b"a.b.c.d."), Err(Erreur::SegmentVide { rang: 4 }));
}

#[test]
fn un_segment_illisible_remonte_sa_faute_a_la_bonne_position() {
    let brut = b"aa.bb.c+c.dd.ee";
    let jwe = Jwe::lire(brut).expect("le découpage passe");
    let mut tampon = [0_u8; 8];
    assert_eq!(
        jwe.decoder_iv(&mut tampon),
        Err(Erreur::SymboleInvalide { position: 7 })
    );
}

#[test]
fn la_phrase_de_pas_cinq_segments_existe() {
    let mut phrases: vec::Vec<String> = [
        Erreur::PasCinqSegments { comptes: 3 },
        Erreur::PasTroisSegments { comptes: 5 },
    ]
    .iter()
    .map(alloc::string::ToString::to_string)
    .collect();
    assert!(phrases.iter().all(|p| !p.is_empty()));
    phrases.sort();
    phrases.dedup();
    assert_eq!(phrases.len(), 2);
}
