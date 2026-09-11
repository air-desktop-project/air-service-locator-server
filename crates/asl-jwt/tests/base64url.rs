//! base64url décode ce qu'il doit, et refuse le reste.

use asl_jwt::{Erreur, decoder, longueur_decodee};

/// L'encodeur base64url sans remplissage — dans l'essai, pour fabriquer des
/// vecteurs. Il n'a pas sa place dans la crate : rien, en production, n'encode
/// un jeton.
fn encoder(source: &[u8]) -> alloc::string::String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut sortie = alloc::string::String::new();
    let mut morceau = 0_u32;
    let mut bits = 0_u32;
    for octet in source {
        morceau = morceau << 8 | u32::from(*octet);
        bits = bits.saturating_add(8);
        while bits >= 6 {
            bits = bits.saturating_sub(6);
            let index = usize::try_from((morceau >> bits) & 0x3F).expect("six bits");
            sortie.push(char::from(ALPHABET[index]));
        }
    }
    if bits > 0 {
        let reste = 6_u32.saturating_sub(bits);
        let index = usize::try_from((morceau << reste) & 0x3F).expect("six bits");
        sortie.push(char::from(ALPHABET[index]));
    }
    sortie
}

extern crate alloc;

#[test]
fn l_aller_retour_tient_sur_toutes_les_longueurs() {
    for n in 0..=64_usize {
        let source: alloc::vec::Vec<u8> = (0..n)
            .map(|i| u8::try_from((i.saturating_mul(7).saturating_add(1)) % 256).expect("un octet"))
            .collect();
        let code = encoder(&source);
        let mut sortie = alloc::vec![0_u8; n];
        let ecrits = decoder(code.as_bytes(), &mut sortie, 0, 0).expect("il se décode");
        assert_eq!(&sortie[..ecrits], &source[..], "à {n} octets");
        assert_eq!(ecrits, n);
    }
}

#[test]
fn la_longueur_decodee_suit_les_restes() {
    assert_eq!(longueur_decodee(0, 0), Ok(0));
    assert_eq!(longueur_decodee(4, 0), Ok(3));
    assert_eq!(longueur_decodee(2, 0), Ok(1));
    assert_eq!(longueur_decodee(3, 0), Ok(2));
    assert_eq!(longueur_decodee(8, 0), Ok(6));
    // Un symbole isolé ne code aucun octet.
    assert_eq!(
        longueur_decodee(1, 2),
        Err(Erreur::LongueurImpossible { rang: 2 })
    );
    assert_eq!(
        longueur_decodee(5, 1),
        Err(Erreur::LongueurImpossible { rang: 1 })
    );
}

#[test]
fn le_plus_et_le_slash_de_base64_ordinaire_sont_refuses() {
    // base64url emploie `-` et `_` ; accepter `+` et `/` ferait lire un jeton
    // de deux façons.
    for (mauvais, pos) in [(b"AB+D", 2), (b"AB/D", 2)] {
        let mut sortie = [0_u8; 3];
        assert_eq!(
            decoder(mauvais, &mut sortie, 0, 0),
            Err(Erreur::SymboleInvalide { position: pos })
        );
    }
    // Et `-`/`_` passent.
    let mut sortie = [0_u8; 3];
    assert!(decoder(b"AB-D", &mut sortie, 0, 0).is_ok());
    assert!(decoder(b"AB_D", &mut sortie, 0, 0).is_ok());
}

#[test]
fn le_remplissage_est_refuse_par_son_propre_nom() {
    let mut sortie = [0_u8; 3];
    assert_eq!(
        decoder(b"QQ==", &mut sortie, 0, 5),
        Err(Erreur::RemplissageRefuse { position: 7 })
    );
}

#[test]
fn un_symbole_de_controle_ou_d_espace_est_refuse() {
    for mauvais in [b"AB D", b"AB\nD", b"AB\x00D"] {
        let mut sortie = [0_u8; 3];
        assert_eq!(
            decoder(mauvais, &mut sortie, 0, 0),
            Err(Erreur::SymboleInvalide { position: 2 })
        );
    }
}

#[test]
fn la_position_est_celle_du_jeton_entier() {
    // Le décalage place la faute là où elle est vraiment, pas au début du
    // segment.
    let mut sortie = [0_u8; 3];
    assert_eq!(
        decoder(b"A+CD", &mut sortie, 1, 40),
        Err(Erreur::SymboleInvalide { position: 41 })
    );
}

#[test]
fn un_tampon_trop_petit_est_refuse_avant_d_ecrire() {
    let mut sortie = [0_u8; 2];
    assert_eq!(
        decoder(b"QUJD", &mut sortie, 0, 0),
        Err(Erreur::TamponTropPetit { attendu: 3 })
    );
}

#[test]
fn une_longueur_impossible_est_refusee_avant_de_lire() {
    let mut sortie = [0_u8; 8];
    assert_eq!(
        decoder(b"QUJDQ", &mut sortie, 2, 0),
        Err(Erreur::LongueurImpossible { rang: 2 })
    );
}

#[test]
fn des_bits_de_fin_non_nuls_sont_refuses() {
    // `QQ` décode un octet (0x41) et laisse quatre bits ; s'ils ne sont pas
    // nuls, deux textes décodent au même octet. `QR` a les mêmes six premiers
    // bits que `QQ` mais des bits de fin non nuls.
    let mut sortie = [0_u8; 2];
    // "QR" : Q=16 (010000), R=17 (010001) → octet 0x41, bits de fin = 0001.
    assert_eq!(
        decoder(b"QR", &mut sortie, 3, 0),
        Err(Erreur::BitsNonNuls { rang: 3 })
    );
    // "QQ" : bits de fin nuls, accepté.
    let ecrits = decoder(b"QQ", &mut sortie, 0, 0).expect("bits de fin nuls");
    assert_eq!(&sortie[..ecrits], &[0x41]);
}

#[test]
fn des_bits_de_fin_non_nuls_sur_trois_symboles_sont_refuses() {
    // Trois symboles → deux octets + deux bits de fin.
    let mut sortie = [0_u8; 2];
    // "AAB" : deux bits de fin valent 01.
    assert_eq!(
        decoder(b"AAB", &mut sortie, 1, 0),
        Err(Erreur::BitsNonNuls { rang: 1 })
    );
    // "AAA" : tout à zéro, accepté.
    assert!(decoder(b"AAA", &mut sortie, 0, 0).is_ok());
}
