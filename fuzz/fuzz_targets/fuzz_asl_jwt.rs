//! **Cible : le découpage d'un jeton JWS** — des octets quelconques vers trois
//! segments décodés.
//!
//! # POURQUOI ELLE COMPTE
//!
//! Un jeton d'intégrité de Play vient d'un appareil Android qu'on n'a pas
//! choisi : quiconque peut ouvrir une connexion peut poster n'importe quels
//! octets à la place. C'est la porte d'entrée de la vérification Play Integrity,
//! avant toute cryptographie.
//!
//! # LES PROPRIÉTÉS
//!
//! 1. **Rien ne panique.**
//! 2. **Un refus est toujours une faute nommée.**
//! 3. **LE DÉCODAGE NE DÉBORDE JAMAIS DU TAMPON**, et ce qu'il annonce écrire,
//!    il l'écrit : la longueur rendue tient dans `longueur_decodee`.
//! 4. **CE QUI SE DÉCODE SE RÉ-ENCODE À L'IDENTIQUE** en base64url — la
//!    propriété d'aller-retour, ici sur la charge.
//! 5. **`signe()` EST BIEN `en-tête_b64 . charge_b64`**, contigu et sans la
//!    signature : c'est ce qu'ES256 hachera, et un octet de travers ici ferait
//!    échouer toute vérification en aval.

#![no_main]

use libfuzzer_sys::fuzz_target;

use asl_jwt::{Erreur, Jws, decoder, longueur_decodee};

fn nommee(faute: Erreur) {
    assert!(matches!(
        faute,
        Erreur::PasTroisSegments { .. }
            | Erreur::SegmentVide { .. }
            | Erreur::SymboleInvalide { .. }
            | Erreur::LongueurImpossible { .. }
            | Erreur::TamponTropPetit { .. }
            | Erreur::RemplissageRefuse { .. }
            | Erreur::BitsNonNuls { .. }
    ));
}

/// Décode un segment dans un tampon assez grand, en vérifiant qu'il ne déborde
/// pas et que la longueur promise est tenue.
fn decoder_bien(segment: &[u8], rang: usize) -> Option<Vec<u8>> {
    let besoin = match longueur_decodee(segment.len(), rang) {
        Ok(besoin) => besoin,
        Err(faute) => {
            nommee(faute);
            return None;
        }
    };
    let mut tampon = vec![0_u8; besoin + 8];
    match decoder(segment, &mut tampon, rang, 0) {
        Ok(ecrits) => {
            assert_eq!(ecrits, besoin, "la longueur promise n'est pas tenue");
            // Rien n'a été écrit au-delà de `besoin`.
            assert!(tampon[besoin..].iter().all(|o| *o == 0));
            tampon.truncate(ecrits);
            Some(tampon)
        }
        Err(faute) => {
            nommee(faute);
            None
        }
    }
}

/// Ré-encode en base64url sans remplissage.
fn encoder(source: &[u8]) -> Vec<u8> {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut sortie = Vec::new();
    let (mut m, mut b) = (0_u32, 0_u32);
    for octet in source {
        m = m << 8 | u32::from(*octet);
        b = b.saturating_add(8);
        while b >= 6 {
            b = b.saturating_sub(6);
            sortie.push(A[usize::try_from((m >> b) & 0x3F).expect("six bits")]);
        }
    }
    if b > 0 {
        let reste = 6_u32.saturating_sub(b);
        sortie.push(A[usize::try_from((m << reste) & 0x3F).expect("six bits")]);
    }
    sortie
}

fuzz_target!(|octets: &[u8]| {
    let jws = match Jws::lire(octets) {
        Ok(jws) => jws,
        Err(faute) => {
            nommee(faute);
            return;
        }
    };

    // Le découpage stable.
    assert_eq!(Jws::lire(octets), Ok(jws));

    // PROPRIÉTÉ 5 : la partie signée est en-tête . charge, contiguë.
    let mut attendu = jws.entete_b64().to_vec();
    attendu.push(b'.');
    attendu.extend_from_slice(jws.charge_b64());
    assert_eq!(
        jws.signe(),
        attendu.as_slice(),
        "signe() n'est pas en-tête.charge"
    );

    // Les trois segments se décodent sans déborder, et l'aller-retour tient.
    for (segment, rang) in [
        (jws.entete_b64(), 0),
        (jws.charge_b64(), 1),
        (jws.signature_b64(), 2),
    ] {
        if let Some(decode) = decoder_bien(segment, rang) {
            assert_eq!(
                encoder(&decode),
                segment,
                "l'aller-retour base64url a changé"
            );
        }
    }
});
