//! Les vérificateurs ECDSA refusent une signature mal formée, une clé mal
//! formée, et une signature fausse — sur chacune des deux courbes.
//!
//! `webpki` ne se trompe pas sur ces trois cas : c'est NOTRE code qui les lui
//! rend, et chacun est un chemin de `signature.rs` qu'un banc cohérent ne
//! prend jamais.

mod forge;

use asl_apple::{Attendu, Environnement, Refus, verifier};
use forge::{
    Banc, IDENTIFIANT_APP, PENDANT, attestation, debut_du_point, enfants_du_certificat, piece,
};

/// Vérifie `feuille` ancrée directement sur `ancre`, et attend un refus de
/// chaîne.
fn refus_de_chaine(feuille: &[u8], ancre: &[u8], banc: &Banc, pourquoi: &str) {
    let objet = attestation(&[feuille], &banc.auth);
    let attendu = Attendu {
        racine: ancre,
        defi: &banc.defi,
        identifiant_app: IDENTIFIANT_APP,
        environnement: Environnement::Developpement,
        maintenant: PENDANT,
    };
    assert!(
        matches!(verifier(&objet, &attendu), Err(Refus::Chaine(_))),
        "{pourquoi}"
    );
}

/// Les deux chaînes du banc : `(feuille, son émettrice)`, P-384 puis P-256.
fn chaines() -> [(&'static str, Vec<u8>, Vec<u8>); 2] {
    [
        ("P-384", piece("feuille.der"), piece("intermediaire.der")),
        (
            "P-256",
            piece("feuille-via-p256.der"),
            piece("intermediaire-p256.der"),
        ),
    ]
}

#[test]
fn une_feuille_bien_signee_remonte_a_son_emettrice_prise_pour_ancre() {
    // Le témoin : sans abîmer quoi que ce soit, les deux chaînes passent quand
    // l'intermédiaire sert d'ancre. Sans ce témoin, les trois refus ci-dessous
    // pourraient venir d'autre chose que de ce qu'on a abîmé.
    let banc = Banc::charger();
    for (courbe, feuille, emettrice) in chaines() {
        let objet = attestation(&[&feuille], &banc.auth);
        let attendu = Attendu {
            racine: &emettrice,
            defi: &banc.defi,
            identifiant_app: IDENTIFIANT_APP,
            environnement: Environnement::Developpement,
            maintenant: PENDANT,
        };
        verifier(&objet, &attendu).unwrap_or_else(|refus| panic!("{courbe} : {refus}"));
    }
}

#[test]
fn une_signature_qui_n_est_pas_du_der_est_refusee() {
    let banc = Banc::charger();
    for (courbe, mut feuille, emettrice) in chaines() {
        let [_, _, (debut_sig, _)] = enfants_du_certificat(&feuille);
        // Le BIT STRING commence par 00 puis la SEQUENCE de la signature : on
        // change la balise de la SEQUENCE.
        assert_eq!(feuille[debut_sig + 1], 0x30);
        feuille[debut_sig + 1] = 0x31;
        refus_de_chaine(&feuille, &emettrice, &banc, courbe);
    }
}

#[test]
fn une_signature_fausse_mais_bien_formee_est_refusee() {
    let banc = Banc::charger();
    for (courbe, mut feuille, emettrice) in chaines() {
        let dernier = feuille.len() - 1;
        feuille[dernier] ^= 0x01;
        refus_de_chaine(&feuille, &emettrice, &banc, courbe);
    }
}

#[test]
fn une_cle_d_emettrice_qui_n_est_pas_un_point_est_refusee() {
    let banc = Banc::charger();
    for (courbe, feuille, mut emettrice) in chaines() {
        let point = debut_du_point(&emettrice);
        assert_eq!(emettrice[point], 0x04);
        emettrice[point] = 0x05;
        refus_de_chaine(&feuille, &emettrice, &banc, courbe);
    }
}
