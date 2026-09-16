//! Le lecteur DER : des balises longues, des longueurs minimales, des entiers
//! bornés — et chaque écart nommé.

use asl_keystore::der::{
    BITS, BOOLEEN, Balise, Classe, ENSEMBLE, ENTIER, ENUMERE, Element, Faute, NUL, OCTETS, OID,
    SEQUENCE, attendu, booleen, element, entier,
};

#[test]
fn les_balises_courtes_et_longues_se_lisent() {
    let (lu, reste) = element(&[0x02, 0x01, 0x05, 0xFF]).expect("un INTEGER");
    assert_eq!(
        lu,
        Element {
            balise: ENTIER,
            contenu: &[0x05]
        }
    );
    assert_eq!(reste, &[0xFF]);
    // `[719]` : BF 85 4F.
    let (lu, _) = element(&[0xBF, 0x85, 0x4F, 0x00]).expect("[719]");
    assert_eq!(lu.balise, Balise::contextuelle(719));
    // `[31]`, le premier numéro en forme longue : BF 1F.
    let (lu, _) = element(&[0xBF, 0x1F, 0x00]).expect("[31]");
    assert_eq!(lu.balise, Balise::contextuelle(31));
    // Quatre octets de numéro : 2²⁸ − 1.
    let (lu, _) = element(&[0xBF, 0xFF, 0xFF, 0xFF, 0x7F, 0x00]).expect("[2^28-1]");
    assert_eq!(lu.balise.numero, (1 << 28) - 1);
    // Les quatre classes.
    for (octet, classe) in [
        (0x04, Classe::Universelle),
        (0x44, Classe::Application),
        (0x84, Classe::Contextuelle),
        (0xC4, Classe::Privee),
    ] {
        let der = [octet, 0x00];
        let (lu, _) = element(&der).expect("un élément");
        assert_eq!(lu.balise.classe, classe);
        assert!(!lu.balise.construite);
    }
    for balise in [BOOLEEN, ENTIER, BITS, OCTETS, NUL, OID, ENUMERE] {
        assert!(!balise.construite);
        assert_eq!(balise, Balise::universelle(balise.numero));
    }
    assert_eq!(Balise::construite(16), SEQUENCE);
    for balise in [SEQUENCE, ENSEMBLE, Balise::contextuelle(0)] {
        assert!(balise.construite);
    }
}

#[test]
fn les_balises_mal_formees_sont_refusees() {
    assert_eq!(element(&[]), Err(Faute::Tronque));
    assert_eq!(element(&[0xBF]), Err(Faute::Tronque));
    assert_eq!(element(&[0xBF, 0x85]), Err(Faute::Tronque));
    // Non minimale : un premier octet de continuation nul.
    assert_eq!(element(&[0xBF, 0x80, 0x4F, 0x00]), Err(Faute::Balise));
    // Forme longue pour un numéro qui tenait en forme courte.
    assert_eq!(element(&[0xBF, 0x05, 0x00]), Err(Faute::Balise));
    // Cinq octets : trop grand.
    assert_eq!(
        element(&[0xBF, 0x81, 0x81, 0x81, 0x81, 0x01, 0x00]),
        Err(Faute::Balise)
    );
}

#[test]
fn les_longueurs_sont_minimales_definies_et_bornees() {
    assert_eq!(element(&[0x04]), Err(Faute::Tronque));
    assert_eq!(element(&[0x04, 0x81]), Err(Faute::Tronque));
    assert_eq!(element(&[0x04, 0x82, 0x01]), Err(Faute::Tronque));
    assert_eq!(element(&[0x04, 0x02, 0x01]), Err(Faute::Tronque));
    // Non minimales.
    assert_eq!(element(&[0x04, 0x81, 0x7F]), Err(Faute::Longueur));
    assert_eq!(element(&[0x04, 0x82, 0x00, 0xFF]), Err(Faute::Longueur));
    // Indéfinie, et sur trois octets.
    assert_eq!(element(&[0x04, 0x80]), Err(Faute::Longueur));
    assert_eq!(
        element(&[0x04, 0x83, 0x00, 0x00, 0x01]),
        Err(Faute::Longueur)
    );
    // Les formes justes.
    let cent_vingt_huit = [0xAA; 128];
    let mut der = vec![0x04, 0x81, 0x80];
    der.extend_from_slice(&cent_vingt_huit);
    assert_eq!(
        element(&der).expect("128 octets").0.contenu,
        &cent_vingt_huit[..]
    );
    let trois_cents = [0xBB; 300];
    let mut der = vec![0x04, 0x82, 0x01, 0x2C];
    der.extend_from_slice(&trois_cents);
    assert_eq!(
        element(&der).expect("300 octets").0.contenu,
        &trois_cents[..]
    );
}

#[test]
fn attendu_exige_la_balise() {
    assert_eq!(
        attendu(&[0x02, 0x01, 0x05], ENTIER),
        Ok((&[0x05][..], &[][..]))
    );
    assert_eq!(attendu(&[0x02, 0x01, 0x05], OCTETS), Err(Faute::Inattendu));
    assert_eq!(attendu(&[0x02], OCTETS), Err(Faute::Tronque));
}

#[test]
fn les_entiers_sont_positifs_minimaux_et_sur_huit_octets_au_plus() {
    assert_eq!(entier(&[0x00]), Ok(0));
    assert_eq!(entier(&[0x7F]), Ok(127));
    assert_eq!(entier(&[0x00, 0x80]), Ok(128));
    assert_eq!(entier(&[0x01, 0x00]), Ok(256));
    assert_eq!(entier(&[0x02, 0x49, 0xF0]), Ok(150_000));
    assert_eq!(entier(&[0x00, 0xFF]), Ok(255));
    assert_eq!(
        entier(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
        Ok(u64::MAX)
    );
    assert_eq!(entier(&[]), Err(Faute::Entier));
    assert_eq!(entier(&[0x80]), Err(Faute::Entier), "négatif");
    assert_eq!(
        entier(&[0x00, 0x01]),
        Err(Faute::Entier),
        "zéro de tête inutile"
    );
    assert_eq!(
        entier(&[0x00, 0x00]),
        Err(Faute::Entier),
        "zéro de tête inutile"
    );
    assert_eq!(
        entier(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        Err(Faute::Entier),
        "neuf octets de valeur"
    );
}

#[test]
fn les_booleens_font_un_octet() {
    assert_eq!(booleen(&[0xFF]), Ok(true));
    assert_eq!(booleen(&[0x01]), Ok(true));
    assert_eq!(booleen(&[0x00]), Ok(false));
    assert_eq!(booleen(&[]), Err(Faute::Booleen));
    assert_eq!(booleen(&[0xFF, 0xFF]), Err(Faute::Booleen));
}
