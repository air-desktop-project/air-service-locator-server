//! Le certificat d'identité — frappé, puis relu par le lecteur étroit.
//!
//! **Ce qui compte** : qu'on relise la clé qu'on a frappée, que la frappe soit
//! la même à chaque démarrage, et que le lecteur — qui reçoit le certificat
//! d'un inconnu — refuse tout ce qui n'est pas une clé Ed25519 dans un DER
//! correct, sans jamais paniquer.

use asl_cle::{
    CERTIFICAT_D_IDENTITE_OCTETS, CleSecrete, Faute, certificat_d_identite, cle_du_certificat,
    cle_pkcs8, identifiant_de_racine,
};

/// Un élément DER, longueur écrite au plus court.
fn tlv(etiquette: u8, contenu: &[u8]) -> Vec<u8> {
    let mut sortie = vec![etiquette];
    let longueur = contenu.len();
    if longueur < 0x80 {
        sortie.push(u8::try_from(longueur).expect("court"));
    } else if longueur < 0x100 {
        sortie.extend([0x81, u8::try_from(longueur).expect("un octet")]);
    } else {
        sortie.extend([0x82]);
        sortie.extend(u16::try_from(longueur).expect("deux octets").to_be_bytes());
    }
    sortie.extend_from_slice(contenu);
    sortie
}

/// `id-Ed25519`, sans paramètre.
const ALGO_ED25519: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];
/// `id-ecPublicKey` : ce n'est pas Ed25519.
const ALGO_EC: [u8; 9] = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

/// Un certificat de forme libre autour d'un `subjectPublicKeyInfo` donné.
fn certificat_autour(version: bool, spki: &[u8]) -> Vec<u8> {
    let mut tbs = Vec::new();
    if version {
        tbs.extend(tlv(0xa0, &tlv(0x02, &[0x02])));
    }
    tbs.extend(tlv(0x02, &[0x01]));
    tbs.extend(tlv(0x30, &ALGO_ED25519));
    tbs.extend(tlv(0x30, &[]));
    tbs.extend(tlv(0x30, &[]));
    tbs.extend(tlv(0x30, &[]));
    tbs.extend_from_slice(spki);
    let mut certificat = tlv(0x30, &tbs);
    certificat.extend(tlv(0x30, &ALGO_ED25519));
    certificat.extend(tlv(0x03, &[0x00; 65]));
    tlv(0x30, &certificat)
}

fn spki(algo: &[u8], bits: &[u8]) -> Vec<u8> {
    let mut contenu = tlv(0x30, algo);
    contenu.extend(tlv(0x03, bits));
    tlv(0x30, &contenu)
}

fn cle_valide() -> [u8; 32] {
    CleSecrete::depuis_entropie([0x42; 32]).publique().octets()
}

#[test]
fn on_relit_la_cle_qu_on_a_frappee() {
    let secrete = CleSecrete::depuis_entropie([0x17; 32]);
    let certificat = certificat_d_identite(&secrete);
    assert_eq!(certificat.len(), CERTIFICAT_D_IDENTITE_OCTETS);
    assert_eq!(cle_du_certificat(&certificat), Ok(secrete.publique()));
}

#[test]
fn la_frappe_est_la_meme_a_chaque_demarrage_et_propre_a_chaque_cle() {
    let une = CleSecrete::depuis_entropie([0x17; 32]);
    let meme = CleSecrete::depuis_entropie([0x17; 32]);
    let autre = CleSecrete::depuis_entropie([0x18; 32]);
    assert_eq!(certificat_d_identite(&une), certificat_d_identite(&meme));
    assert_ne!(certificat_d_identite(&une), certificat_d_identite(&autre));
}

#[test]
fn le_nom_porte_est_l_identifiant_de_la_cle() {
    // Émetteur et sujet disent `CN=n-…` : ce n'est pas ce qu'on juge, mais un
    // humain qui ouvre le certificat doit y lire l'annuaire.
    let secrete = CleSecrete::depuis_entropie([0x33; 32]);
    let certificat = certificat_d_identite(&secrete);
    let nom = identifiant_de_racine(&secrete.publique()).texte();
    let nom = nom.as_str().as_bytes();
    let fois = certificat
        .windows(nom.len())
        .filter(|fenetre| *fenetre == nom)
        .count();
    assert_eq!(fois, 2, "émetteur et sujet");
}

#[test]
fn la_signature_se_verifie_avec_la_cle_du_certificat() {
    // Auto-signé : la signature du `TBSCertificate` se vérifie contre la clé
    // qu'il porte. Personne ne la juge (décision 54), mais un certificat qui
    // mentirait sur lui-même serait un piège pour l'outil qui l'inspecte.
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
    let secrete = CleSecrete::depuis_entropie([0x55; 32]);
    let certificat = certificat_d_identite(&secrete);
    let tbs = &certificat[4..4 + 193];
    let signature: [u8; 64] = certificat[certificat.len() - 64..]
        .try_into()
        .expect("64 octets");
    let cle = VerifyingKey::from_bytes(&secrete.publique().octets()).expect("une clé");
    assert!(cle.verify(tbs, &Signature::from_bytes(&signature)).is_ok());
}

#[test]
fn la_cle_pkcs8_porte_la_graine_derriere_l_en_tete_de_rfc_8410() {
    let secrete = CleSecrete::depuis_entropie([0x66; 32]);
    let pkcs8 = cle_pkcs8(&secrete);
    assert_eq!(
        pkcs8[..16],
        [
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20
        ]
    );
    assert_eq!(pkcs8[16..], [0x66; 32]);
}

#[test]
fn un_certificat_sans_version_se_lit_aussi() {
    let certificat = certificat_autour(
        false,
        &spki(&ALGO_ED25519, &[&[0][..], &cle_valide()].concat()),
    );
    assert_eq!(
        cle_du_certificat(&certificat).map(|cle| cle.octets()),
        Ok(cle_valide())
    );
}

#[test]
fn une_cle_qui_n_est_pas_ed25519_est_refusee() {
    let certificat = certificat_autour(true, &spki(&ALGO_EC, &[&[0][..], &[0x04; 65]].concat()));
    assert_eq!(
        cle_du_certificat(&certificat),
        Err(Faute::CertificatIllisible)
    );
}

#[test]
fn une_cle_qui_n_est_pas_un_point_est_refusee() {
    let certificat = certificat_autour(
        true,
        &spki(&ALGO_ED25519, &[&[0][..], &[0x02; 32]].concat()),
    );
    assert_eq!(
        cle_du_certificat(&certificat),
        Err(Faute::ClePubliqueInvalide)
    );
}

#[test]
fn la_chaine_de_bits_de_la_cle_est_jugee() {
    let cas = [
        // Des bits inutilisés.
        [&[1][..], &cle_valide()].concat(),
        // Trente et un octets.
        [&[0][..], &cle_valide()[..31]].concat(),
        // Vide.
        Vec::new(),
    ];
    for bits in cas {
        let certificat = certificat_autour(true, &spki(&ALGO_ED25519, &bits));
        assert_eq!(
            cle_du_certificat(&certificat),
            Err(Faute::CertificatIllisible)
        );
    }
    // Un octet derrière la chaîne de bits, dans la clé.
    let mut contenu = tlv(0x30, &ALGO_ED25519);
    contenu.extend(tlv(0x03, &[&[0][..], &cle_valide()].concat()));
    contenu.push(0x00);
    let certificat = certificat_autour(true, &tlv(0x30, &contenu));
    assert_eq!(
        cle_du_certificat(&certificat),
        Err(Faute::CertificatIllisible)
    );
}

#[test]
fn un_der_mal_forme_est_refuse_sans_paniquer() {
    let bon = certificat_d_identite(&CleSecrete::depuis_entropie([0x11; 32]));
    let mut avec_une_queue = bon.to_vec();
    avec_une_queue.push(0x00);
    let cas: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0x31, 0x00],                   // pas une SEQUENCE
        vec![0x30],                         // pas de longueur
        vec![0x30, 0x05, 0x00],             // plus court que dit
        vec![0x30, 0x81],                   // 0x81 sans octet
        vec![0x30, 0x81, 0x05],             // 0x81 non minimal
        vec![0x30, 0x82, 0x00, 0x05],       // 0x82 non minimal
        vec![0x30, 0x82, 0x01],             // 0x82 tronqué
        vec![0x30, 0x83, 0x00, 0x00, 0x05], // 0x83 : trop long pour nous
        vec![0x30, 0x80],                   // longueur indéfinie (BER)
        avec_une_queue,
        tlv(0x30, &[]),                         // pas de TBSCertificate
        tlv(0x30, &tlv(0x30, &[])),             // TBS vide
        tlv(0x30, &tlv(0x30, &tlv(0xa0, &[]))), // version, puis rien
        bon[..bon.len() - 1].to_vec(),          // tronqué
    ];
    for der in cas {
        assert_eq!(
            cle_du_certificat(&der).map(|_| ()),
            Err(Faute::CertificatIllisible),
            "{der:02x?}"
        );
    }
}

#[test]
fn les_longueurs_longues_se_lisent() {
    // Un sujet assez long pour qu'un élément s'écrive sur 0x81, puis sur 0x82.
    for taille in [200_usize, 300] {
        let mut tbs = tlv(0xa0, &tlv(0x02, &[0x02]));
        tbs.extend(tlv(0x02, &[0x01]));
        tbs.extend(tlv(0x30, &ALGO_ED25519));
        tbs.extend(tlv(0x30, &vec![0x00; taille]));
        tbs.extend(tlv(0x30, &[]));
        tbs.extend(tlv(0x30, &[]));
        tbs.extend(spki(&ALGO_ED25519, &[&[0][..], &cle_valide()].concat()));
        let certificat = tlv(0x30, &tlv(0x30, &tbs));
        assert_eq!(
            cle_du_certificat(&certificat).map(|cle| cle.octets()),
            Ok(cle_valide())
        );
    }
}

#[test]
fn chaque_element_attendu_est_exige_a_sa_place() {
    // Une version annoncée mais tronquée.
    let version_tronquee = tlv(0x30, &tlv(0x30, &[0xa0]));
    // Les cinq champs traversés, puis plus rien : pas de clé.
    let mut sans_cle = tlv(0x02, &[0x01]);
    for _ in 0..4 {
        sans_cle.extend(tlv(0x30, &[]));
    }
    let sans_cle = tlv(0x30, &tlv(0x30, &sans_cle));
    // Une clé dont l'algorithme n'est pas une SEQUENCE.
    let algorithme_nu = certificat_autour(true, &tlv(0x30, &tlv(0x06, &[0x2b, 0x65, 0x70])));
    // Un algorithme Ed25519 suivi d'autre chose qu'une chaîne de bits.
    let mut contenu = tlv(0x30, &ALGO_ED25519);
    contenu.extend(tlv(0x04, &cle_valide()));
    let pas_de_bits = certificat_autour(true, &tlv(0x30, &contenu));
    for der in [version_tronquee, sans_cle, algorithme_nu, pas_de_bits] {
        assert_eq!(
            cle_du_certificat(&der).map(|_| ()),
            Err(Faute::CertificatIllisible),
            "{der:02x?}"
        );
    }
}
