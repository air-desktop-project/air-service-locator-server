//! Les quatre séparateurs de l'écho, et ce qu'ils séparent.
//!
//! La disposition des datagrammes vit dans `asl-echo` ; ce qui est éprouvé
//! ici est ce qui vit ici : qu'une signature faite sous un séparateur ne vaut
//! sous aucun autre — ni sous un autre de l'écho, ni sous ceux qui existaient
//! avant lui.

use asl_cle::{
    CONTENU_ECHO_MAX_OCTETS, CleSecrete, DOMAINE, DOMAINE_ATTESTATION, DOMAINE_ATTESTATION_DE_CLE,
    DOMAINE_ECHO_JETON, DOMAINE_ECHO_REPONSE, DOMAINE_ECHO_SONDE, DOMAINE_ECHO_SONDE_ANNUAIRE,
    DOMAINE_EXPLOITANT, DOMAINE_IDENTITE_RACINE, DOMAINE_POSSESSION, DOMAINE_PREUVE_DE_RACINE,
    DomaineEcho,
};

const TOUS: [DomaineEcho; 4] = [
    DomaineEcho::SondeAnnuaire,
    DomaineEcho::Sonde,
    DomaineEcho::Reponse,
    DomaineEcho::Jeton,
];

#[test]
fn les_separateurs_sont_ceux_de_la_specification() {
    // `protocole.md` §3 quater, à la lettre.
    assert_eq!(
        DomaineEcho::SondeAnnuaire.octets(),
        b"air-service-locator/v1/echo-sonde-annuaire\x00"
    );
    assert_eq!(
        DomaineEcho::Sonde.octets(),
        b"air-service-locator/v1/echo-sonde\x00"
    );
    assert_eq!(
        DomaineEcho::Reponse.octets(),
        b"air-service-locator/v1/echo-reponse\x00"
    );
    assert_eq!(
        DomaineEcho::Jeton.octets(),
        b"air-service-locator/v1/echo-jeton\x00"
    );
    assert_eq!(
        DOMAINE_ECHO_SONDE_ANNUAIRE,
        DomaineEcho::SondeAnnuaire.octets()
    );
    assert_eq!(DOMAINE_ECHO_SONDE, DomaineEcho::Sonde.octets());
    assert_eq!(DOMAINE_ECHO_REPONSE, DomaineEcho::Reponse.octets());
    assert_eq!(DOMAINE_ECHO_JETON, DomaineEcho::Jeton.octets());
}

#[test]
fn aucun_separateur_n_est_le_prefixe_d_un_autre() {
    let tous: Vec<&[u8]> = TOUS
        .iter()
        .map(|domaine| domaine.octets())
        .chain([
            DOMAINE,
            DOMAINE_POSSESSION,
            DOMAINE_IDENTITE_RACINE,
            DOMAINE_PREUVE_DE_RACINE,
            DOMAINE_EXPLOITANT,
            DOMAINE_ATTESTATION,
            DOMAINE_ATTESTATION_DE_CLE,
        ])
        .collect();
    for (i, un) in tous.iter().enumerate() {
        assert_eq!(un.last(), Some(&0), "un séparateur finit par un octet nul");
        for (j, autre) in tous.iter().enumerate() {
            if i != j {
                assert!(!autre.starts_with(un), "{i} est un préfixe de {j}");
            }
        }
    }
}

#[test]
fn une_signature_ne_vaut_que_sous_son_separateur() {
    let secrete = CleSecrete::depuis_entropie([0x42; 32]);
    let publique = secrete.publique();
    let contenu = [0x5A_u8; 66];
    for signe in TOUS {
        let signature = secrete.signer_echo(signe, &contenu);
        for verifie in TOUS {
            assert_eq!(
                publique.verifie_echo(verifie, &contenu, &signature),
                signe == verifie,
                "signé sous {signe:?}, vérifié sous {verifie:?}"
            );
        }
        // Un octet de contenu changé, une autre clé : refusés.
        let mut autre = contenu;
        autre[65] ^= 1;
        assert!(!publique.verifie_echo(signe, &autre, &signature));
        let etrangere = CleSecrete::depuis_entropie([0x43; 32]).publique();
        assert!(!etrangere.verifie_echo(signe, &contenu, &signature));
    }
}

#[test]
fn le_plus_long_contenu_tient_dans_le_tampon() {
    let secrete = CleSecrete::depuis_entropie([0x42; 32]);
    let contenu = [0xA5_u8; CONTENU_ECHO_MAX_OCTETS];
    let signature = secrete.signer_echo(DomaineEcho::SondeAnnuaire, &contenu);
    assert!(
        secrete
            .publique()
            .verifie_echo(DomaineEcho::SondeAnnuaire, &contenu, &signature)
    );
}
