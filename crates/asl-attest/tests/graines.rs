//! Les graines de fuzz disent-elles ce que leur nom prétend ?
//!
//! # POURQUOI CET ESSAI EXISTE
//!
//! Une graine est un fichier d'octets avec un nom en français. Rien, jamais, ne
//! vérifie que les deux se correspondent : `check-fuzz.sh` compte les graines et
//! refuse celles que libFuzzer a trouvées lui-même, mais il ne les LIT pas.
//!
//! Une graine mal fabriquée ne casse rien — elle est simplement refusée à la
//! première seconde de campagne, et la branche qu'elle devait atteindre ne l'est
//! jamais. **C'est une couverture qu'on croit avoir**, et ce dépôt en a déjà
//! payé le prix trois fois cette semaine.
//!
//! Cet essai lit donc les fichiers. C'est la seule entrée-sortie de tout
//! l'étage 1, et elle est dans un ESSAI, pas dans la crate.

use std::fs;
use std::path::PathBuf;

use asl_attest::{AUTH_MINIMUM, Champ, DRAPEAU_ATTESTE, Erreur, ObjetAttestation, X5C_MAX};

/// Où vivent les graines, depuis cette crate.
fn graine(nom: &str) -> Vec<u8> {
    let mut chemin = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    chemin.push("../../fuzz/seeds/attestation");
    chemin.push(nom);
    fs::read(&chemin).unwrap_or_else(|faute| panic!("graine {chemin:?} illisible : {faute}"))
}

#[test]
fn les_deux_attestations_acceptees_portent_bien_ce_qu_elles_annoncent() {
    for (nom, aaguid) in [
        ("attestation-de-production", &b"appattest\0\0\0\0\0\0\0"[..]),
        ("attestation-de-developpement", &b"appattestdevelop"[..]),
    ] {
        let brut = graine(nom);
        let objet = ObjetAttestation::lire(&brut).unwrap_or_else(|faute| {
            panic!("{nom} devrait se lire, et rend {faute}");
        });
        assert_eq!(objet.chaine().len(), 2, "{nom}");
        assert!(objet.recu.is_some(), "{nom}");
        assert!(objet.auth.atteste(), "{nom}");
        let cle = objet.auth.cle.expect("le drapeau la promet");
        assert_eq!(cle.aaguid, aaguid, "{nom}");
        assert_eq!(cle.identifiant.len(), 32, "{nom}");
        assert!(!cle.cle_cose.is_empty(), "{nom}");
    }
}

#[test]
fn la_graine_sans_cle_n_a_rien_derriere_son_compteur() {
    let brut = graine("auth-data-sans-cle");
    let objet = ObjetAttestation::lire(&brut).expect("elle devrait se lire");
    assert_eq!(objet.auth.cle, None);
    assert_eq!(objet.auth.drapeaux & DRAPEAU_ATTESTE, 0);
    assert_eq!(objet.donnees_auth.len(), AUTH_MINIMUM);
}

#[test]
fn les_deux_graines_de_chaine_touchent_les_deux_bornes() {
    let brut = graine("chaine-a-quatre-certificats");
    let objet = ObjetAttestation::lire(&brut).expect("la borne est incluse");
    assert_eq!(objet.chaine().len(), X5C_MAX);

    let brut = graine("chaine-vide");
    let objet = ObjetAttestation::lire(&brut).expect("vide, mais bien formée");
    assert!(objet.chaine().is_empty());
}

#[test]
fn chaque_graine_de_refus_rend_le_refus_de_son_nom() {
    let cas: Vec<(&str, Erreur)> = vec![
        ("refus-format-android", Erreur::FormatInconnu),
        (
            "refus-auth-data-tronque",
            Erreur::AuthDataTronque { octets: 40 },
        ),
        (
            "refus-champ-en-double",
            Erreur::ChampEnDouble {
                champ: Champ::Format,
            },
        ),
        (
            "refus-longueur-indefinie",
            Erreur::LongueurIndefinie { position: 0 },
        ),
        (
            "refus-tete-non-minimale",
            Erreur::EncodageNonMinimal { position: 0 },
        ),
        (
            "refus-type-flottant",
            Erreur::TypeRefuse {
                majeur: 7,
                position: 5,
            },
        ),
    ];
    for (nom, attendu) in cas {
        let brut = graine(nom);
        assert_eq!(ObjetAttestation::lire(&brut), Err(attendu), "pour {nom}");
    }

    // Celle-ci ne se compare pas à une position fixe : ce qui compte est la
    // RÈGLE qui mord, et elle mord dans `sauter`.
    let brut = graine("refus-imbrication-profonde");
    let faute = ObjetAttestation::lire(&brut);
    assert!(
        matches!(faute, Err(Erreur::TropProfond { .. })),
        "refus-imbrication-profonde rend {faute:?}"
    );
}

#[test]
fn aucune_graine_n_est_oubliee_par_cet_essai() {
    // Sans ce compte, une graine ajoutée demain ne serait vérifiée par
    // personne, et cet essai rendrait vert sur ce qu'il n'a pas regardé.
    let mut chemin = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    chemin.push("../../fuzz/seeds/attestation");
    let combien = fs::read_dir(&chemin)
        .unwrap_or_else(|faute| panic!("{chemin:?} illisible : {faute}"))
        .count();
    assert_eq!(
        combien, 12,
        "12 graines sont vérifiées ici ; le répertoire en porte {combien}"
    );
}
