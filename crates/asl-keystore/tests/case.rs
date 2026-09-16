//! La case du fil se découpe, se réassemble, et refuse en le disant.

use asl_keystore::case::{CASE_MAX, CERTIFICATS_MAX, Chaine, Faute, assembler, decouper};

#[test]
fn une_case_se_decoupe_feuille_d_abord_et_se_reassemble() {
    let feuille = [0x30, 0x03, 0x02, 0x01, 0x01];
    let tee = [0x30, 0x00];
    let racine = vec![0xAA; 300];
    let case = assembler(&[&feuille, &tee, &racine]).expect("la case tient");
    assert_eq!(&case[..2], &[0x00, 0x05]);
    assert_eq!(&case[7..9], &[0x00, 0x02]);
    assert_eq!(&case[11..13], &[0x01, 0x2C]);
    let chaine = decouper(&case).expect("elle se découpe");
    assert_eq!(
        chaine,
        Chaine {
            feuille: &feuille,
            intermediaires: vec![&tee, &racine],
        }
    );
    assert_eq!(chaine.clone(), chaine);
    // Une feuille seule : aucun intermédiaire.
    let seule = assembler(&[&feuille]).expect("la case tient");
    assert_eq!(
        decouper(&seule).expect("une feuille").intermediaires,
        Vec::<&[u8]>::new()
    );
}

#[test]
fn chaque_faute_est_nommee() {
    assert_eq!(decouper(&[]), Err(Faute::Vide));
    assert_eq!(decouper(&[0x00]), Err(Faute::LongueurCoupee { rang: 0 }));
    assert_eq!(
        decouper(&[0x00, 0x00]),
        Err(Faute::CertificatVide { rang: 0 })
    );
    assert_eq!(
        decouper(&[0x00, 0x03, 0x01, 0x02]),
        Err(Faute::Tronquee {
            rang: 0,
            annoncee: 3,
            restant: 2
        })
    );
    // La faute porte le rang du certificat fautif.
    assert_eq!(
        decouper(&[0x00, 0x01, 0xAA, 0x00]),
        Err(Faute::LongueurCoupee { rang: 1 })
    );
    assert_eq!(
        decouper(&[0x00, 0x01, 0xAA, 0x00, 0x00]),
        Err(Faute::CertificatVide { rang: 1 })
    );
    assert_eq!(
        decouper(&[0x00, 0x01, 0xAA, 0x00, 0x02, 0xBB]),
        Err(Faute::Tronquee {
            rang: 1,
            annoncee: 2,
            restant: 1
        })
    );
    let trop = vec![0; CASE_MAX + 1];
    assert_eq!(
        decouper(&trop),
        Err(Faute::TropLongue {
            obtenue: CASE_MAX + 1
        })
    );
    let un: &[u8] = &[0xAA];
    let neuf = assembler(&[un; CERTIFICATS_MAX + 1]).expect("la case tient");
    assert_eq!(decouper(&neuf), Err(Faute::TropDeCertificats));
    let huit = assembler(&[un; CERTIFICATS_MAX]).expect("la case tient");
    assert_eq!(
        decouper(&huit)
            .expect("huit, c'est la borne")
            .intermediaires
            .len(),
        CERTIFICATS_MAX - 1
    );
    for faute in [
        Faute::Vide,
        Faute::LongueurCoupee { rang: 0 },
        Faute::CertificatVide { rang: 0 },
        Faute::Tronquee {
            rang: 0,
            annoncee: 3,
            restant: 2,
        },
        Faute::TropLongue { obtenue: 9000 },
        Faute::TropDeCertificats,
    ] {
        assert!(!faute.to_string().is_empty(), "{faute:?}");
    }
}

#[test]
fn ce_qui_ne_se_decouperait_pas_ne_s_assemble_pas() {
    let trop_long = vec![0; 65_536];
    assert_eq!(assembler(&[&trop_long]), None);
    let presque = vec![0; CASE_MAX - 2];
    assert!(assembler(&[&presque]).is_some());
    let juste_trop = vec![0; CASE_MAX - 1];
    assert_eq!(assembler(&[&juste_trop]), None);
}
