//! Les corps de `POST /v1/echo/jetons` (décision 91) : la demande, et le
//! jeton rendu — lus comme ils sont écrits, et rien d'autre.

use asl_api::echo::{DemandeDeJeton, JETON_RENDU_MAX, JetonRendu};
use asl_cle::CleSecrete;
use asl_echo::Jeton;
use asl_id::{Genre, Identifiant};
use asl_proto::Erreur;

fn machine(graine: u8) -> Identifiant {
    Identifiant::depuis_entropie(Genre::Machine, [graine; 16])
}

fn jeton() -> Jeton {
    Jeton::emettre(
        &CleSecrete::depuis_entropie([0x11; 32]),
        machine(0x70),
        CleSecrete::depuis_entropie([0x33; 32]).publique(),
        machine(0x80),
        CleSecrete::depuis_entropie([0x44; 32]).publique(),
        1_789_217_731_000,
    )
    .unwrap()
}

#[test]
fn la_demande_nomme_une_machine_et_rien_d_autre() {
    let demande = DemandeDeJeton {
        machine: machine(0x70),
    };
    let mut sortie = [0_u8; 64];
    let n = demande.encoder(&mut sortie).unwrap();
    assert_eq!(
        &sortie[..n],
        format!(r#"{{"machine":"{}"}}"#, machine(0x70).texte()).as_bytes()
    );
    assert_eq!(DemandeDeJeton::decoder(&sortie[..n]), Ok(demande));
    assert_eq!(
        DemandeDeJeton::decoder(b" { \"machine\" : \"m-00000000000000000000000000\" } ")
            .map(|d| d.machine.genre()),
        Ok(Genre::Machine)
    );

    // Un autre genre, un autre champ, un champ de trop.
    let u = Identifiant::depuis_entropie(Genre::Utilisateur, [1; 16]);
    assert!(matches!(
        DemandeDeJeton::decoder(format!(r#"{{"machine":"{}"}}"#, u.texte()).as_bytes()),
        Err(Erreur::IdentifiantInvalide { .. })
    ));
    assert!(matches!(
        DemandeDeJeton::decoder(br#"{"cible":"m-00000000000000000000000000"}"#),
        Err(Erreur::ChampInconnu { .. })
    ));
    assert!(
        DemandeDeJeton::decoder(br#"{"machine":"m-00000000000000000000000000","cle":"x"}"#)
            .is_err()
    );
    assert!(DemandeDeJeton::decoder(br#"{"machine":7}"#).is_err());
    assert!(demande.encoder(&mut [0_u8; 8]).is_err());
}

#[test]
fn le_jeton_rendu_se_relit_et_dit_son_expiration() {
    let rendu = JetonRendu { jeton: jeton() };
    let mut sortie = [0_u8; JETON_RENDU_MAX];
    let n = rendu.encoder(&mut sortie).unwrap();
    let texte = core::str::from_utf8(&sortie[..n]).unwrap();
    assert_eq!(
        texte,
        format!(
            r#"{{"jeton":"{}","expire_a":1789217791000}}"#,
            jeton().hex().as_str()
        )
    );
    assert_eq!(JetonRendu::decoder(&sortie[..n]), Ok(rendu));
    assert!(rendu.encoder(&mut [0_u8; 64]).is_err());
}

#[test]
fn le_jeton_rendu_refuse_un_jeton_illisible_ou_une_expiration_qui_ment() {
    let hex = jeton().hex();
    // Une expiration qui n'est pas celle que le jeton porte.
    let menteur = format!(r#"{{"jeton":"{}","expire_a":1789217791001}}"#, hex.as_str());
    assert!(matches!(
        JetonRendu::decoder(menteur.as_bytes()),
        Err(Erreur::JsonAttendu { .. })
    ));
    // Un jeton qui ne se lit pas.
    let court = r#"{"jeton":"01","expire_a":1789217791000}"#;
    assert!(matches!(
        JetonRendu::decoder(court.as_bytes()),
        Err(Erreur::JsonAttendu { .. })
    ));
    // L'ordre des champs, la virgule, l'entier, la fin.
    for mauvais in [
        format!(r#"{{"expire_a":1789217791000,"jeton":"{}"}}"#, hex.as_str()),
        format!(r#"{{"jeton":"{}"}}"#, hex.as_str()),
        format!(r#"{{"jeton":"{}","fin":1}}"#, hex.as_str()),
        format!(r#"{{"jeton":"{}","expire_a":"x"}}"#, hex.as_str()),
        format!(
            r#"{{"jeton":"{}","expire_a":1789217791000,"x":1}}"#,
            hex.as_str()
        ),
        format!(r#"{{"jeton":{}}}"#, 1),
    ] {
        assert!(
            JetonRendu::decoder(mauvais.as_bytes()).is_err(),
            "{mauvais}"
        );
    }
}
