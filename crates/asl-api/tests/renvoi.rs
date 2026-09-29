//! Le corps du `421` (décisions 52, 57 et 59) — et ce qu'en lit un client
//! d'hier. Et celui de `GET /v1/ou/{n-…}/asl-directory`, qui est le même plus
//! `service` (décisions 75 et 80, 0.38.0).

use asl_api::annuaire::{AnnuaireResolu, RenvoiRendu};
use asl_id::{Genre, Identifiant};
use asl_proto::Erreur;

fn annuaire(graine: u8) -> Identifiant {
    Identifiant::depuis_entropie(Genre::Annuaire, [graine; 16])
}

fn encoder(renvoi: &RenvoiRendu<'_>) -> String {
    let mut sortie = vec![0_u8; 1024];
    let combien = renvoi.encoder(&mut sortie).expect("assez de place");
    String::from_utf8(sortie[..combien].to_vec()).expect("de l'ASCII")
}

/// **LE LECTEUR DU CLIENT 0.16/0.17, À LA LETTRE** (`asl-client::renvoi`,
/// `Renvoi::lire`) : un objet ; `annuaire` une chaîne, `adresses` une liste de
/// chaînes, chacun une fois ; **une clé inconnue n'est sautée que si sa
/// valeur est une chaîne** ; aucune barre oblique inverse. Rend l'annuaire et
/// les adresses, ou `None` là où le client refuserait le renvoi.
fn lire_comme_hier(corps: &str) -> Option<(String, Vec<String>)> {
    fn chaine(reste: &mut &str) -> Option<String> {
        *reste = reste.trim_start().strip_prefix('"')?;
        let fin = reste.find('"')?;
        let valeur = &reste[..fin];
        if valeur.contains('\\') {
            return None;
        }
        *reste = &reste[fin.saturating_add(1)..];
        Some(valeur.to_owned())
    }
    fn signe(reste: &mut &str, attendu: char) -> Option<()> {
        *reste = reste.trim_start().strip_prefix(attendu)?;
        Some(())
    }
    let mut reste = corps;
    let (mut annuaire, mut adresses) = (None, None);
    signe(&mut reste, '{')?;
    loop {
        let cle = chaine(&mut reste)?;
        signe(&mut reste, ':')?;
        match cle.as_str() {
            "annuaire" if annuaire.is_none() => annuaire = Some(chaine(&mut reste)?),
            "adresses" if adresses.is_none() => {
                signe(&mut reste, '[')?;
                let mut liste = Vec::new();
                loop {
                    liste.push(chaine(&mut reste)?);
                    if signe(&mut reste, ']').is_some() {
                        break;
                    }
                    signe(&mut reste, ',')?;
                }
                adresses = Some(liste);
            }
            "annuaire" | "adresses" => return None,
            // Une clé inconnue se saute SI sa valeur est une chaîne.
            _ => {
                chaine(&mut reste)?;
            }
        }
        if signe(&mut reste, '}').is_some() {
            break;
        }
        signe(&mut reste, ',')?;
    }
    if !reste.trim().is_empty() {
        return None;
    }
    Some((annuaire?, adresses?))
}

#[test]
fn chaque_adresse_porte_l_identite_de_son_membre() {
    let (titulaire, second) = (annuaire(1), annuaire(2));
    let corps = encoder(&RenvoiRendu {
        annuaire: titulaire,
        adresses: &[
            ("[2001:db8::51]:6630", titulaire),
            ("192.0.2.51:6630", titulaire),
            ("helium.maison:6630", second),
        ],
    });
    assert_eq!(
        corps,
        format!(
            "{{\"annuaire\":\"{t}\",\"adresses\":[\"[2001:db8::51]:6630\",\"192.0.2.51:6630\",\
             \"helium.maison:6630\"],\"identites\":\"{t} {t} {s}\"}}",
            t = titulaire.texte().as_str(),
            s = second.texte().as_str(),
        )
    );
}

#[test]
fn un_client_d_hier_lit_toujours_le_renvoi() {
    // **COMPATIBLE EN AVANT** : `identites` est une chaîne, et le lecteur
    // d'hier la saute ; il suit les mêmes adresses vers le même annuaire.
    let (titulaire, second) = (annuaire(1), annuaire(2));
    let corps = encoder(&RenvoiRendu {
        annuaire: titulaire,
        adresses: &[("192.0.2.51:6630", titulaire), ("192.0.2.52:6630", second)],
    });
    assert_eq!(
        lire_comme_hier(&corps),
        Some((
            titulaire.texte().as_str().to_owned(),
            vec!["192.0.2.51:6630".to_owned(), "192.0.2.52:6630".to_owned()]
        ))
    );
    // **LE DÉFAUT ÉCARTÉ** : une liste d'objets aurait fait refuser le renvoi
    // entier par le client d'hier.
    let en_objets = corps.replace(
        &format!(
            "\"identites\":\"{} {}\"",
            titulaire.texte().as_str(),
            second.texte().as_str()
        ),
        "\"membres\":[{\"annuaire\":\"n-x\"}]",
    );
    assert_ne!(en_objets, corps);
    assert_eq!(lire_comme_hier(&en_objets), None);
}

#[test]
fn un_renvoi_sans_adresse_s_encode_vide() {
    let titulaire = annuaire(1);
    let corps = encoder(&RenvoiRendu {
        annuaire: titulaire,
        adresses: &[],
    });
    assert!(
        corps.ends_with(",\"adresses\":[],\"identites\":\"\"}"),
        "{corps}"
    );
}

#[test]
fn un_tampon_trop_petit_est_refuse() {
    let titulaire = annuaire(1);
    let mut sortie = [0_u8; 8];
    assert!(matches!(
        RenvoiRendu {
            annuaire: titulaire,
            adresses: &[("192.0.2.51:6630", titulaire)],
        }
        .encoder(&mut sortie),
        Err(Erreur::TamponTropPetit)
    ));
}

// ── L'`asl-directory` : le corps du `421`, plus `service` ───────────────────

fn service() -> Identifiant {
    Identifiant::depuis_entropie(Genre::Service, [9; 16])
}

fn encoder_resolu(resolu: &AnnuaireResolu<'_>) -> String {
    let mut sortie = vec![0_u8; 1024];
    let combien = resolu.encoder(&mut sortie).expect("assez de place");
    String::from_utf8(sortie[..combien].to_vec()).expect("de l'ASCII")
}

#[test]
fn l_asl_directory_rend_le_corps_du_renvoi_precede_de_son_service() {
    // **DEUX MEMBRES VIVANTS, DEUX ADRESSES, DEUX IDENTITÉS** (décision 75) :
    // chacun sous SON `n-…`, au même rang.
    let (titulaire, second) = (annuaire(1), annuaire(2));
    let adresses = [
        ("[2001:db8::51]:6630", titulaire),
        ("[2001:db8::52]:6630", second),
    ];
    let corps = encoder_resolu(&AnnuaireResolu {
        service: service(),
        annuaire: titulaire,
        adresses: Some(&adresses),
    });
    let renvoi = encoder(&RenvoiRendu {
        annuaire: titulaire,
        adresses: &adresses,
    });
    assert_eq!(
        corps,
        format!(
            "{{\"service\":\"{}\",{}",
            service().texte().as_str(),
            &renvoi[1..]
        )
    );
    // **LE LECTEUR DE RENVOI D'HIER LE LIT TEL QUEL** : `service` est une
    // chaîne, il la saute.
    assert_eq!(
        lire_comme_hier(&corps),
        Some((
            titulaire.texte().as_str().to_owned(),
            vec![
                "[2001:db8::51]:6630".to_owned(),
                "[2001:db8::52]:6630".to_owned()
            ]
        ))
    );
}

#[test]
fn avec_voir_seul_l_asl_directory_omet_adresses_et_identites() {
    // **ABSENTS, PAS VIDES** (décision 80) : un lecteur de renvoi qui les
    // exige refuse ce corps plutôt que de suivre une liste vide.
    let titulaire = annuaire(1);
    let corps = encoder_resolu(&AnnuaireResolu {
        service: service(),
        annuaire: titulaire,
        adresses: None,
    });
    assert_eq!(
        corps,
        format!(
            "{{\"service\":\"{}\",\"annuaire\":\"{}\"}}",
            service().texte().as_str(),
            titulaire.texte().as_str()
        )
    );
    assert_eq!(lire_comme_hier(&corps), None);
    let mut sortie = [0_u8; 8];
    assert!(matches!(
        AnnuaireResolu {
            service: service(),
            annuaire: titulaire,
            adresses: None,
        }
        .encoder(&mut sortie),
        Err(Erreur::TamponTropPetit)
    ));
}
