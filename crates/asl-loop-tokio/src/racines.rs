//! Les racines embarquées — l'ancre (`annuaires.md` §2, décision 56).
//!
//! # CE QUI EST ÉPINGLÉ, C'EST LA CLÉ
//!
//! Pour chaque racine : son identifiant `n-…`, **sa clé d'identité**, et des
//! locateurs — des adresses d'abord (C20 : aucun résolveur requis), des noms
//! ensuite, comme commodités. Un locateur ne fait rien croire : il dit où
//! joindre ; la clé dit qui l'on doit trouver au bout.
//!
//! # POURQUOI DANS LE BINAIRE
//!
//! C'est ce qu'un annuaire neuf a pour tout bagage (§2) : il n'a encore parlé à
//! personne. Les clés ont été relevées sur les bancs le 2026-09-27
//! (`/etc/asl-server/identite.key.pub`) ; un essai tient que chacune se déduit
//! bien en l'identifiant écrit à côté — une clé recopiée de travers ne
//! passerait pas la barrière.

use asl_cle::ClePublique;
use asl_id::Identifiant;

use crate::confiance::Confiance;
use crate::tireur::{Connexion, Faute, resoudre};

// **LA LISTE ET LA RÈGLE VIVENT DANS `asl-racines`** (étage 2, partagée avec le
// client depuis 0.31.0) : une seule ancre de confiance, une seule copie.
pub use asl_racines::{ALIAS_DES_RACINES, RACINES, RacineEmbarquee};

/// Les identités qu'on doit trouver au bout de ce locateur : celle d'une
/// racine embarquée, les deux pour l'alias commun, aucune sinon
/// (`asl_racines::racines_du_locateur`).
#[must_use]
pub fn identites_du_locateur(locateur: &str) -> Vec<ClePublique> {
    asl_racines::racines_du_locateur(locateur)
        .filter_map(RacineEmbarquee::cle_publique)
        .collect()
}

/// Les racines embarquées, chacune encodée comme `GET /v1/racines` la rend
/// (décision 56) : `{"annuaire":"n-…","cle":"<hex>","locateurs":[…]}`.
#[must_use]
pub fn racines_encodees() -> Vec<Vec<u8>> {
    RACINES
        .iter()
        .filter_map(|racine| {
            let annuaire =
                asl_id::Identifiant::analyser_genre(asl_id::Genre::Annuaire, racine.identifiant)
                    .ok()?;
            let mut sortie = vec![0_u8; 1024];
            let combien = asl_api::annuaire::RacineRendue {
                annuaire,
                cle: racine.cle,
                locateurs: racine.locateurs,
            }
            .encoder(&mut sortie)
            .ok()?;
            sortie.truncate(combien);
            Some(sortie)
        })
        .collect()
}

/// Une racine apprise d'une liste de `GET /v1/racines`, **vérifiée** : sa
/// clé se déduit en son identifiant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RacineApprise {
    /// Son identité.
    pub identifiant: Identifiant,
    /// Sa clé d'identité.
    pub cle: ClePublique,
    /// Où la joindre — sans valeur de confiance.
    pub locateurs: Vec<String>,
}

/// Lit et VÉRIFIE une liste de `GET /v1/racines` (décision 56).
///
/// **Une seule racine dont la clé ne donne pas l'identifiant écrit à côté
/// refuse la liste entière** : c'est une liste fausse, et l'on ne trie pas
/// dans une liste fausse. Le reste — qui l'a servie — a été jugé par la
/// connexion : c'est elle, vérifiée par clé, qui signe.
///
/// # Errors
///
/// [`Faute::Illisible`] pour une liste qui ne se lit pas, ou qui ment.
pub fn verifier_la_liste(corps: &[u8]) -> Result<Vec<RacineApprise>, Faute> {
    let liste = asl_racines::verifier_la_liste(corps).map_err(|_| Faute::Illisible)?;
    liste
        .racines()
        .map(|lue| {
            // La liste est vérifiée : chaque clé est un point, et se déduit en
            // son identifiant. Relire le point ne peut plus échouer.
            let cle = ClePublique::depuis_octets(lue.cle).map_err(|_| Faute::Illisible)?;
            Ok(RacineApprise {
                identifiant: lue.annuaire,
                cle,
                locateurs: lue
                    .locateurs()
                    .iter()
                    .map(|&texte| texte.to_owned())
                    .collect(),
            })
        })
        .collect()
}

/// Joint la racine au bout de ce locateur — sous cette confiance —, lui
/// demande `GET /v1/racines`, et rend la liste vérifiée : ce qu'un client
/// fait pour renouveler les locateurs qu'il tient (décision 56).
///
/// # Errors
///
/// [`Faute`] : la racine ne se joint pas ou n'est pas celle qu'on attend ;
/// elle ne rend pas `200` ; la liste ne se lit pas ou ment.
pub async fn apprendre_les_racines(
    adresse: &str,
    confiance: &Confiance,
) -> Result<Vec<RacineApprise>, Faute> {
    let cible = resoudre(adresse).await?;
    let mut connexion = Connexion::ouvrir(cible, adresse, confiance, 5_000_000).await?;
    let reponse = connexion.requete(b"GET", b"/v1/racines", &[], b"").await?;
    match reponse.statut.value() {
        200 => verifier_la_liste(&reponse.corps),
        autre => Err(Faute::Statut(autre)),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ALIAS_DES_RACINES, RACINES, identites_du_locateur, racines_encodees, verifier_la_liste,
    };

    #[test]
    fn chaque_cle_embarquee_se_deduit_en_son_identifiant() {
        // Une clé recopiée de travers ne passerait pas : l'identifiant écrit à
        // côté est celui qu'on a relevé sur le banc.
        for racine in RACINES {
            let cle = asl_cle::ClePublique::depuis_octets(racine.cle).expect("un point");
            assert_eq!(
                asl_cle::identifiant_de_racine(&cle).texte().as_str(),
                racine.identifiant
            );
            // Ses locateurs la désignent, elle seule.
            for locateur in racine.locateurs {
                assert_eq!(identites_du_locateur(locateur), vec![cle], "{locateur}");
            }
        }
    }

    #[test]
    fn l_alias_designe_les_deux_et_un_inconnu_personne() {
        assert_eq!(identites_du_locateur(ALIAS_DES_RACINES).len(), 2);
        assert_eq!(
            identites_du_locateur("ASL-ROOT.air-desktop.org:6630").len(),
            2
        );
        assert!(identites_du_locateur("127.0.0.1:6630").is_empty());
    }

    #[test]
    fn les_deux_racines_s_encodent_telles_qu_embarquees() {
        let encodees = racines_encodees();
        assert_eq!(encodees.len(), RACINES.len());
        for (racine, octets) in RACINES.iter().zip(&encodees) {
            let texte = core::str::from_utf8(octets).expect("de l'ASCII");
            assert!(texte.starts_with(&format!("{{\"annuaire\":\"{}\"", racine.identifiant)));
            let hexa: String = racine
                .cle
                .iter()
                .map(|octet| format!("{octet:02x}"))
                .collect();
            assert!(texte.contains(&format!("\"cle\":\"{hexa}\"")), "{texte}");
            for locateur in racine.locateurs {
                assert!(texte.contains(&format!("\"{locateur}\"")), "{texte}");
            }
        }
    }

    #[test]
    fn la_liste_servie_se_verifie_et_une_cle_etrangere_la_refuse() {
        let corps = |encodees: &[Vec<u8>]| {
            let mut corps = b"[".to_vec();
            corps.extend(encodees.join(&b","[..]));
            corps.push(b']');
            corps
        };
        let apprises = verifier_la_liste(&corps(&racines_encodees())).expect("elle se vérifie");
        assert_eq!(apprises.len(), RACINES.len());
        for (apprise, embarquee) in apprises.iter().zip(RACINES) {
            assert_eq!(apprise.identifiant.texte().as_str(), embarquee.identifiant);
            assert_eq!(apprise.cle.octets(), embarquee.cle);
            assert_eq!(apprise.locateurs, embarquee.locateurs);
        }
        // La clé d'argon sous l'identité de nitrogen : la liste ment.
        let menteuse = String::from_utf8(corps(&racines_encodees()))
            .expect("de l'ASCII")
            .replacen(
                &RACINES[0]
                    .cle
                    .iter()
                    .map(|o| format!("{o:02x}"))
                    .collect::<String>(),
                &RACINES[1]
                    .cle
                    .iter()
                    .map(|o| format!("{o:02x}"))
                    .collect::<String>(),
                1,
            );
        assert!(verifier_la_liste(menteuse.as_bytes()).is_err());
        // Trente-deux octets qui ne sont pas un point : refusée aussi.
        let pas_un_point = String::from_utf8(corps(&racines_encodees()))
            .expect("de l'ASCII")
            .replacen(
                &RACINES[0]
                    .cle
                    .iter()
                    .map(|o| format!("{o:02x}"))
                    .collect::<String>(),
                &"ff".repeat(32),
                1,
            );
        assert!(verifier_la_liste(pas_un_point.as_bytes()).is_err());
        assert!(verifier_la_liste(b"[]").is_err());
    }
}
