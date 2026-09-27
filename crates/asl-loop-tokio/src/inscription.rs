//! L'annuaire local qui se présente aux racines (`docs/annuaires.md` §4.1,
//! `protocole.md` §2.2 et §3 ter ; 0.27.0) : la connexion sortante, et les
//! deux verbes — présenter son code, relire son état.
//!
//! # LE CÔTÉ CLIENT DE L'INSCRIPTION, ET RIEN DE PLUS
//!
//! C'est [`crate::exploitant`] une fois de plus : ouvrir une connexion vers
//! une racine EN MARCHE, tirer un défi, prouver une clé, poster. Ce qui
//! change est la clé — **celle d'identité de l'annuaire**, dont son `n-…` se
//! déduit — et la preuve : celle de la possession, comme un enrôlement,
//! puisque la racine ne connaît pas encore la clé.
//!
//! La voie de la fédération — les machines reçues, l'état des services
//! poussé — n'est pas ici : c'est la PR suivante.

use asl_cle::CleSecrete;

use crate::tireur::{Connexion, Faute as FauteDeVoie, resoudre};

/// Ce qui peut empêcher une inscription de se présenter ou de se relire.
#[derive(Debug)]
pub enum Faute {
    /// La connexion n'a pas abouti, ou la racine n'a rien rendu de lisible.
    Voie(FauteDeVoie),
    /// Le code ne se lit pas : dix symboles, un tiret facultatif.
    CodeIllisible,
    /// `404` : code inconnu — ou, pour l'état, une clé qui n'est membre de
    /// rien.
    Inconnu,
    /// `403` : le code a passé son heure.
    Expire,
    /// `409` : une autre clé a présenté ce code, ou cette clé est déjà
    /// membre d'un autre annuaire.
    Deja,
    /// `429` : trop d'échecs depuis cette adresse.
    TropDEchecs,
    /// La racine a répondu autre chose que ce que le verbe promet.
    Statut(u16),
    /// La réponse ne porte pas l'état là où il est promis.
    ReponseIllisible,
}

impl core::fmt::Display for Faute {
    fn fmt(&self, sortie: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Voie(quoi) => write!(sortie, "{quoi}"),
            Self::CodeIllisible => sortie.write_str(
                "le code d'inscription ne se lit pas : dix symboles, comme l'application l'a donné",
            ),
            Self::Inconnu => sortie.write_str(
                "la racine ne connaît pas ce code, ou cette clé n'est membre d'aucun annuaire",
            ),
            Self::Expire => sortie
                .write_str("ce code a passé son heure : redemandez-en un depuis l'application"),
            Self::Deja => sortie.write_str(
                "ce code a déjà été présenté par une autre clé, ou cette clé est déjà membre \
                 d'un autre annuaire",
            ),
            Self::TropDEchecs => sortie.write_str(
                "la racine a compté trop d'échecs depuis cette adresse — attendez une minute",
            ),
            Self::Statut(code) => write!(sortie, "la racine a répondu {code}"),
            Self::ReponseIllisible => {
                sortie.write_str("la racine a répondu 200, mais sans état lisible")
            }
        }
    }
}

impl std::error::Error for Faute {}

/// Ce que la racine dit de cette inscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtatLu {
    /// Le `n-…` du membre — celui de la clé.
    pub membre: String,
    /// L'annuaire — son titulaire.
    pub annuaire: String,
    /// `en attente`, `acceptée`, `refusée`, `retirée`.
    pub etat: String,
}

/// L'inactivité annoncée à la racine, en microsecondes : un geste ne dure
/// qu'un aller-retour.
const INACTIVITE_US: u64 = 30 * 1_000_000;

/// Présente ce code avec cette clé d'identité, et rend l'état.
///
/// # Errors
///
/// [`Faute::CodeIllisible`] avant toute connexion ; les refus de la racine ;
/// [`Faute::Voie`] si la connexion échoue.
pub async fn presenter(
    adresse: &str,
    confiance: &crate::confiance::Confiance,
    identite: &CleSecrete,
    code: &str,
) -> Result<EtatLu, Faute> {
    let code = asl_cle::CodeInscription::analyser(code).map_err(|_| Faute::CodeIllisible)?;
    let mut corps = code.texte().as_bytes().to_vec();
    poster(
        adresse,
        confiance,
        identite,
        b"/v1/annuaires/inscription",
        &mut corps,
    )
    .await
}

/// Relit l'état de l'inscription de cette clé d'identité.
///
/// # Errors
///
/// [`Faute::Inconnu`] si la clé n'est membre de rien ; [`Faute::Voie`] si la
/// connexion échoue.
pub async fn relire(
    adresse: &str,
    confiance: &crate::confiance::Confiance,
    identite: &CleSecrete,
) -> Result<EtatLu, Faute> {
    let mut corps = Vec::new();
    poster(
        adresse,
        confiance,
        identite,
        b"/v1/annuaires/etat",
        &mut corps,
    )
    .await
}

/// Ouvre, tire un défi, prouve la possession de la clé, poste
/// `corps ‖ clé ‖ preuve`, et lit la réponse.
async fn poster(
    adresse: &str,
    confiance: &crate::confiance::Confiance,
    identite: &CleSecrete,
    chemin: &[u8],
    corps: &mut Vec<u8>,
) -> Result<EtatLu, Faute> {
    let cible = resoudre(adresse).await.map_err(Faute::Voie)?;
    let mut connexion = Connexion::ouvrir(cible, adresse, confiance, INACTIVITE_US)
        .await
        .map_err(Faute::Voie)?;
    let defi = connexion.defi().await.map_err(Faute::Voie)?;
    let preuve = identite.prouver_la_possession(&defi, &connexion.liaison);
    corps.extend_from_slice(&identite.publique().octets());
    corps.extend_from_slice(preuve.octets());
    let reponse = connexion
        .requete(
            b"POST",
            chemin,
            &[(b"content-type", b"application/octet-stream")],
            corps,
        )
        .await
        .map_err(Faute::Voie)?;
    match reponse.statut.value() {
        200 => lire_l_etat(&reponse.corps).ok_or(Faute::ReponseIllisible),
        404 => Err(Faute::Inconnu),
        403 => Err(Faute::Expire),
        409 => Err(Faute::Deja),
        429 => Err(Faute::TropDEchecs),
        autre => Err(Faute::Statut(autre)),
    }
}

/// Lit la valeur de ce champ texte, dans un objet JSON sans échappement.
fn champ(texte: &str, nom: &str) -> Option<String> {
    let valeur = texte
        .split(&format!("\"{nom}\":\""))
        .nth(1)?
        .split('"')
        .next()?;
    (!valeur.is_empty()).then(|| valeur.to_owned())
}

/// Lit `{"membre":"n-…","annuaire":"n-…","etat":"…","adresse":"…"}` — **à la
/// main**, comme [`crate::exploitant`] lit un code : trois champs, et pas de
/// dépendance d'analyse de plus pour eux.
fn lire_l_etat(corps: &[u8]) -> Option<EtatLu> {
    let texte = core::str::from_utf8(corps).ok()?;
    Some(EtatLu {
        membre: champ(texte, "membre")?,
        annuaire: champ(texte, "annuaire")?,
        etat: champ(texte, "etat")?,
    })
}

#[cfg(test)]
mod essais {
    use super::{EtatLu, lire_l_etat};

    #[test]
    fn l_etat_se_lit() {
        let rendu = br#"{"membre":"n-1","annuaire":"n-2","etat":"en attente","adresse":"a:1"}"#;
        assert_eq!(
            lire_l_etat(rendu),
            Some(EtatLu {
                membre: "n-1".to_owned(),
                annuaire: "n-2".to_owned(),
                etat: "en attente".to_owned(),
            })
        );
    }

    #[test]
    fn une_reponse_incomplete_ne_s_invente_pas() {
        for rendu in [
            &br#"{"annuaire":"n-2","etat":"x"}"#[..],
            &br#"{"membre":"n-1","etat":"x"}"#[..],
            &br#"{"membre":"n-1","annuaire":"n-2"}"#[..],
            &br#"{"membre":"","annuaire":"n-2","etat":"x"}"#[..],
            &[0xFF, 0xFE][..],
        ] {
            assert_eq!(lire_l_etat(rendu), None, "{rendu:?}");
        }
    }
}
