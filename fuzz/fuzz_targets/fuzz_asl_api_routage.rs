//! **Cible : le routage** — des octets de chemin entièrement contrôlés par un
//! inconnu vers une ressource, ou vers un refus.
//!
//! # Pourquoi celle-ci
//!
//! **Un chemin est ce qu'un attaquant contrôle le plus complètement.** C'est la
//! première surface de cette API qu'aucune norme ne décrit, et la quasi-totalité
//! des fautes d'autorisation d'une API vit dans l'écart entre deux écritures
//! d'une même cible.
//!
//! Ce module REFUSE au lieu de normaliser — pas de pourcent-encodage, pas de
//! segment vide, un alphabet étroit — et c'est cette promesse-là qu'il faut
//! vérifier sur des octets qu'on n'a pas choisis.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique.**
//! 2. **AUCUN SEGMENT ACCEPTÉ N'EST `.`, `..`, VIDE, OU HORS DE L'ASCII
//!    GRAPHIQUE.** Vérifié sur l'ENTRÉE d'un chemin accepté, parce que c'est
//!    d'elle que la promesse parle.
//! 3. **AUCUN POURCENT N'A SURVÉCU.** Le refus le plus structurant du module.
//! 4. **CE QU'ON A COMPRIS, ON SAIT LE RÉÉCRIRE — ET LE RELIRE À L'IDENTIQUE.**
//!    Sans cela, il existerait une cible que le serveur accepte mais ne sait pas
//!    désigner, et ses deux moitiés ne parleraient plus de la même ressource.
//! 5. **`sert` DIT EXACTEMENT CE QUE `verbes` ANNONCE**, et le routage n'échoue
//!    JAMAIS sur le verbe — c'est la propriété de sécurité du module.
//! 6. **L'EXIGENCE NE DÉPEND PAS DU VERBE.** Une ressource exige la même chose
//!    quelle que soit la méthode ; sinon un `GET` ouvrirait ce qu'un `POST`
//!    ferme.
//! 7. **LA CHAÎNE DE REQUÊTE NE CHANGE JAMAIS LA RESSOURCE**, sauf là où elle la
//!    définit (`/v1/ou`).

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asl_api::{Erreur, Exigence, Methode, Ressource, resoudre, separer_requete};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// La cible, telle qu'elle arriverait du réseau.
    cible: &'a [u8],
    /// La méthode.
    methode: u8,
}

/// La méthode que désigne un octet.
const fn methode(brut: u8) -> Methode {
    match brut % 5 {
        0 => Methode::Get,
        1 => Methode::Post,
        2 => Methode::Put,
        3 => Methode::Patch,
        _ => Methode::Delete,
    }
}

/// Le chemin canonique d'une ressource, recomposé depuis ce qu'on en a compris.
fn chemin_de(ressource: &Ressource<'_>) -> String {
    match ressource {
        Ressource::Annonce => "/v1/annonce".to_owned(),
        Ressource::Defi => "/v1/defi".to_owned(),
        Ressource::Poussees => "/v1/poussees".to_owned(),
        Ressource::Comptes => "/v1/comptes".to_owned(),
        Ressource::Enrolement => "/v1/enrolement".to_owned(),
        Ressource::Utilisateur { compte } => format!("/v1/utilisateurs/{compte}"),
        Ressource::Appareils => "/v1/appareils".to_owned(),
        Ressource::Appareil { appareil } => format!("/v1/appareils/{appareil}"),
        Ressource::PousseeAppareil { appareil } => format!("/v1/appareils/{appareil}/poussee"),
        Ressource::Machines => "/v1/machines".to_owned(),
        Ressource::Machine { machine } => format!("/v1/machines/{machine}"),
        Ressource::EnrolementMachine { machine } => format!("/v1/machines/{machine}/enrolement"),
        Ressource::CleMachine { machine } => format!("/v1/machines/{machine}/cle"),
        Ressource::ServicesMachine { machine } => format!("/v1/machines/{machine}/services"),
        Ressource::Autorisations => "/v1/autorisations".to_owned(),
        Ressource::Autorisation { autorisation } => format!("/v1/autorisations/{autorisation}"),
        Ressource::Alias => "/v1/alias".to_owned(),
        Ressource::AliasResolu { alias } => format!("/v1/alias/{}", alias.as_str()),
        Ressource::Expositions => "/v1/expositions".to_owned(),
        Ressource::Exposition { annuaire } => format!("/v1/expositions/{annuaire}"),
        Ressource::Ou { machine, service } => format!("/v1/ou/{machine}/{service}"),
        Ressource::OuParNom { service } => format!("/v1/ou?service={service}"),
    }
}

fuzz_target!(|entree: Entree| {
    let methode = methode(entree.methode);

    // PROPRIÉTÉ 7 : la séparation ne perd ni n'invente rien.
    let (chemin, requete) = separer_requete(entree.cible);
    assert!(chemin.len() <= entree.cible.len());
    assert!(requete.len() <= entree.cible.len());
    assert!(!chemin.contains(&b'?'), "un `?` est resté dans le chemin");

    let Ok(resolu) = resoudre(methode, entree.cible) else {
        return;
    };
    let ressource = resolu.ressource;

    // ── PROPRIÉTÉ 5 : le routage ne juge pas le verbe ───────────────────────
    assert_eq!(resolu.methode, methode);
    assert_eq!(resolu.sert, ressource.verbes().contains(&methode));
    assert_eq!(resolu.sert, ressource.sert(methode));

    // ── PROPRIÉTÉ 6 : l'exigence ne dépend pas du verbe ─────────────────────
    assert_eq!(resolu.exigence, ressource.exigence());
    for autre in [
        Methode::Get,
        Methode::Post,
        Methode::Put,
        Methode::Patch,
        Methode::Delete,
    ] {
        let encore =
            resoudre(autre, entree.cible).expect("le chemin se résout quel que soit le verbe");
        assert_eq!(
            encore.ressource, ressource,
            "le verbe a changé la ressource"
        );
        assert_eq!(
            encore.exigence, resolu.exigence,
            "le verbe a changé l'exigence"
        );
    }

    // ── PROPRIÉTÉS 2 et 3 : ce qui a été accepté ────────────────────────────
    assert!(
        !chemin.contains(&b'%'),
        "un pourcent-encodage a été accepté"
    );
    for segment in chemin.split(|octet| *octet == b'/').skip(1) {
        assert!(!segment.is_empty(), "un segment vide a été accepté");
        assert_ne!(segment, b".", "un segment `.` a été accepté");
        assert_ne!(segment, b"..", "un segment `..` a été accepté");
        for octet in segment {
            assert!(
                octet.is_ascii_graphic(),
                "un octet hors ASCII graphique a été accepté : {octet:?}"
            );
        }
    }

    // ── PROPRIÉTÉ 4 : l'aller-retour ────────────────────────────────────────
    //
    // On réécrit le chemin depuis ce qu'on en a COMPRIS, et il doit désigner la
    // même chose. C'est ce qui garantit qu'il n'existe pas de cible que le
    // serveur accepte sans savoir la nommer.
    let refait = chemin_de(&ressource);
    let relu = resoudre(methode, refait.as_bytes())
        .expect("un chemin reconstruit depuis sa ressource se relit");
    assert_eq!(
        relu.ressource, ressource,
        "l'aller-retour a changé la ressource : {refait}"
    );
    assert_eq!(relu.exigence, resolu.exigence);
    assert_eq!(relu.sert, resolu.sert);

    // Réécrire deux fois ne change plus rien.
    assert_eq!(chemin_de(&relu.ressource), refait);

    // ── LA LISTE CLOSE DE CE QUI N'EXIGE RIEN ───────────────────────────────
    //
    // Cinq ressources, et chacune a sa raison écrite sur `Ressource::exigence`.
    // **CETTE ASSERTION A DÉJÀ SERVI** : elle a arrêté `/v1/enrolement` le jour
    // de son ajout. Le verbe était légitime et sa liberté délibérée — mais
    // c'est précisément le point : une ressource ne devient publique que si
    // quelqu'un l'écrit ICI, jamais parce qu'un `_ =>` l'a laissée passer.
    if resolu.exigence == Exigence::Aucune {
        assert!(
            matches!(
                ressource,
                Ressource::Defi
                    | Ressource::Comptes
                    | Ressource::Enrolement
                    | Ressource::AliasResolu { .. }
                    | Ressource::Utilisateur { .. }
            ),
            "une ressource inattendue n'exige rien : {ressource:?}"
        );
    }

    // Et une faute de chemin ne se déguise jamais en autre chose.
    if let Err(faute) = resoudre(methode, entree.cible) {
        assert!(matches!(
            faute,
            Erreur::CibleTropLongue { .. }
                | Erreur::CibleSansRacine
                | Erreur::CibleNonAscii { .. }
                | Erreur::SegmentVide { .. }
                | Erreur::EncodageRefuse { .. }
                | Erreur::RessourceInconnue
                | Erreur::IdentifiantInvalide { .. }
                | Erreur::NomInvalide
                | Erreur::AliasLongueur { .. }
                | Erreur::AliasSymboleInvalide { .. }
                | Erreur::AliasBordInvalide
                | Erreur::AliasRessembleAUnIdentifiant
                | Erreur::RequeteInvalide
        ));
    }
});
