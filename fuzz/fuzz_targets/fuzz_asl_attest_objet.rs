//! **Cible : l'attestation de plate-forme** — des octets quelconques vers un
//! objet d'App Attest.
//!
//! # POURQUOI CELLE-CI EST LA PLUS EXPOSÉE DU DÉPÔT
//!
//! Ces octets viennent d'un APPAREIL QUI N'A PAS ENCORE DE COMPTE. Toutes les
//! autres grammaires du produit se lisent après qu'une identité a été établie ;
//! celle-ci se lit AVANT, et c'est précisément ce qu'elle sert à établir.
//!
//! Autrement dit : quiconque peut ouvrir une connexion peut choisir ces octets,
//! et n'a rien à perdre à les choisir mal.
//!
//! # LES PROPRIÉTÉS
//!
//! 1. **Rien ne panique**, sur n'importe quels octets.
//! 2. **UN REFUS EST TOUJOURS UNE FAUTE NOMMÉE.** Il n'en existe pas d'autre
//!    sorte, et une panique n'en est pas une.
//! 3. **LE CURSEUR AVANCE TOUJOURS.** Une lecture qui réussit sans consommer
//!    d'octet ferait boucler indéfiniment quiconque lit un conteneur. C'est une
//!    faute de disponibilité, et elle ne se voit pas sur un objet bien formé.
//! 4. **LE CURSEUR NE DÉPASSE JAMAIS LA FIN.**
//! 5. **TOUT CE QUI EST RENDU EST UNE TRANCHE DE L'ENTRÉE.** Pas une copie
//!    ailleurs, pas un tampon statique : les octets rendus sont, littéralement,
//!    ceux qu'on a soumis. Sans cela, le nonce se calculerait sur autre chose
//!    que ce qui a été signé.
//! 6. **`authData` SE RECONSTITUE OCTET POUR OCTET** depuis ce qui en a été lu.
//!    C'est l'équivalent ici de l'aller-retour des enregistrements : si la
//!    somme des morceaux ne rend pas le tout, un morceau a été mal découpé.
//! 7. **LIRE DEUX FOIS REND LA MÊME CHOSE.**

#![no_main]

use libfuzzer_sys::fuzz_target;

use asl_attest::{
    AAGUID_OCTETS, AUTH_MINIMUM, EMPREINTE_OCTETS, Erreur, Lecteur, ObjetAttestation, Valeur,
    X5C_MAX,
};

/// Une faute est toujours l'une des quinze, et jamais une panique.
fn nommee(faute: Erreur) {
    assert!(matches!(
        faute,
        Erreur::Tronque { .. }
            | Erreur::TypeRefuse { .. }
            | Erreur::LongueurIndefinie { .. }
            | Erreur::EnteteReserve { .. }
            | Erreur::EncodageNonMinimal { .. }
            | Erreur::LongueurDemesuree { .. }
            | Erreur::TexteInvalide { .. }
            | Erreur::PasLeBonType { .. }
            | Erreur::TropProfond { .. }
            | Erreur::DonneesEnTrop { .. }
            | Erreur::ChampManquant { .. }
            | Erreur::ChampEnDouble { .. }
            | Erreur::FormatInconnu
            | Erreur::TropDeCertificats { .. }
            | Erreur::AuthDataTronque { .. }
    ));
}

/// La tranche rendue est-elle bien DANS les octets soumis ?
fn dedans(entree: &[u8], tranche: &[u8]) {
    if tranche.is_empty() {
        return;
    }
    let bornes = entree.as_ptr_range();
    let rendue = tranche.as_ptr_range();
    assert!(
        rendue.start >= bornes.start && rendue.end <= bornes.end,
        "une tranche rendue ne vient pas des octets soumis"
    );
}

fuzz_target!(|octets: &[u8]| {
    // ── LE LECTEUR SEUL : propriétés 1 à 5 ──────────────────────────────────
    let mut lecteur = Lecteur::nouveau(octets);
    loop {
        let avant = lecteur.position();
        let Ok(valeur) = lecteur.valeur() else {
            break;
        };
        let apres = lecteur.position();
        assert!(apres > avant, "une valeur lue n'a consommé aucun octet");
        assert!(apres <= octets.len(), "le curseur a dépassé la fin");
        match valeur {
            Valeur::Octets(tranche) => dedans(octets, tranche),
            Valeur::Texte(texte) => dedans(octets, texte.as_bytes()),
            Valeur::Entier(_) | Valeur::Tableau(_) | Valeur::Carte(_) => {}
        }
    }

    // Sauter, depuis le début, a les mêmes obligations.
    let mut lecteur = Lecteur::nouveau(octets);
    while lecteur.sauter().is_ok() {
        assert!(
            lecteur.position() <= octets.len(),
            "le curseur a dépassé la fin en sautant"
        );
        if lecteur.restants() == 0 {
            break;
        }
    }

    // ── L'OBJET : propriétés 6 et 7 ─────────────────────────────────────────
    let lu = ObjetAttestation::lire(octets);
    assert_eq!(lu, ObjetAttestation::lire(octets), "lire n'est pas stable");

    let objet = match lu {
        Ok(objet) => objet,
        Err(faute) => {
            nommee(faute);
            return;
        }
    };

    assert!(objet.chaine().len() <= X5C_MAX);
    for der in objet.chaine() {
        dedans(octets, der);
    }
    if let Some(recu) = objet.recu {
        dedans(octets, recu);
    }
    dedans(octets, objet.donnees_auth);
    dedans(octets, objet.auth.empreinte_app);

    assert_eq!(objet.auth.empreinte_app.len(), EMPREINTE_OCTETS);
    assert!(objet.donnees_auth.len() >= AUTH_MINIMUM);

    // PROPRIÉTÉ 6 : la somme des morceaux rend le tout.
    let mut refait = Vec::with_capacity(objet.donnees_auth.len());
    refait.extend_from_slice(objet.auth.empreinte_app);
    refait.push(objet.auth.drapeaux);
    refait.extend_from_slice(&objet.auth.compteur.to_be_bytes());
    if let Some(cle) = objet.auth.cle {
        dedans(octets, cle.aaguid);
        dedans(octets, cle.identifiant);
        dedans(octets, cle.cle_cose);
        assert_eq!(cle.aaguid.len(), AAGUID_OCTETS);
        let longueur = u16::try_from(cle.identifiant.len()).expect("un identifiant court");
        refait.extend_from_slice(cle.aaguid);
        refait.extend_from_slice(&longueur.to_be_bytes());
        refait.extend_from_slice(cle.identifiant);
        refait.extend_from_slice(cle.cle_cose);
    } else {
        assert_eq!(
            objet.donnees_auth.len(),
            AUTH_MINIMUM,
            "sans clé attestée, `authData` n'a rien de plus à porter"
        );
    }
    assert_eq!(
        refait, objet.donnees_auth,
        "`authData` ne se reconstitue pas octet pour octet"
    );
});
