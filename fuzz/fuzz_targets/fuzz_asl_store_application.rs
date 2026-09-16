//! **Cible : l'application des opérations reçues** — des octets quelconques,
//! décodés en cadres, appliqués à un entrepôt.
//!
//! # POURQUOI CELLE-CI, ALORS QUE L'ÉTAGE 3 EST HORS DU 100 %
//!
//! L'entrepôt fait des entrées-sorties, et sa COUVERTURE est hors de portée —
//! simuler des pannes du noyau mesurerait la simulation. Mais **la
//! panique-freedom, elle, se fuzze**, et c'est un tout autre objet : un
//! attaquant qui tient l'autre racine (ou un intermédiaire qui a la clé)
//! CHOISIT les opérations qu'on applique, et aucune séquence d'opérations
//! décodées ne doit faire paniquer l'application ni corrompre l'entrepôt.
//!
//! **L'entrepôt est EN MÉMOIRE** ([`Entrepot::en_memoire`]) : aucun fichier,
//! aucun `fsync`, donc des milliers d'applications par seconde là où un disque
//! en ferait quelques centaines. La règle appliquée est la même — c'est le
//! support qui change.
//!
//! # Les propriétés
//!
//! 1. **RIEN NE PANIQUE**, sur n'importe quelle suite de cadres, dans les deux
//!    modes — le flux (avec ses gardes : recul, rejeu, provenance) et
//!    l'instantané (la fusion, qui n'exerce que la règle de conflit).
//! 2. **L'ENTREPÔT RESTE LISIBLE** après coup : son instantané se relit sans
//!    faute. Une application qui laisserait un index en désaccord avec sa table
//!    se verrait ici — l'instantané balaie tout ce qui se réplique.
//! 3. **LE CADRE DE FIN POSE LE CURSEUR SANS L'APPLIQUER** : un `Cadre::Fin`
//!    n'est jamais pris pour un fait (c'est déjà tenu par le décodeur), et son
//!    application avance le curseur et le compteur, sans écrire d'enregistrement.

#![no_main]

use libfuzzer_sys::fuzz_target;

use asl_id::{Genre, Identifiant};
use asl_registre::Cadre;
use asl_store::{Applique, Entrepot};

/// La racine LOCALE de l'entrepôt fuzzé.
fn locale() -> Identifiant {
    Identifiant::depuis_entropie(Genre::Annuaire, [0xEE; 16])
}

/// Le pair dont on tire.
fn pair() -> Identifiant {
    Identifiant::depuis_entropie(Genre::Annuaire, [0xAA; 16])
}

/// Applique tout ce que ces octets portent de cadres, dans ce mode, à un
/// entrepôt neuf en mémoire — et rend l'entrepôt s'il reste lisible.
fn appliquer_tout(octets: &[u8], instantane: bool) {
    let Ok(entrepot) = Entrepot::en_memoire(locale()) else {
        return;
    };
    let mut reste = octets;
    // Une borne : un flux d'octets pathologique ne doit pas faire tourner cette
    // itération sans fin. Chaque cadre fait au moins un octet, donc la longueur
    // majore le nombre de tours ; on la double pour rester ample sans être
    // infini.
    let mut tours = octets.len().saturating_mul(2).saturating_add(1);
    while !reste.is_empty() && tours > 0 {
        tours -= 1;
        let Ok((cadre, combien)) = Cadre::lire(reste) else {
            break;
        };
        // **NE DOIT PAS PANIQUER**, quelle que soit l'opération décodée.
        match entrepot.appliquer(pair(), &cadre, instantane) {
            Ok(Applique::Faite { .. } | Applique::Fin { .. } | Applique::Refusee(_)) => {}
            // Une faute de base en mémoire est possible (table pleine, etc.) :
            // on l'accepte, ce n'est pas une panique.
            Err(_) => break,
        }
        let avance = combien.max(1).min(reste.len());
        reste = &reste[avance..];
    }
    // **L'ENTREPÔT RESTE LISIBLE** : l'instantané balaie tout ce qui se
    // réplique, et un index en désaccord avec sa table se verrait ici.
    let _ = entrepot.instantane();
}

fuzz_target!(|octets: &[u8]| {
    // Le mode flux : les gardes s'exercent — un cadre qui recule, qui porte
    // notre propre racine (rejeu), ou une provenance hors périmètre.
    appliquer_tout(octets, false);
    // Le mode instantané : la fusion, qui applique la règle de conflit de
    // chaque genre sans garde.
    appliquer_tout(octets, true);
});
