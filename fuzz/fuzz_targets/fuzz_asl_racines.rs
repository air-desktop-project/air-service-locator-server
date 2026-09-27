//! **Cible : ce qu'on croit d'un inconnu, avant de le croire** — une liste de
//! racines servie par `GET /v1/racines`, et le certificat qu'un pair présente
//! (décisions 53, 54 et 56).
//!
//! # Pourquoi celle-ci
//!
//! La liste arrive d'une racine qu'on vient seulement de joindre, et le
//! certificat d'un pair qu'on n'a pas encore cru : ce sont les octets sur
//! lesquels on décide de faire confiance. Les deux passent par des fonctions
//! pures d'`asl-racines`.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, sur aucun octet.
//! 2. **UNE LISTE ACCEPTÉE NE MENT PAS** : chacune de ses clés est un point, et
//!    se déduit en l'identifiant écrit à côté — recalculé ici.
//! 3. **UN CERTIFICAT N'EST UNE IDENTITÉ QUE D'UN SEUL MAILLON** : sous tout
//!    autre compte de maillons, aucune identité n'est rendue ; et l'identité
//!    rendue est celle de la clé qu'il porte, recalculée ici.
//! 4. **RIEN D'ATTENDU, RIEN DE CRU.**

#![no_main]

use libfuzzer_sys::fuzz_target;

use asl_cle::{ClePublique, cle_du_certificat, identifiant_de_racine};
use asl_racines::{identite_attendue, identite_du_certificat, verifier_la_liste};

fuzz_target!(|octets: &[u8]| {
    if let Ok(liste) = verifier_la_liste(octets) {
        for lue in liste.racines() {
            let cle = ClePublique::depuis_octets(lue.cle).expect("une clé acceptée est un point");
            assert_eq!(
                identifiant_de_racine(&cle),
                lue.annuaire,
                "une liste acceptée ment"
            );
        }
    }

    let maillons = usize::from(octets.first().copied().unwrap_or(0) % 4);
    let certificat = octets.get(1..).unwrap_or_default();
    let identite = identite_du_certificat(maillons, certificat);
    if maillons != 1 {
        assert_eq!(identite, None, "une identité hors d'un seul maillon");
    }
    if let Some(rendue) = identite {
        let cle = cle_du_certificat(certificat).expect("une identité rendue se relit");
        assert_eq!(rendue, identifiant_de_racine(&cle));
        assert_eq!(
            identite_attendue(maillons, certificat, &[rendue]),
            Some(rendue)
        );
    }
    assert_eq!(identite_attendue(maillons, certificat, &[]), None);
});
