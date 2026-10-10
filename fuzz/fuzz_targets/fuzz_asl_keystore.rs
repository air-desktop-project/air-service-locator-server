//! **Cible : la vérification d'une attestation de clé Android** — des octets
//! quelconques vers un verdict, sous DEUX racines : celle du banc, et celle de
//! Google.
//!
//! # LA PROPRIÉTÉ QUI COMPTE, ET ELLE EST FORTE
//!
//! Sous chaque racine, UNE SEULE feuille a jamais été mise entre les mains de
//! libFuzzer : celle du banc (`banc-acceptee`), celle du Fairphone 5
//! (`reelle-entiere`). Donc **tout `Ok` doit rendre exactement la clé de cette
//! feuille-là**. Un `Ok` qui en rendrait une autre serait une contrefaçon —
//! libFuzzer aurait forgé une chaîne pour une clé qu'aucune racine n'a signée.
//!
//! **La racine de Google et la chaîne réelle, comme graine.** C'est ce qui
//! distingue cette cible de celle d'`asl-apple` : ici, la campagne part aussi
//! d'une chaîne qu'un vrai TEE a émise, et chaque déformation de cette chaîne
//! passe par les vrais vérificateurs — RSA-4096 compris.
//!
//! Les autres :
//!
//! 1. **Rien ne panique**, ni dans la vérification, ni dans le découpage de la
//!    case, ni dans le marcheur X.509, ni dans le lecteur de `KeyDescription`
//!    pris seuls.
//! 2. **Le lecteur de `KeyDescription` ne rend que des tranches de l'entrée.**
//! 3. **Un refus est toujours nommé.**
//! 4. **La vérification est stable** : deux fois les mêmes octets, le même
//!    verdict.

#![no_main]

use libfuzzer_sys::fuzz_target;

use asl_keystore::{Attendu, Refus, case, description, verifier, x509};

const RACINE_DU_BANC: &[u8] =
    include_bytes!("../../crates/asl-keystore/tests/fixtures/racine-du-banc.der");
const CLE_DU_BANC: &[u8; 33] =
    include_bytes!("../../crates/asl-keystore/tests/fixtures/cle-du-banc.bin");
const DEFI_DU_BANC: &[u8] =
    include_bytes!("../../crates/asl-keystore/tests/fixtures/defi-du-banc.bin");

const RACINE_DE_GOOGLE: &[u8] =
    include_bytes!("../../docs/attestation/captures/keystore-fp5-2026-09-16/cert3.der");
const FEUILLE_REELLE: &[u8] =
    include_bytes!("../../docs/attestation/captures/keystore-fp5-2026-09-16/cert0.der");
const DEFI_REEL: &[u8] =
    include_bytes!("../../docs/attestation/captures/keystore-fp5-2026-09-16/defi.bin");

/// Le 1er juin 2026, dans la validité des certificats du banc.
const PENDANT: u64 = 1_780_272_000;
/// Le 2026-09-16, le jour de la capture.
const AU_JOUR_DE_LA_CAPTURE: u64 = 1_789_560_000;

/// L'empreinte du banc, et celle de la build de débogage du Fairphone 5.
const EMPREINTE_DU_BANC: [u8; 32] = [0xA5; 32];

/// **DES EMPREINTES QUI NE SONT PAS LES NÔTRES**, pour éprouver l'épinglage
/// multiple par ce qu'il doit REFUSER.
///
/// Le voisin est à **un bit** de celle du banc : c'est lui qui attrape une
/// comparaison tronquée, faite sur un préfixe, ou qui s'arrêterait au premier
/// octet. Les deux autres sont loin, et attrapent le cas grossier.
const LEURRE_NUL: [u8; 32] = [0x00; 32];
const LEURRE_PLEIN: [u8; 32] = [0xFF; 32];
const LEURRE_VOISIN: [u8; 32] = {
    let mut voisin = EMPREINTE_DU_BANC;
    voisin[31] ^= 0x01;
    voisin
};
const EMPREINTE_REELLE: [u8; 32] = [
    0x5e, 0xa3, 0x16, 0xf1, 0xb5, 0x0f, 0x2c, 0xe5, 0x4b, 0x82, 0x25, 0xab, 0xa8, 0x5f, 0xf5, 0xcc,
    0x82, 0x38, 0xa7, 0x10, 0xb8, 0xfa, 0xe4, 0x4b, 0x4f, 0x3a, 0x19, 0x5a, 0xad, 0xeb, 0x5f, 0x68,
];

fn nomme(refus: &Refus) {
    assert!(matches!(
        refus,
        Refus::Case(_)
            | Refus::SansRacine
            | Refus::RacineIllisible
            | Refus::FeuilleIllisible
            | Refus::Chaine(_)
            | Refus::CertificatIllisible
            | Refus::CleInattendue
            | Refus::DescriptionAbsente
            | Refus::DescriptionIllisible(_)
            | Refus::CleDifferente
            | Refus::DefiDifferent
            | Refus::AttestationLogicielle(_)
            | Refus::CleLogicielle(_)
            | Refus::RacineDeConfianceAbsente
            | Refus::DemarrageNonVerifie(_)
            | Refus::AppareilDeverrouille
            | Refus::OrigineAbsente
            | Refus::OrigineInattendue(_)
            | Refus::ApplicationAbsente
            | Refus::AutrePaquet
            | Refus::AutreSignataire
    ));
}

/// Chaque tranche rendue est-elle DANS l'entrée ?
fn dans(entree: &[u8], tranche: &[u8]) -> bool {
    let debut = entree.as_ptr() as usize;
    let t = tranche.as_ptr() as usize;
    tranche.is_empty() || (t >= debut && t + tranche.len() <= debut + entree.len())
}

/// Vérifie sous cette attente, et exige que tout `Ok` rende `cle_attendue`.
///
/// Rend le verdict, pour que l'épreuve de l'épinglage multiple s'y compare sans
/// le recalculer — sur cette cible, une vérification porte du RSA-4096.
fn eprouver(
    octets: &[u8],
    attendu: &Attendu<'_>,
    cle_attendue: &[u8; 33],
) -> Result<asl_keystore::Verdict, Refus> {
    let verdict = verifier(octets, attendu);
    assert_eq!(
        verdict,
        verifier(octets, attendu),
        "la vérification n'est pas stable"
    );
    match &verdict {
        Ok(rendu) => assert_eq!(
            x509::compresser(&rendu.cle),
            *cle_attendue,
            "CONTREFAÇON : une clé que cette racine n'a jamais certifiée"
        ),
        Err(refus) => nomme(refus),
    }
    verdict
}

/// **TROIS PROPRIÉTÉS QUE L'ÉPINGLE UNIQUE NE POUVAIT PAS EXPRIMER.**
///
/// La version précédente d'`Attendu` ne portait qu'une empreinte de signature ;
/// ce harnais ne tirait donc jamais qu'une build reconnue. Depuis que
/// l'exploitant peut en épingler plusieurs — nos propres builds ET celle que
/// Google resigne pour le magasin —, l'élargissement doit être éprouvé par ce
/// qu'il REFUSE, sans quoi la nouveauté serait livrée non fuzzée derrière une CI
/// verte.
///
/// `reference` est le verdict déjà obtenu avec la seule VRAIE empreinte
/// épinglée : on ne le recalcule pas.
fn eprouver_les_signataires(
    octets: &[u8],
    base: &Attendu<'_>,
    vraie: [u8; 32],
    reference: &Result<asl_keystore::Verdict, Refus>,
) {
    // **1. LISTE VIDE ⇒ JAMAIS D'`Ok`.** C'est le refus sûr que documente
    // `Attendu::empreintes` : « vide, rien ne correspond, et toute attestation
    // est refusée ». On n'exige pas `AutreSignataire` : sur des octets
    // quelconques, un refus plus précoce et tout aussi légitime (case, chaîne,
    // description) arrive d'abord. Ce qui doit être impossible, c'est le
    // SUCCÈS — un épinglage vide qui laisserait passer serait une porte ouverte
    // par un tableau oublié.
    let aucune = Attendu {
        empreintes: &[],
        ..*base
    };
    assert!(
        verifier(octets, &aucune).is_err(),
        "AUCUNE empreinte épinglée, et l'attestation est pourtant acceptée"
    );

    // **2. DES LEURRES AUTOUR DE LA VRAIE NE CHANGENT RIEN.** C'est le sens de
    // l'élargissement : ce qui grandit est l'ensemble des builds reconnues, pas
    // le pouvoir d'en forger une. Le verdict doit être EXACTEMENT celui de
    // l'épingle unique — ni plus permissif, ni moins. Attrape une
    // implémentation qui ne regarderait que le premier élément, le dernier, ou
    // qui s'arrêterait au premier leurre rencontré. La vraie est présente deux
    // fois : un doublon ne doit rien changer non plus.
    let elargi = [LEURRE_NUL, vraie, LEURRE_PLEIN, LEURRE_VOISIN, vraie];
    let plusieurs = Attendu {
        empreintes: &elargi,
        ..*base
    };
    assert_eq!(
        &verifier(octets, &plusieurs),
        reference,
        "des empreintes épinglées EN PLUS de la vraie changent le verdict"
    );

    // **3. QUE DES LEURRES ⇒ JAMAIS D'`Ok`.** Dont un à un bit de la vraie.
    // Attrape l'inverse de la propriété 2 : une implémentation qui accepterait
    // parce que la liste n'est pas vide, ou qui comparerait sur un préfixe.
    let aucune_bonne = [LEURRE_NUL, LEURRE_PLEIN, LEURRE_VOISIN];
    let etrangeres = Attendu {
        empreintes: &aucune_bonne,
        ..*base
    };
    assert!(
        verifier(octets, &etrangeres).is_err(),
        "aucune empreinte épinglée n'est la bonne, et l'attestation est pourtant acceptée"
    );
}

fuzz_target!(|octets: &[u8]| {
    // Les trois lecteurs pris seuls, sur n'importe quoi.
    let _ = case::decouper(octets);
    let _ = x509::lire(octets);
    if let Ok(lue) = description::lire(octets) {
        assert!(dans(octets, lue.defi));
        assert!(dans(octets, lue.identifiant_unique));
        for liste in [&lue.logiciel, &lue.materiel] {
            if let Some(racine) = liste.racine_de_confiance {
                assert!(dans(octets, racine.cle_de_demarrage));
                assert!(dans(octets, racine.empreinte_de_demarrage));
            }
            if let Some(app) = &liste.application {
                assert!(app.paquets.iter().all(|p| dans(octets, p.nom)));
                assert!(app.empreintes.iter().all(|e| dans(octets, e)));
            }
        }
    }

    // Sous la racine du banc.
    let racines = [RACINE_DU_BANC];
    let empreintes_du_banc = [EMPREINTE_DU_BANC];
    let banc = Attendu {
        racines: &racines,
        defi: DEFI_DU_BANC,
        cle: CLE_DU_BANC,
        paquet: "org.airdesktop.servicelocator",
        empreintes: &empreintes_du_banc,
        maintenant: PENDANT,
    };
    let verdict_du_banc = eprouver(octets, &banc, CLE_DU_BANC);
    eprouver_les_signataires(octets, &banc, EMPREINTE_DU_BANC, &verdict_du_banc);

    // Sous la racine de Google, au jour de la capture.
    let feuille = x509::lire(FEUILLE_REELLE).expect("la feuille réelle se lit");
    let cle_reelle = x509::compresser(feuille.cle.try_into().expect("65 octets"));
    let racines = [RACINE_DE_GOOGLE];
    let empreintes_reelles = [EMPREINTE_REELLE];
    let google = Attendu {
        racines: &racines,
        defi: DEFI_REEL,
        cle: &cle_reelle,
        paquet: "org.airdesktop.servicelocator",
        empreintes: &empreintes_reelles,
        maintenant: AU_JOUR_DE_LA_CAPTURE,
    };
    let verdict_reel = eprouver(octets, &google, &cle_reelle);
    eprouver_les_signataires(octets, &google, EMPREINTE_REELLE, &verdict_reel);
});
