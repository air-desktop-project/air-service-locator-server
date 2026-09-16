//! La chaîne RÉELLE du Fairphone 5 (2026-09-16), et c'est l'essai qui compte.
//!
//! Tout le reste de cette crate éprouve qu'elle fait ce qu'elle dit sur des
//! chaînes FABRIQUÉES. Ici, la chaîne vient d'un vrai TEE, sous la vraie racine
//! de Google — `docs/attestation/captures/keystore-fp5-2026-09-16/` —, et
//! chaque valeur que le README de la capture a lue avec `openssl` doit sortir
//! telle quelle du lecteur.
//!
//! **La chaîne expirera** : les intermédiaires valent jusqu'en octobre 2033,
//! la racine jusqu'en mars 2042. L'instant est donc FIXÉ, au jour de la
//! capture, et cet essai continuera de passer après.

use std::fs;
use std::path::PathBuf;

use asl_keystore::{Attendu, Demarrage, Niveau, Origine, Refus, case, description, verifier, x509};
use sha2::{Digest, Sha256};

/// Le 2026-09-16 à midi UTC.
const AU_JOUR_DE_LA_CAPTURE: u64 = 1_789_560_000;

/// Ce que `capture.txt` dit.
const PAQUET: &str = "org.airdesktop.servicelocator";
const SIGNATURE: &str = "5ea316f1b50f2ce54b8225aba85ff5cc8238a710b8fae44b4f3a195aadeb5f68";

/// Empreinte SHA-256 de `cert3.der`, la racine de Google — relevée avec
/// `openssl sha256` et gravée ici pour qu'un octet changé ne passe pas.
const EMPREINTE_RACINE: &str = "cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc";

fn piece(nom: &str) -> Vec<u8> {
    let mut chemin = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    chemin.push("../../docs/attestation/captures/keystore-fp5-2026-09-16");
    chemin.push(nom);
    fs::read(&chemin).unwrap_or_else(|faute| panic!("pièce {chemin:?} illisible : {faute}"))
}

fn hexadecimal(octets: &[u8]) -> String {
    octets.iter().map(|octet| format!("{octet:02x}")).collect()
}

fn depuis_hexadecimal(texte: &str) -> [u8; 32] {
    let mut sortie = [0_u8; 32];
    for (place, paire) in sortie.iter_mut().zip(texte.as_bytes().chunks(2)) {
        *place = u8::from_str_radix(std::str::from_utf8(paire).expect("ascii"), 16)
            .expect("hexadécimal");
    }
    sortie
}

/// La capture, chargée.
struct Capture {
    certificats: [Vec<u8>; 4],
    defi: Vec<u8>,
    empreinte: [u8; 32],
}

impl Capture {
    fn charger() -> Self {
        Self {
            certificats: [
                piece("cert0.der"),
                piece("cert1.der"),
                piece("cert2.der"),
                piece("cert3.der"),
            ],
            defi: piece("defi.bin"),
            empreinte: depuis_hexadecimal(SIGNATURE),
        }
    }

    fn racine(&self) -> &[u8] {
        &self.certificats[3]
    }

    fn feuille(&self) -> &[u8] {
        &self.certificats[0]
    }

    /// La clé de la feuille, compressée — ce que le fil porterait.
    fn cle(&self) -> [u8; 33] {
        let feuille = x509::lire(self.feuille()).expect("la feuille se lit");
        x509::compresser(feuille.cle.try_into().expect("65 octets"))
    }

    fn attendu<'a>(&'a self, racines: &'a [&'a [u8]], cle: &'a [u8; 33]) -> Attendu<'a> {
        Attendu {
            racines,
            defi: &self.defi,
            cle,
            paquet: PAQUET,
            empreinte: &self.empreinte,
            maintenant: AU_JOUR_DE_LA_CAPTURE,
        }
    }
}

#[test]
fn la_racine_est_bien_celle_de_google() {
    let capture = Capture::charger();
    assert_eq!(
        hexadecimal(&Sha256::digest(capture.racine())),
        EMPREINTE_RACINE
    );
    // Et les tailles du README.
    let tailles: Vec<usize> = capture.certificats.iter().map(Vec::len).collect();
    assert_eq!(tailles, [686, 503, 920, 1312]);
    assert_eq!(tailles.iter().sum::<usize>(), 3421);
    assert_eq!(capture.defi.len(), 32);
}

#[test]
fn la_key_description_de_la_feuille_est_celle_que_le_readme_a_lue() {
    let capture = Capture::charger();
    let feuille = x509::lire(capture.feuille()).expect("la feuille se lit");
    assert_eq!(feuille.cle.len(), 65);
    let lue = description::lire(feuille.description.expect("l'extension y est"))
        .expect("la KeyDescription se lit");

    assert_eq!(lue.version, 3);
    assert_eq!(lue.niveau_attestation, Niveau::EnvironnementDeConfiance);
    assert_eq!(lue.version_keymaster, 41);
    assert_eq!(lue.niveau_keymaster, Niveau::EnvironnementDeConfiance);
    assert_eq!(lue.defi, &capture.defi[..], "le défi, octet pour octet");
    assert_eq!(lue.identifiant_unique, &[], "uniqueId vide");

    // softwareEnforced : creationDateTime [701] et attestationApplicationId [709].
    let logiciel = &lue.logiciel;
    assert_eq!(logiciel.creation, Some(0x01A0_AB0A_0620));
    let application = logiciel.application.as_ref().expect("[709]");
    assert_eq!(application.paquets.len(), 1);
    assert_eq!(application.paquets[0].nom, PAQUET.as_bytes());
    assert_eq!(application.paquets[0].version, 6);
    assert_eq!(application.empreintes.len(), 1);
    assert_eq!(hexadecimal(application.empreintes[0]), SIGNATURE);
    assert_eq!(logiciel.sautees, 0);
    assert_eq!(logiciel.racine_de_confiance, None);

    // teeEnforced.
    let materiel = &lue.materiel;
    assert_eq!(
        materiel.finalites.as_deref(),
        Some(&[2][..]),
        "purpose SIGN"
    );
    assert_eq!(materiel.algorithme, Some(3), "EC");
    assert_eq!(materiel.taille_de_cle, Some(256));
    assert_eq!(materiel.condensats.as_deref(), Some(&[4][..]), "SHA-256");
    assert_eq!(materiel.courbe, Some(1), "P-256");
    assert!(materiel.sans_authentification, "[503]");
    assert_eq!(materiel.origine, Some(Origine::Generee));
    let racine = materiel.racine_de_confiance.expect("[704]");
    assert!(racine.verrouille);
    assert_eq!(racine.demarrage, Demarrage::Verifie);
    assert_eq!(
        hexadecimal(racine.cle_de_demarrage),
        "c31c8269e026de3f999d8f77c4fd46a3498b7f25fedd22755bae82063d5183f2"
    );
    assert_eq!(
        hexadecimal(racine.empreinte_de_demarrage),
        "9b7ff9e624e943df3704d5e0bb89a2103b8b69d587928933b33ee35cf2c52f0e"
    );
    assert_eq!(materiel.version_os, Some(150_000));
    assert_eq!(materiel.correctif_os, Some(202_608));
    assert_eq!(materiel.correctif_fabricant, Some(20_260_805));
    assert_eq!(materiel.correctif_demarrage, Some(20_260_805));
    assert_eq!(materiel.creation, None);
    assert_eq!(materiel.application, None);
    assert_eq!(materiel.sautees, 0);
}

#[test]
fn la_chaine_reelle_remonte_a_la_racine_de_google_et_rend_un_verdict() {
    let capture = Capture::charger();
    let cle = capture.cle();
    let racines = [capture.racine()];
    let attendu = capture.attendu(&racines, &cle);

    // Racine comprise, telle que `getCertificateChain` la rend…
    let entiere: Vec<&[u8]> = capture.certificats.iter().map(Vec::as_slice).collect();
    let case = case::assembler(&entiere).expect("la case tient");
    assert_eq!(case.len(), 3421 + 4 * 2);
    let verdict = verifier(&case, &attendu).unwrap_or_else(|refus| panic!("{refus}"));

    assert_eq!(x509::compresser(&verdict.cle), cle);
    assert_eq!(verdict.niveau_attestation, Niveau::EnvironnementDeConfiance);
    assert_eq!(verdict.niveau_keymaster, Niveau::EnvironnementDeConfiance);
    assert_eq!(verdict.version, 3);
    assert_eq!(verdict.version_keymaster, 41);
    assert_eq!(verdict.version_os, Some(150_000));
    assert_eq!(verdict.correctif_os, Some(202_608));
    assert_eq!(verdict.correctif_fabricant, Some(20_260_805));
    assert_eq!(verdict.correctif_demarrage, Some(20_260_805));
    assert_eq!(verdict.version_du_paquet, 6);

    // … et racine omise, comme le protocole le permet.
    let sans_racine = case::assembler(&entiere[..3]).expect("la case tient");
    assert_eq!(
        verifier(&sans_racine, &attendu).expect("la racine est chez l'annuaire"),
        verdict
    );
}

#[test]
fn la_chaine_reelle_est_refusee_sous_une_autre_racine_ou_avec_une_autre_attente() {
    let capture = Capture::charger();
    let cle = capture.cle();
    let entiere: Vec<&[u8]> = capture.certificats.iter().map(Vec::as_slice).collect();
    let case = case::assembler(&entiere).expect("la case tient");

    // Sous l'intermédiaire pris pour racine, la chaîne remonte aussi : c'est
    // le témoin que la racine de Google n'est pas seule à savoir ancrer.
    let racines = [capture.certificats[2].as_slice()];
    verifier(&case, &capture.attendu(&racines, &cle)).expect("ancrée à l'intermédiaire");

    // Sous la feuille prise pour racine : rien ne remonte à elle.
    let racines = [capture.feuille()];
    assert!(matches!(
        verifier(&case, &capture.attendu(&racines, &cle)),
        Err(Refus::Chaine(_))
    ));

    let racines = [capture.racine()];
    // Un autre défi.
    let mut autre = capture.attendu(&racines, &cle);
    autre.defi = b"un autre";
    assert_eq!(verifier(&case, &autre), Err(Refus::DefiDifferent));
    // Une autre clé.
    let mut autre_cle = cle;
    autre_cle[1] ^= 0x01;
    assert_eq!(
        verifier(&case, &capture.attendu(&racines, &autre_cle)),
        Err(Refus::CleDifferente)
    );
    // Un autre paquet, une autre signature.
    let mut autre = capture.attendu(&racines, &cle);
    autre.paquet = "org.airdesktop.autre";
    assert_eq!(verifier(&case, &autre), Err(Refus::AutrePaquet));
    let empreinte = [0x5A; 32];
    let mut autre = capture.attendu(&racines, &cle);
    autre.empreinte = &empreinte;
    assert_eq!(verifier(&case, &autre), Err(Refus::AutreSignataire));
    // Après l'expiration des intermédiaires (2034), la chaîne ne remonte plus.
    let mut plus_tard = capture.attendu(&racines, &cle);
    plus_tard.maintenant = 2_050_000_000;
    assert!(matches!(
        verifier(&case, &plus_tard),
        Err(Refus::Chaine(webpki::Error::CertExpired { .. }))
    ));
}
