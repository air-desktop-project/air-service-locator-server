//! Lit une chaîne d'attestation Android RÉELLE et dit ce que notre
//! vérification en fait.
//!
//! # À QUOI IL SERT
//!
//! C'est le pont entre un appareil et cette crate : on lui donne le dossier
//! d'une capture (`docs/attestation/capture-keystore.md`), et il imprime
//!
//! - la `KeyDescription` de la feuille, telle que notre lecteur la lit — ce
//!   qui, sur une capture neuve, dit si la forme est bien celle qu'on croit ;
//! - puis le [`Verdict`], ou le [`Refus`] et LAQUELLE de nos attentes il
//!   contredit.
//!
//! # USAGE
//!
//! ```text
//! cargo run --example verifier-une-chaine -- <dossier> [paquet] [empreinte-hex]
//! ```
//!
//! Le dossier contient :
//!
//! | Fichier                 | Ce qu'il porte                                         |
//! |-------------------------|--------------------------------------------------------|
//! | `cert0.der` … `certN.der` | la chaîne, feuille d'abord, DER — le dernier est la racine |
//! | `defi.bin`              | le défi d'attestation, tel que l'app l'a posé          |
//! | `capture.txt`           | le bloc Logcat, d'où l'on lit `PAQUET=` et `SIGNATURE=` |
//!
//! La racine épinglée est le DERNIER certificat du dossier — comme si
//! l'exploitant l'avait mise dans `--android-roots`. Le paquet et l'empreinte
//! viennent de `capture.txt`, ou des arguments s'ils sont donnés. L'instant
//! est celui de l'horloge.

use std::path::{Path, PathBuf};

use asl_keystore::description::{Description, ListeAutorisations};
use asl_keystore::{Attendu, Refus, Verdict, case, description, verifier, x509};
use sha2::{Digest, Sha256};

fn lire(chemin: &Path) -> Vec<u8> {
    std::fs::read(chemin).unwrap_or_else(|faute| {
        eprintln!(
            "capture incomplète : {} illisible ({faute})",
            chemin.display()
        );
        std::process::exit(2);
    })
}

fn hexadecimal(octets: &[u8]) -> String {
    octets.iter().map(|octet| format!("{octet:02x}")).collect()
}

fn depuis_hexadecimal(texte: &str) -> Option<[u8; 32]> {
    let propre: String = texte.trim().chars().filter(|c| *c != ':').collect();
    if propre.len() != 64 {
        return None;
    }
    let mut sortie = [0_u8; 32];
    for (place, paire) in sortie.iter_mut().zip(propre.as_bytes().chunks(2)) {
        *place = u8::from_str_radix(std::str::from_utf8(paire).ok()?, 16).ok()?;
    }
    Some(sortie)
}

/// `PAQUET=` et `SIGNATURE=` de `capture.txt`, s'il est là.
fn depuis_la_capture(dossier: &Path) -> (Option<String>, Option<String>) {
    let Ok(texte) = std::fs::read_to_string(dossier.join("capture.txt")) else {
        return (None, None);
    };
    let valeur = |cle: &str| {
        texte
            .lines()
            .find_map(|ligne| ligne.strip_prefix(cle))
            .map(|v| v.trim().to_owned())
    };
    (valeur("PAQUET="), valeur("SIGNATURE="))
}

fn main() {
    let mut arguments = std::env::args().skip(1);
    let Some(dossier) = arguments.next().map(PathBuf::from) else {
        eprintln!("usage : verifier-une-chaine <dossier> [paquet] [empreinte-hex]");
        std::process::exit(2);
    };
    let (paquet_capture, signature_capture) = depuis_la_capture(&dossier);
    let Some(paquet) = arguments.next().or(paquet_capture) else {
        eprintln!("ni PAQUET= dans capture.txt, ni paquet en argument");
        std::process::exit(2);
    };
    let Some(empreinte) = arguments
        .next()
        .or(signature_capture)
        .and_then(|texte| depuis_hexadecimal(&texte))
    else {
        eprintln!("ni SIGNATURE= dans capture.txt, ni empreinte SHA-256 en argument");
        std::process::exit(2);
    };

    let mut certificats = Vec::new();
    for rang in 0.. {
        let chemin = dossier.join(format!("cert{rang}.der"));
        if !chemin.is_file() {
            break;
        }
        certificats.push(lire(&chemin));
    }
    let Some(racine) = certificats.last() else {
        eprintln!("aucun cert0.der dans {}", dossier.display());
        std::process::exit(2);
    };
    let defi = lire(&dossier.join("defi.bin"));

    println!("── capture ──");
    for (rang, der) in certificats.iter().enumerate() {
        println!(
            "  cert{rang}.der   : {:>5} octets{}",
            der.len(),
            match rang {
                0 => " — la feuille",
                r if r.saturating_add(1) == certificats.len() => " — la racine, épinglée",
                _ => "",
            }
        );
    }
    println!(
        "  racine SHA-256 : {}",
        hexadecimal(&Sha256::digest(racine))
    );
    println!(
        "  défi           : {} octets, {}",
        defi.len(),
        hexadecimal(&defi)
    );
    println!("  paquet         : {paquet}");
    println!("  empreinte      : {}", hexadecimal(&empreinte));
    println!();

    // La KeyDescription d'abord, sans rien vérifier : sur une capture neuve,
    // c'est ce qu'on veut lire même si la chaîne ne remonte pas.
    println!("── KeyDescription de la feuille, telle que lue ──");
    match x509::lire(&certificats[0]) {
        Err(refus) => println!("  feuille illisible : {refus}"),
        Ok(feuille) => {
            println!(
                "  clé de la feuille (compressée) : {}",
                hexadecimal(&x509::compresser(
                    feuille.cle.try_into().expect("65 octets")
                ))
            );
            match feuille.description {
                None => println!("  extension 1.3.6.1.4.1.11129.2.1.17 ABSENTE"),
                Some(der) => match description::lire(der) {
                    Err(faute) => println!("  KeyDescription illisible : {faute}"),
                    Ok(lue) => imprimer(&lue),
                },
            }
        }
    }
    println!();

    let feuille_d_abord: Vec<&[u8]> = certificats.iter().map(Vec::as_slice).collect();
    let Some(case) = case::assembler(&feuille_d_abord) else {
        eprintln!(
            "la chaîne ne tient pas dans une case de {} octets",
            case::CASE_MAX
        );
        std::process::exit(2);
    };
    let feuille = x509::lire(&certificats[0]).ok();
    let cle = feuille.map_or([0_u8; 33], |f| {
        x509::compresser(f.cle.try_into().expect("65 octets"))
    });
    let maintenant = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |ecoule| ecoule.as_secs());
    let racines = [racine.as_slice()];
    let attendu = Attendu {
        racines: &racines,
        defi: &defi,
        cle: &cle,
        paquet: &paquet,
        empreinte: &empreinte,
        maintenant,
    };

    println!(
        "── verdict ({} octets de case, racine comprise) ──",
        case.len()
    );
    match verifier(&case, &attendu) {
        Ok(verdict) => {
            println!("✔ VERDICT : la chaîne prouve ce qu'on lui demande.");
            imprimer_le_verdict(&verdict);
        }
        Err(refus) => {
            println!("✘ REFUSÉ : {refus}");
            println!();
            println!("{}", diagnostic(&refus));
        }
    }
}

fn imprimer(lue: &Description<'_>) {
    println!("  attestationVersion        : {}", lue.version);
    println!("  attestationSecurityLevel  : {}", lue.niveau_attestation);
    println!("  keymasterVersion          : {}", lue.version_keymaster);
    println!("  keymasterSecurityLevel    : {}", lue.niveau_keymaster);
    println!("  attestationChallenge      : {}", hexadecimal(lue.defi));
    println!(
        "  uniqueId                  : {}",
        if lue.identifiant_unique.is_empty() {
            "(vide)".to_owned()
        } else {
            hexadecimal(lue.identifiant_unique)
        }
    );
    println!("  softwareEnforced :");
    imprimer_la_liste(&lue.logiciel);
    println!("  teeEnforced :");
    imprimer_la_liste(&lue.materiel);
}

fn imprimer_la_liste(liste: &ListeAutorisations<'_>) {
    let entiers = |valeurs: &Option<Vec<u64>>| valeurs.as_ref().map(|v| format!("{v:?}"));
    let champs: [(&str, Option<String>); 13] = [
        ("purpose [1]", entiers(&liste.finalites)),
        ("algorithm [2]", liste.algorithme.map(|v| v.to_string())),
        ("keySize [3]", liste.taille_de_cle.map(|v| v.to_string())),
        ("digest [5]", entiers(&liste.condensats)),
        ("ecCurve [10]", liste.courbe.map(|v| v.to_string())),
        (
            "noAuthRequired [503]",
            liste.sans_authentification.then(|| "présent".to_owned()),
        ),
        ("creationDateTime [701]", liste.creation.map(|v| v.to_string())),
        ("origin [702]", liste.origine.map(|v| v.to_string())),
        (
            "rootOfTrust [704]",
            liste.racine_de_confiance.map(|r| {
                format!(
                    "deviceLocked={}, verifiedBootState={}, verifiedBootKey={}, verifiedBootHash={}",
                    r.verrouille,
                    r.demarrage,
                    hexadecimal(r.cle_de_demarrage),
                    hexadecimal(r.empreinte_de_demarrage)
                )
            }),
        ),
        ("osVersion [705]", liste.version_os.map(|v| v.to_string())),
        ("osPatchLevel [706]", liste.correctif_os.map(|v| v.to_string())),
        (
            "vendorPatchLevel [718]",
            liste.correctif_fabricant.map(|v| v.to_string()),
        ),
        (
            "bootPatchLevel [719]",
            liste.correctif_demarrage.map(|v| v.to_string()),
        ),
    ];
    for (nom, valeur) in champs {
        if let Some(valeur) = valeur {
            println!("    {nom:<28} {valeur}");
        }
    }
    if let Some(app) = &liste.application {
        for paquet in &app.paquets {
            println!(
                "    {:<28} {} (versionCode {})",
                "attestationApplicationId [709]",
                String::from_utf8_lossy(paquet.nom),
                paquet.version
            );
        }
        for empreinte in &app.empreintes {
            println!(
                "    {:<28} {}",
                "  signature SHA-256",
                hexadecimal(empreinte)
            );
        }
    }
    if liste.sautees > 0 {
        println!("    ({} balise(s) inconnue(s), sautée(s))", liste.sautees);
    }
}

fn imprimer_le_verdict(verdict: &Verdict) {
    println!(
        "  clé certifiée (compressée) : {}",
        hexadecimal(&x509::compresser(&verdict.cle))
    );
    println!(
        "  attestation produite dans   : {}",
        verdict.niveau_attestation
    );
    println!(
        "  clé qui vit dans            : {}",
        verdict.niveau_keymaster
    );
    println!(
        "  schéma / KeyMint            : {} / {}",
        verdict.version, verdict.version_keymaster
    );
    let ou = |v: Option<u64>| v.map_or("absent".to_owned(), |v| v.to_string());
    println!("  osVersion                   : {}", ou(verdict.version_os));
    println!(
        "  osPatchLevel                : {} (rendu, pas jugé)",
        ou(verdict.correctif_os)
    );
    println!(
        "  vendorPatchLevel            : {}",
        ou(verdict.correctif_fabricant)
    );
    println!(
        "  bootPatchLevel              : {}",
        ou(verdict.correctif_demarrage)
    );
    println!(
        "  versionCode de notre app    : {}",
        verdict.version_du_paquet
    );
}

/// Ce qu'un refus dit de NOS attentes, ou de la capture.
fn diagnostic(refus: &Refus) -> &'static str {
    match refus {
        Refus::Case(_) | Refus::SansRacine => {
            "La case ne se forme pas : vérifier les fichiers cert*.der du dossier."
        }
        Refus::RacineIllisible | Refus::FeuilleIllisible | Refus::CertificatIllisible => {
            "Un certificat n'est pas lisible. Les fichiers sont-ils bien en DER, et\n\
             non en PEM ou en base64 ?"
        }
        Refus::Chaine(_) => {
            "La chaîne ne remonte pas à la racine (le dernier certificat). Il manque\n\
             un intermédiaire, ou la chaîne est expirée à l'horloge d'aujourd'hui, ou\n\
             un vérificateur de signature manque — regarder les algorithmes avec\n\
             `openssl x509 -text`."
        }
        Refus::CleInattendue => {
            "La feuille ne porte pas une clé P-256 : l'app a généré une autre courbe."
        }
        Refus::DescriptionAbsente => {
            "La feuille ne porte pas l'extension d'attestation : la clé a été générée\n\
             sans setAttestationChallenge, ou ce n'est pas la feuille."
        }
        Refus::DescriptionIllisible(_) => {
            "L'extension est là mais notre lecteur ne la lit pas : c'est la découverte\n\
             qui compte — une version de schéma inattendue ; comparer avec\n\
             `openssl asn1parse -strparse`."
        }
        Refus::CleDifferente => {
            "La clé de la feuille n'est pas celle attendue — impossible ici, la clé\n\
             attendue est celle de la feuille elle-même."
        }
        Refus::DefiDifferent => {
            "Le défi de la feuille n'est pas celui de defi.bin : mauvaise capture, ou\n\
             mauvais décodage base64."
        }
        Refus::AttestationLogicielle(_) | Refus::CleLogicielle(_) => {
            "La clé ne vit pas dans du matériel : émulateur, ou Keystore logiciel."
        }
        Refus::RacineDeConfianceAbsente
        | Refus::DemarrageNonVerifie(_)
        | Refus::AppareilDeverrouille => {
            "L'appareil n'a pas démarré vérifié et verrouillé : bootloader ouvert,\n\
             système alternatif, ou attestation sans rootOfTrust côté matériel."
        }
        Refus::OrigineAbsente | Refus::OrigineInattendue(_) => {
            "La clé n'a pas été générée dans le matériel : importée, ou dérivée."
        }
        Refus::ApplicationAbsente | Refus::AutrePaquet | Refus::AutreSignataire => {
            "L'app qui tient la clé n'est pas la nôtre sous notre signature : vérifier\n\
             PAQUET= et SIGNATURE= (la build de release a une AUTRE empreinte que la\n\
             build de débogage)."
        }
    }
}
