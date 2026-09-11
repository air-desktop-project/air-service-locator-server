//! Lit une capture d'attestation RÉELLE et dit si notre vérification la passe.
//!
//! # À QUOI IL SERT
//!
//! `asl-apple` est écrit d'après la documentation d'Apple, et rien d'autre :
//! aucun iPhone n'a jamais parlé à ce dépôt. Cet outil est le pont. On lui donne
//! une capture faite sur un vrai appareil (voir `docs/attestation/capture-reelle.md`),
//! et il dit, pas à pas, ce que `asl_apple::verifier` en fait — et, si elle
//! échoue, LAQUELLE de nos hypothèses sur le format d'Apple est fausse.
//!
//! **Un échec n'est pas forcément une faute de capture.** Si la chaîne remonte
//! mais que l'identifiant de clé ne correspond pas, c'est que notre façon de
//! hacher la clé publique n'est pas celle d'Apple — et c'est exactement ce que
//! la capture existe pour révéler.
//!
//! # USAGE
//!
//! ```text
//! cargo run --example verifier-une-capture -- <dossier> [--racine <fichier.der>]
//! ```
//!
//! Le dossier contient, en octets BRUTS (pas de base64) :
//!
//! | Fichier             | Ce qu'il porte                                     |
//! |---------------------|----------------------------------------------------|
//! | `attestation.cbor`  | l'objet d'attestation, tel qu'App Attest l'a rendu |
//! | `defi.bin`          | le défi que l'app a haché en `clientDataHash`       |
//! | `app-id.txt`        | `<TeamID>.<BundleID>`, sans espace ni saut de ligne |
//! | `environnement.txt` | `production` ou `developpement`                     |
//!
//! `--racine` remplace la racine d'Apple par une autre (pour éprouver l'outil
//! lui-même sur une chaîne de banc) ; sans lui, c'est `asl_apple::RACINE_APPLE`.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use asl_apple::{Attendu, Environnement, RACINE_APPLE, Refus, verifier};

fn lire(dossier: &Path, nom: &str) -> Vec<u8> {
    let chemin = dossier.join(nom);
    std::fs::read(&chemin).unwrap_or_else(|faute| {
        eprintln!(
            "capture incomplète : {} illisible ({faute})",
            chemin.display()
        );
        std::process::exit(2);
    })
}

fn texte(dossier: &Path, nom: &str) -> String {
    String::from_utf8(lire(dossier, nom))
        .unwrap_or_else(|_| {
            eprintln!("{nom} n'est pas de l'UTF-8");
            std::process::exit(2);
        })
        .trim()
        .to_owned()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(dossier) = args.next().map(PathBuf::from) else {
        eprintln!("usage : verifier-une-capture <dossier> [--racine <fichier.der>]");
        std::process::exit(2);
    };
    let mut racine_fichier: Option<PathBuf> = None;
    while let Some(drapeau) = args.next() {
        match drapeau.as_str() {
            "--racine" => racine_fichier = args.next().map(PathBuf::from),
            autre => {
                eprintln!("drapeau inconnu : {autre}");
                std::process::exit(2);
            }
        }
    }

    let attestation = lire(&dossier, "attestation.cbor");
    let defi = lire(&dossier, "defi.bin");
    let identifiant_app = texte(&dossier, "app-id.txt");
    let environnement = match texte(&dossier, "environnement.txt").as_str() {
        "production" => Environnement::Production,
        "developpement" => Environnement::Developpement,
        autre => {
            eprintln!("environnement inconnu : « {autre} » (production|developpement)");
            std::process::exit(2);
        }
    };
    let racine = racine_fichier
        .as_ref()
        .map(|c| std::fs::read(c).expect("racine illisible"));
    let racine = racine.as_deref().unwrap_or(RACINE_APPLE);

    let maintenant = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("une horloge après 1970")
        .as_secs();

    println!("── capture ──");
    println!("  attestation      : {} octets", attestation.len());
    println!("  défi             : {} octets", defi.len());
    println!("  app-id           : {identifiant_app}");
    println!("  environnement    : {environnement:?}");
    println!(
        "  racine           : {}",
        if racine_fichier.is_some() {
            "fournie (hors Apple)"
        } else {
            "Apple (RACINE_APPLE)"
        }
    );
    println!();

    let attendu = Attendu {
        racine,
        defi: &defi,
        identifiant_app: &identifiant_app,
        environnement,
        maintenant,
    };

    match verifier(&attestation, &attendu) {
        Ok(certifie) => {
            println!("✔ VÉRIFIÉE. Notre lecture du format d'Apple est la bonne.");
            println!(
                "  clé certifiée    : {} octets (P-256 non compressé)",
                certifie.cle.len()
            );
            print!("  identifiant      : ");
            for octet in certifie.identifiant {
                print!("{octet:02x}");
            }
            println!();
            println!();
            println!("On peut désormais tenir `--attestation exigee` pour sûre sur cet");
            println!("environnement. Mieux : commettre cette capture comme VECTEUR, pour que");
            println!("`asl-apple` soit éprouvé contre une attestation réelle et non seulement");
            println!("contre ce que la documentation décrit.");
        }
        Err(refus) => {
            println!("✘ REFUSÉE : {refus}");
            println!();
            println!("{}", diagnostic(&refus));
        }
    }
}

/// Ce qu'un refus dit de NOS hypothèses, et ce qu'il faut regarder.
fn diagnostic(refus: &Refus) -> &'static str {
    match refus {
        Refus::Grammaire(_) => {
            "La GRAMMAIRE a refusé l'objet : notre lecteur CBOR ou la disposition de\n\
             `authData` ne correspond pas à ce qu'Apple envoie. C'est la découverte la\n\
             plus instructive — comparer octet par octet avec `asl-attest`."
        }
        Refus::Chaine(_) | Refus::FeuilleIllisible | Refus::RacineIllisible => {
            "La CHAÎNE ne remonte pas à la racine donnée. Vérifier que la capture vient\n\
             bien d'un appareil réel (et non du simulateur), et que la racine est celle\n\
             d'Apple. Si tout cela est juste, c'est notre construction de chaîne qui est\n\
             en cause."
        }
        Refus::CleInattendue | Refus::CertificatIllisible => {
            "La feuille ne se lit pas comme un certificat P-256 à la disposition de\n\
             RFC 5280 attendue. Notre marcheur DER (`x509.rs`) fait une hypothèse que\n\
             ce certificat-ci dément."
        }
        Refus::NonceAbsent => {
            "L'extension d'Apple (OID 1.2.840.113635.100.8.2) est absente, ou notre\n\
             marcheur ne la trouve pas là où elle est. Regarder la forme exacte de\n\
             l'extension dans la feuille."
        }
        Refus::NonceDifferent => {
            "Le nonce ne correspond pas. Soit le `defi.bin` n'est pas EXACTEMENT ce que\n\
             l'app a haché en `clientDataHash`, soit notre formule du nonce diffère de\n\
             celle d'Apple (on calcule SHA256(authData ‖ SHA256(defi)))."
        }
        Refus::IdentifiantDifferent => {
            "La chaîne et le nonce passent, mais l'identifiant de clé ne correspond pas :\n\
             Apple ne hache pas la clé publique comme nous (on hache le point P-256 non\n\
             compressé de 65 octets). C'est un réglage d'une ligne, une fois la bonne\n\
             forme connue."
        }
        Refus::App => {
            "Le `rpIdHash` ne correspond pas à SHA256(app-id). Vérifier `app-id.txt` :\n\
             c'est `<TeamID à 10 caractères>.<bundle id>`, sans rien d'autre."
        }
        Refus::Environnement => {
            "L'`aaguid` n'est pas celui de l'environnement déclaré. Une app lancée depuis\n\
             Xcode donne `developpement` ; TestFlight et l'App Store donnent `production`."
        }
        Refus::Compteur { .. } => {
            "Le compteur n'est pas à zéro : cette clé a déjà servi. Une attestation est\n\
             la PREMIÈRE signature d'une clé — en générer une neuve pour la capture."
        }
        Refus::PasDeCleAttestee => {
            "Le drapeau d'attestation n'est pas levé : l'objet n'est pas une attestation\n\
             d'App Attest. Vérifier qu'on capture bien la sortie de `attestKey`."
        }
        Refus::ChaineVide => "L'objet ne porte aucun certificat : ce n'est pas une attestation.",
    }
}
