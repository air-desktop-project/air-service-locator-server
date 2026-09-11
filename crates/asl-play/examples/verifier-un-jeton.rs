//! Lit un jeton Play Integrity RÉEL et dit ce que notre vérification en fait.
//!
//! # À QUOI IL SERT
//!
//! `asl-play` sait déchiffrer et vérifier un jeton, mais il n'a jamais vu de
//! vrai jeton : sa forme (`A256KW`, `A256GCM`, ES256) vient de la documentation
//! de Google. Cet outil est le pont. On lui donne un jeton capturé sur un vrai
//! appareil, les deux clés de la Play Console, et il dit :
//!
//! - soit il l'OUVRE, et il imprime le verdict JSON — ce qu'on attend pour
//!   écrire la politique (quels champs, quelles valeurs, à confirmer sur du
//!   réel plutôt que sur la documentation) ;
//! - soit il le REFUSE, et il dit LAQUELLE de nos hypothèses sur la forme de
//!   Google est fausse.
//!
//! # USAGE
//!
//! ```text
//! cargo run --example verifier-un-jeton -- <dossier>
//! ```
//!
//! Le dossier contient :
//!
//! | Fichier                 | Ce qu'il porte                                      |
//! |-------------------------|-----------------------------------------------------|
//! | `jeton.txt`             | le jeton, tel quel (JWE compact, texte base64url)   |
//! | `cle-dechiffrement.bin` | la clé AES-256 de la Play Console, base64 DÉCODÉE     |
//! | `cle-verification.der`  | la clé de vérification, SPKI DER, base64 DÉCODÉE     |

use std::path::{Path, PathBuf};

use asl_play::{Clefs, Refus, ouvrir};

fn lire(dossier: &Path, nom: &str) -> Vec<u8> {
    std::fs::read(dossier.join(nom)).unwrap_or_else(|faute| {
        eprintln!("capture incomplète : {nom} illisible ({faute})");
        std::process::exit(2);
    })
}

fn main() {
    let Some(dossier) = std::env::args().nth(1).map(PathBuf::from) else {
        eprintln!("usage : verifier-un-jeton <dossier>");
        std::process::exit(2);
    };

    let jeton = lire(&dossier, "jeton.txt");
    let jeton = jeton.trim_ascii();
    let dechiffrement = lire(&dossier, "cle-dechiffrement.bin");
    let verification = lire(&dossier, "cle-verification.der");

    let Ok(kek) = <[u8; 32]>::try_from(&dechiffrement[..]) else {
        eprintln!(
            "la clé de déchiffrement fait {} octets, 32 attendus (base64 bien décodée ?)",
            dechiffrement.len()
        );
        std::process::exit(2);
    };

    println!("── capture ──");
    println!("  jeton             : {} octets", jeton.len());
    println!("  clé déchiffrement : {} octets", dechiffrement.len());
    println!(
        "  clé vérification  : {} octets (SPKI DER)",
        verification.len()
    );
    println!();

    let clefs = Clefs {
        dechiffrement: &kek,
        verification: &verification,
    };

    match ouvrir(jeton, &clefs) {
        Ok(verdict) => {
            println!("✔ OUVERT. Notre lecture de la forme de Google est la bonne.");
            println!();
            println!("Voici le VERDICT, tel qu'il est — c'est lui qui dira, sur du réel, quels");
            println!("champs lire et quelles valeurs accepter, pour écrire la politique :");
            println!();
            match core::str::from_utf8(&verdict) {
                Ok(texte) => println!("{texte}"),
                Err(_) => println!("{verdict:02x?}"),
            }
        }
        Err(refus) => {
            println!("✘ REFUSÉ : {refus}");
            println!();
            println!("{}", diagnostic(&refus));
        }
    }
}

/// Ce qu'un refus dit de NOS hypothèses sur la forme du jeton de Google.
fn diagnostic(refus: &Refus) -> &'static str {
    match refus {
        Refus::TropLong { .. } => {
            "Le jeton dépasse notre borne. Soit elle est trop basse pour un jeton\n\
             réel, soit ce n'est pas un jeton — vérifier le fichier."
        }
        Refus::Jwe(_) => {
            "Le jeton ne se découpe pas en un JWE à cinq segments. Ce n'est peut-être\n\
             pas un jeton « standard » chiffré, mais un jeton déjà déchiffré par\n\
             Google (mode géré par Google), qui serait alors un JWS nu."
        }
        Refus::EnveloppeInattendue => {
            "L'enveloppe n'est pas `A256KW` + `A256GCM`. Regarder l'en-tête du JWE :\n\
             Google emploie peut-être `dir`, ou un autre chiffrement. C'est la\n\
             découverte la plus probable, et elle se corrige sur les octets réels."
        }
        Refus::Deballage(_) => {
            "La clé de session ne se déballe pas. La clé de déchiffrement n'est pas\n\
             la bonne (mauvaise app, ou mauvais décodage base64), ou l'emballage\n\
             n'est pas RFC 3394."
        }
        Refus::Dechiffrement | Refus::IvInvalide | Refus::EtiquetteInvalide => {
            "La clé se déballe, mais le déchiffrement échoue. L'iv, l'étiquette ou\n\
             la donnée authentifiée (l'en-tête protégé) ne sont pas ce qu'on croit."
        }
        Refus::Jws(_) => {
            "Le contenu déchiffré n'est pas un JWS à trois segments. Le déchiffrement\n\
             a donc réussi mais rendu autre chose qu'un JWS — forme inattendue."
        }
        Refus::SignatureInattendue => {
            "Le JWS n'annonce pas ES256. Google signe peut-être autrement ; l'en-tête\n\
             du JWS déchiffré le dira."
        }
        Refus::CleIllisible => {
            "La clé de vérification n'est pas un SPKI de clé P-256 lisible. Vérifier\n\
             qu'elle est bien base64-décodée, et que c'est la clé de VÉRIFICATION."
        }
        Refus::SignatureFausse => {
            "Tout se déchiffre, mais la signature ne vérifie pas. La clé de\n\
             vérification ne correspond pas au jeton, ou notre calcul du message\n\
             signé diffère de celui de Google."
        }
    }
}
