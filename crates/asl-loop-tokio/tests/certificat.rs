//! **La cérémonie d'autorité produit-elle un certificat que NOTRE pile accepte ?**
//!
//! # POURQUOI CET ESSAI EXISTE
//!
//! `scripts/ca.sh` finit par `openssl verify`, et cela ne prouve pas grand-chose :
//! **openssl s'y donne raison à lui-même.** Ce qui compte est qu'une chaîne et
//! une clé frappées par cette cérémonie soient chargeables par la pile qui va
//! réellement servir — `rustls` monté sur `rustls-rustcrypto`, à travers
//! `ams_tls::quic_server_config`.
//!
//! Deux choses peuvent diverger sans que personne ne le voie, et les deux se
//! découvriraient à la poignée de main, c'est-à-dire au pire endroit :
//!
//!   1. **L'algorithme.** Notre fournisseur charge une clé Ed25519 **en
//!      PKCS#8** (`sign/eddsa.rs`). Un jour où la cérémonie produirait autre
//!      chose — SEC1, PKCS#1, une autre courbe —, elle produirait un certificat
//!      valide et inutilisable.
//!   2. **L'accord de la clé et du certificat.** `quic_server_config` le
//!      vérifie ; l'essai négatif ci-dessous s'assure que ce contrôle est bien
//!      vivant, en croisant la clé d'un serveur avec le certificat d'un autre.
//!
//! # IL FRAPPE SA PROPRE AUTORITÉ, ET NE LIT JAMAIS LA VRAIE
//!
//! `ASL_CA` déplace le répertoire de la cérémonie vers un temporaire. La racine
//! réelle vit dans `local/`, qui est ignoré par git et n'existe pas sur un
//! clone neuf — un essai qui la lirait ne tournerait jamais en CI, et un essai
//! qui lit une clé privée est un essai qu'on finit par ne plus lancer.
//!
//! # IL EXIGE `openssl`, ET IL ÉCHOUE PLUTÔT QUE DE SE TAIRE
//!
//! Un essai qui se saute lui-même quand un outil manque rend un vert qui ne
//! veut rien dire. `openssl` est présent sur les runners GitHub et sur toute
//! machine de développement ; s'il manque, le message le dit.

use std::path::{Path, PathBuf};
use std::process::Command;

/// La racine du dépôt, depuis ce paquet.
fn depot() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("le paquet vit sous `crates/`")
        .to_path_buf()
}

/// Lance la cérémonie, et rend ce qu'elle a écrit.
fn ceremonie(autorite: &Path, arguments: &[&str]) {
    let sortie = Command::new(depot().join("scripts/ca.sh"))
        .args(arguments)
        .env("ASL_CA", autorite)
        .current_dir(depot())
        .output()
        .expect("`scripts/ca.sh` doit être lançable — et `openssl` présent");

    assert!(
        sortie.status.success(),
        "la cérémonie a échoué :\n{}\n{}",
        String::from_utf8_lossy(&sortie.stdout),
        String::from_utf8_lossy(&sortie.stderr),
    );
}

/// Un répertoire temporaire à nous, effacé par l'appelant.
fn temporaire(quoi: &str) -> PathBuf {
    let chemin = std::env::temp_dir().join(format!("asl-ca-{}-{quoi}", std::process::id()));
    let _ = std::fs::remove_dir_all(&chemin);
    chemin
}

#[test]
fn un_certificat_de_la_ceremonie_se_charge_dans_notre_pile() {
    let autorite = temporaire("accepte");
    ceremonie(&autorite, &["racine"]);
    ceremonie(
        &autorite,
        &["serveur", "essai", "localhost", "::1", "127.0.0.1"],
    );

    let chaine = std::fs::read(autorite.join("essai/chaine.pem")).expect("la chaîne");
    let cle = std::fs::read(autorite.join("essai/serveur.key")).expect("la clé");

    let configuration = ams_tls::quic_server_config(&chaine, &cle);
    assert!(
        configuration.is_ok(),
        "notre pile refuse ce que la cérémonie produit : {:?}",
        configuration.err()
    );

    let _ = std::fs::remove_dir_all(&autorite);
}

#[test]
fn une_cle_qui_n_est_pas_celle_du_certificat_est_refusée() {
    // CE N'EST PAS UN ESSAI DE `ams-tls`, C'EST UN ESSAI DE NOTRE CONFIANCE EN
    // LUI. Si ce contrôle disparaissait un jour d'une mise à jour d'amont, le
    // premier essai passerait toujours — et un serveur monté sur une clé
    // dépareillée démarrerait pour échouer à la première connexion.
    let autorite = temporaire("depareillee");
    ceremonie(&autorite, &["racine"]);
    ceremonie(&autorite, &["serveur", "un", "localhost"]);
    ceremonie(&autorite, &["serveur", "deux", "localhost"]);

    let chaine = std::fs::read(autorite.join("un/chaine.pem")).expect("la chaîne du premier");
    let cle = std::fs::read(autorite.join("deux/serveur.key")).expect("la clé du second");

    assert!(
        ams_tls::quic_server_config(&chaine, &cle).is_err(),
        "une clé dépareillée a été acceptée"
    );

    let _ = std::fs::remove_dir_all(&autorite);
}
