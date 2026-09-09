//! **Le binaire livré, lancé pour de vrai, et interrogé par un vrai client.**
//!
//! # CE QUE CET ESSAI PROUVE, ET QU'AUCUN AUTRE NE PROUVE
//!
//! Les essais de `asl-loop-tokio` montent l'écoute EN BIBLIOTHÈQUE : ils
//! appellent `servir_quic` depuis le harnais. Rien n'y dit que le BINAIRE lit
//! ses arguments, ouvre son entrepôt, charge son certificat et se lie à sa
//! socket dans un ordre qui marche.
//!
//! Ici, c'est `target/debug/asl-server` qui tourne, dans son propre processus,
//! avec sa vraie ligne de commande.
//!
//! # LE PORT EST ZÉRO, ET LE SERVEUR DIT LEQUEL IL A EU
//!
//! Un port fixe ferait une course entre essais et un échec aléatoire en CI. Le
//! noyau choisit donc, et l'essai lit l'adresse sur la sortie d'erreur du
//! serveur — ce qui éprouve au passage que ce message est exact.

use std::io::{BufRead as _, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use asl_id::{Genre, Identifiant};
use asl_registre::{AliasRange, Compte, Provenance};
use asl_store::Entrepot;

/// La racine du dépôt, depuis ce paquet.
fn depot() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("le paquet vit sous `crates/`")
        .to_path_buf()
}

/// Frappe une autorité et un certificat de banc dans un temporaire.
fn materiel(quoi: &str) -> (PathBuf, Vec<u8>) {
    let autorite = std::env::temp_dir().join(format!("asl-bin-{}-{quoi}", std::process::id()));
    let _ = std::fs::remove_dir_all(&autorite);
    for arguments in [
        vec!["racine"],
        vec!["serveur", "banc", "localhost", "127.0.0.1", "::1"],
    ] {
        let sortie = Command::new(depot().join("scripts/ca.sh"))
            .args(&arguments)
            .env("ASL_CA", &autorite)
            .current_dir(depot())
            .output()
            .expect("`scripts/ca.sh` doit être lançable — et `openssl` présent");
        assert!(
            sortie.status.success(),
            "la cérémonie a échoué :\n{}",
            String::from_utf8_lossy(&sortie.stderr)
        );
    }
    let racine = std::fs::read(autorite.join("racine.crt")).expect("la racine");
    (autorite, racine)
}

/// Lance le binaire, et rend l'adresse qu'il annonce.
///
/// **ON LIT SON ANNONCE PLUTÔT QUE D'ATTENDRE UN DÉLAI** : une attente fixe est
/// soit trop courte sur une machine chargée, soit du temps perdu à chaque
/// exécution.
fn lancer(autorite: &Path, base: &Path) -> (Child, SocketAddr) {
    let mut enfant = Command::new(env!("CARGO_BIN_EXE_asl-server"))
        .arg("--entrepot")
        .arg(base)
        .arg("--certificat")
        .arg(autorite.join("banc/chaine.pem"))
        .arg("--cle")
        .arg(autorite.join("banc/serveur.key"))
        .args(["--port", "0"])
        .stderr(Stdio::piped())
        .spawn()
        .expect("le binaire se lance");

    let erreurs = enfant.stderr.take().expect("sa sortie d'erreur");
    let mut lignes = BufReader::new(erreurs).lines();
    let annonce = lignes
        .find_map(|ligne| {
            let ligne = ligne.ok()?;
            let apres = ligne.split("écoute sur ").nth(1)?;
            apres.split(' ').next()?.parse::<SocketAddr>().ok()
        })
        .expect("le serveur annonce son adresse avant de servir");

    (enfant, annonce)
}

#[tokio::test]
async fn le_binaire_sert_un_compte_de_son_entrepot() {
    let (autorite, racine) = materiel("sert");
    let base = std::env::temp_dir().join(format!("asl-bin-{}-sert.redb", std::process::id()));
    let _ = std::fs::remove_file(&base);

    // **L'ENTREPÔT EST GARNI AVANT LE LANCEMENT**, et il le faut : le serveur en
    // prend le verrou exclusif, donc on n'y écrit plus une fois qu'il tourne.
    let qui = Identifiant::depuis_entropie(Genre::Utilisateur, [0x11; 16]);
    {
        let entrepot = Entrepot::ouvrir(&base).expect("un entrepôt");
        entrepot
            .poser_compte(
                qui,
                &Compte {
                    provenance: Provenance::Ici,
                    alias: Some(AliasRange::nouveau("nitrogen").expect("il tient")),
                },
            )
            .expect("le compte est écrit");
    }

    let (mut serveur, ou) = lancer(&autorite, &base);

    // Le harnais client se lie en IPv4 : on parle donc au serveur par sa face
    // IPv4, ce que la double pile rend possible sur la MÊME socket.
    let vers = SocketAddr::from(([127, 0, 0, 1], ou.port()));
    let mut client =
        ams_quic_client::Client::new(ams_quic_client::config_client(&racine), vers).await;
    for _ in 0..64_u32 {
        client.parler().await;
        if !client.ecouter().await {
            break;
        }
    }

    ams_quic_client::envoyer_une_requete(&mut client, 0, 17, b"/v1/alias/nitrogen", None, b"")
        .await;
    let corps = ams_quic_client::attendre_la_reponse(&mut client, 0).await;
    let rendu = String::from_utf8_lossy(&corps);

    assert!(
        rendu.contains(qui.texte().as_str()),
        "le binaire n'a pas rendu l'identifiant : {rendu}"
    );
    assert!(
        rendu.contains("nitrogen"),
        "le binaire n'a pas rendu l'alias : {rendu}"
    );

    let _ = serveur.kill();
    let _ = serveur.wait();
    let _ = std::fs::remove_dir_all(&autorite);
    let _ = std::fs::remove_file(&base);
}

#[test]
fn sans_arguments_il_refuse_et_montre_comment_faire() {
    let sortie = Command::new(env!("CARGO_BIN_EXE_asl-server"))
        .output()
        .expect("le binaire se lance");
    assert!(!sortie.status.success(), "il aurait dû refuser");

    let dit = String::from_utf8_lossy(&sortie.stderr);
    assert!(
        dit.contains("--entrepot"),
        "il doit nommer ce qui manque : {dit}"
    );
    assert!(
        dit.contains("--certificat"),
        "et montrer l'usage complet : {dit}"
    );
}

#[test]
fn l_aide_sort_sans_erreur() {
    let sortie = Command::new(env!("CARGO_BIN_EXE_asl-server"))
        .arg("--aide")
        .output()
        .expect("le binaire se lance");
    assert!(sortie.status.success(), "`--aide` n'est pas une faute");
    let dit = String::from_utf8_lossy(&sortie.stdout);
    assert!(
        dit.contains("6630"),
        "l'aide annonce le port par défaut : {dit}"
    );
    assert!(
        dit.contains("root"),
        "et le refus de root, qui surprendrait sinon : {dit}"
    );
}
