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

use ams_proto_h3::{FrameHeader, FrameKind, qpack};
use asl_cle::{ClePublique, CleSecrete, identifiant_de_racine};
use asl_id::{Genre, Identifiant};
use asl_registre::{AliasRange, Cadre, Cause, Operation, Provenance};
use asl_store::{Entrepot, Rattrapage};

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
    lancer_avec(autorite, base, &[])
}

/// Éteint ce serveur PROPREMENT, et attend qu'il soit sorti.
///
/// # POURQUOI PAS `kill()`
///
/// `Child::kill` envoie `SIGKILL` : le processus meurt sur-le-champ, sans
/// exécuter la moindre ligne de sortie. Le binaire, lui, sait s'éteindre en
/// deux temps sur `SIGTERM` (`main::arret`, `replication.md` §5.2) — c'est ce
/// que systemd lui envoie, et c'est donc ce chemin-là qu'un essai doit
/// éprouver, pas la mort brutale.
///
/// **Et c'est ce qui rend sa couverture mesurable** : un processus tué de
/// force n'écrit pas son profil, et tout ce qu'il a exercé est perdu pour la
/// mesure — y compris du code des étages 1 et 2, que C2 veut à 100 %.
fn eteindre(serveur: &mut Child) {
    // SAFETY : `kill(2)` sur le PID d'un enfant qu'on tient, avec un signal
    // valide ; la valeur de retour est ignorée à dessein — si le processus
    // est déjà sorti, il n'y a rien à faire.
    let pid = i32::try_from(serveur.id()).unwrap_or(-1);
    if pid > 0 {
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
    // Il s'éteint en deux temps ; s'il s'attarde, on ne bloque pas l'essai.
    for _ in 0..50 {
        match serveur.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(100)),
            Err(_) => break,
        }
    }
    // Il ne s'est pas éteint : on ne laisse pas un processus derrière soi.
    let _ = serveur.kill();
    let _ = serveur.wait();
}

/// La même chose, avec des arguments de plus — ceux de la voie entre racines.
fn lancer_avec(autorite: &Path, base: &Path, en_plus: &[&str]) -> (Child, SocketAddr) {
    let mut enfant = Command::new(env!("CARGO_BIN_EXE_asl-server"))
        .arg("--store")
        .arg(base)
        .arg("--certificate")
        .arg(autorite.join("banc/chaine.pem"))
        .arg("--key")
        .arg(autorite.join("banc/serveur.key"))
        .args(["--port", "0"])
        // Le banc crée des comptes : il tient donc la posture faible, et le
        // binaire l'annonce dans son journal.
        .args(["--attestation", "optional"])
        .args(en_plus)
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

    // **LE TUYAU RESTE OUVERT TANT QUE LE SERVEUR VIT.** Le lâcher ici
    // fermerait la lecture de sa sortie d'erreur, et sa PROCHAINE ligne — la
    // posture, l'identité sous laquelle il estampille — tomberait sur un tuyau
    // fermé : `eprintln!` panique alors, et le serveur meurt avant d'avoir
    // servi. C'était une course, gagnée le plus souvent ; une ligne de plus au
    // démarrage l'a fait perdre une fois sur deux.
    // **`ASL_ESSAI_JOURNAL=1` MONTRE CE QUE LE SERVEUR DIT** : sans lui, le
    // journal d'exploitation est bu en silence, et un essai qui échoue ne dit
    // pas ce que le binaire a vu.
    let montrer = std::env::var_os("ASL_ESSAI_JOURNAL").is_some();
    std::thread::spawn(move || {
        for ligne in lignes.map_while(Result::ok) {
            if montrer {
                eprintln!("[{}] {ligne}", annonce.port());
            }
        }
    });

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
        let racine = Identifiant::depuis_entropie(Genre::Annuaire, [0xEE; 16]);
        let entrepot = Entrepot::ouvrir(&base, racine).expect("un entrepôt");
        entrepot
            .creer_compte(
                qui,
                Provenance::Ici,
                Some(AliasRange::nouveau("nitrogen").expect("il tient")),
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

    eteindre(&mut serveur);
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
        dit.contains("--store"),
        "il doit nommer ce qui manque : {dit}"
    );
    assert!(
        dit.contains("--certificate"),
        "et montrer l'usage complet : {dit}"
    );
}

#[test]
fn l_ancienne_grammaire_est_refusee_et_traduite() {
    // **UNE UNITÉ SYSTEMD D'AVANT 0.4.0 DOIT APPRENDRE LE NOUVEAU NOM**, et non
    // seulement « drapeau inconnu » : la grammaire est passée en anglais, et
    // le message reste en français.
    let sortie = Command::new(env!("CARGO_BIN_EXE_asl-server"))
        .args(["--entrepot", "/tmp/x"])
        .output()
        .expect("le binaire se lance");
    assert!(!sortie.status.success(), "il aurait dû refuser");
    let dit = String::from_utf8_lossy(&sortie.stderr);
    assert!(
        dit.contains("--entrepot n'existe plus : --store"),
        "il doit dire le nouveau nom : {dit}"
    );
}

#[test]
fn l_aide_sort_sans_erreur() {
    let sortie = Command::new(env!("CARGO_BIN_EXE_asl-server"))
        .arg("--help")
        .output()
        .expect("le binaire se lance");
    assert!(sortie.status.success(), "`--help` n'est pas une faute");
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

// ── La voie entre racines (`docs/replication.md` §2.2, §5.3-5.4) ────────────

/// Une identité de racine, frappée PAR LE BINAIRE : la clé privée, la publique
/// relue du fichier `.pub`, et l'identifiant que le binaire a imprimé.
fn identite(quoi: &str) -> (PathBuf, PathBuf, CleSecrete, ClePublique) {
    let privee = std::env::temp_dir().join(format!("asl-bin-{}-{quoi}.key", std::process::id()));
    let publique = privee.with_extension("key.pub");
    let _ = std::fs::remove_file(&privee);
    let _ = std::fs::remove_file(&publique);
    let sortie = Command::new(env!("CARGO_BIN_EXE_asl-server"))
        .arg("--new-identity-key")
        .arg(&privee)
        .output()
        .expect("le binaire se lance");
    assert!(
        sortie.status.success(),
        "la frappe a échoué : {}",
        String::from_utf8_lossy(&sortie.stderr)
    );
    let secrete = {
        let octets: [u8; 32] = std::fs::read(&privee)
            .expect("la clé privée est écrite")
            .as_slice()
            .try_into()
            .expect("trente-deux octets bruts");
        CleSecrete::depuis_entropie(octets)
    };
    let cle = {
        let octets: [u8; 32] = std::fs::read(&publique)
            .expect("la clé publique est écrite à côté")
            .as_slice()
            .try_into()
            .expect("trente-deux octets bruts");
        ClePublique::depuis_octets(octets).expect("un point valide")
    };
    assert_eq!(secrete.publique(), cle, "les deux fichiers vont ensemble");
    // Et ce qui est imprimé est ce qu'on porte chez l'autre : l'identifiant
    // se déduit de la clé, et l'exploitant le compare à l'œil.
    let dit = String::from_utf8_lossy(&sortie.stdout);
    assert!(
        dit.contains(identifiant_de_racine(&cle).texte().as_str()),
        "le binaire n'imprime pas l'identifiant déduit : {dit}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let droits = std::fs::metadata(&privee).expect("là").permissions().mode() & 0o777;
        assert_eq!(droits, 0o600, "la clé privée est en 0600");
    }
    (privee, publique, secrete, cle)
}

/// Mène la poignée de main.
async fn poignee(client: &mut ams_quic_client::Client) {
    for _ in 0..64_u32 {
        client.parler().await;
        if !client.ecouter().await {
            break;
        }
    }
}

/// La liaison de canal, exportée de la poignée de main du client.
fn liaison_du_client(client: &ams_quic_client::Client) -> asl_cle::LiaisonDeCanal {
    asl_cle::LiaisonDeCanal::depuis_octets(
        client
            .export(asl_cle::ETIQUETTE_LIAISON, None)
            .expect("la poignée de main est terminée"),
    )
}

/// Les champs d'une réponse, décodés — le statut n'est pas en clair sur le fil.
fn champs(reponse: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let entete = FrameHeader::parse(reponse).expect("une trame HTTP/3");
    assert_eq!(entete.kind(), FrameKind::Headers);
    let fin = usize::try_from(entete.total()).expect("tient");
    let mut section = reponse
        .get(entete.header_len()..fin)
        .expect("la section entière");
    let prefixe = qpack::read_prefix(section, 0, 0).expect("un préfixe");
    section = section.get(prefixe.read..).unwrap_or_default();
    let mut sortie = Vec::new();
    let mut place = [0_u8; 4096];
    let mut libre = &mut place[..];
    while !section.is_empty() {
        let decode = qpack::read_field_line(section, libre).expect("une ligne de champ");
        libre = decode.rest;
        section = section.get(decode.read..).unwrap_or_default();
        let (nom, valeur) = match decode.line {
            qpack::FieldLine::Indexed { index, .. } => {
                qpack::entree_statique(index).expect("une entrée statique")
            }
            qpack::FieldLine::LiteralWithName { index, value, .. } => {
                let (nom, _) = qpack::entree_statique(index).expect("un nom statique");
                (nom, value)
            }
            qpack::FieldLine::Literal { name, value, .. } => (name, value),
            autre => panic!("une représentation qu'on n'attend pas : {autre:?}"),
        };
        sortie.push((nom.to_vec(), valeur.to_vec()));
    }
    sortie
}

/// Le statut d'une réponse reçue sur ce flux.
fn statut(client: &ams_quic_client::Client, flux: u64) -> String {
    let champs = champs(client.recu(flux));
    let (_, valeur) = champs
        .iter()
        .find(|(nom, _)| nom == b":status")
        .expect("un statut");
    String::from_utf8_lossy(valeur).into_owned()
}

/// Tire un défi sur ce flux.
async fn un_defi(client: &mut ams_quic_client::Client, flux: u64) -> asl_cle::Defi {
    ams_quic_client::envoyer_une_requete(client, flux, 17, b"/v1/defi", None, b"").await;
    let octets = ams_quic_client::attendre_la_reponse(client, flux).await;
    let mut brut = [0_u8; asl_cle::DEFI_OCTETS];
    brut.copy_from_slice(&octets);
    asl_cle::Defi::depuis_octets(brut)
}

/// Prouve une clé Ed25519 sous cet identifiant — machine ou racine —, et rend
/// le statut.
async fn prouver(
    client: &mut ams_quic_client::Client,
    qui: Identifiant,
    secrete: &CleSecrete,
    flux: u64,
) -> String {
    let defi = un_defi(client, flux).await;
    let signature = secrete
        .signer(qui, &defi, &liaison_du_client(client))
        .expect("elle signe");
    let mut preuve = Vec::with_capacity(81);
    preuve.push(qui.genre().prefixe());
    preuve.extend_from_slice(qui.octets());
    preuve.extend_from_slice(signature.octets());
    // Le flux suivant, de quatre en quatre : les bidirectionnels du client.
    let suivant = flux.saturating_add(4);
    ams_quic_client::envoyer_avec_media(
        client,
        suivant,
        20,
        b"/v1/defi",
        None,
        &preuve,
        b"application/octet-stream",
    )
    .await;
    let _ = ams_quic_client::attendre_la_reponse(client, suivant).await;
    statut(client, suivant)
}

/// Demande à la racine tirée de prouver son identité, et vérifie ce qu'elle
/// rend contre la clé qu'on tient d'elle.
async fn preuve_de_la_racine(
    client: &mut ams_quic_client::Client,
    flux: u64,
    attendue: &ClePublique,
) {
    let defi = asl_cle::Defi::depuis_octets([0x5A; 32]);
    ams_quic_client::envoyer_avec_media(
        client,
        flux,
        20,
        b"/v1/pair/preuve",
        None,
        defi.octets(),
        b"application/octet-stream",
    )
    .await;
    let corps = ams_quic_client::attendre_la_reponse(client, flux).await;
    assert_eq!(statut(client, flux), "200");
    assert_eq!(corps.len(), 81, "n-… (17) ‖ signature (64)");
    assert_eq!(corps[0], b'n');
    let racine =
        Identifiant::depuis_entropie(Genre::Annuaire, corps[1..17].try_into().expect("seize"));
    let mut brute = [0_u8; 64];
    brute.copy_from_slice(&corps[17..]);
    let signature = asl_cle::Signature::depuis_octets(brute);
    assert_eq!(racine, identifiant_de_racine(attendue));
    assert!(
        attendue.prouve_la_racine(racine, &defi, &liaison_du_client(client), &signature),
        "la racine tirée n'a pas prouvé la clé qu'on tient d'elle"
    );
}

/// Lit les cadres d'un flux tenu, jusqu'à en avoir `combien` — ou jusqu'au
/// cadre de fin si `jusqu_a_la_fin`.
///
/// **LE FLUX NE SE TERMINE PAS**, donc on ne peut pas attendre sa fin : on lit
/// ce qui est arrivé, on découpe les trames `DATA` ENTIÈRES, et l'on
/// recommence tant qu'il manque quelque chose.
async fn lire_les_cadres(
    client: &mut ams_quic_client::Client,
    flux: u64,
    combien: usize,
    jusqu_a_la_fin: bool,
) -> Vec<Cadre> {
    let depart = std::time::Instant::now();
    loop {
        let recu = client.recu(flux).to_vec();
        let cadres = cadres_de(&recu);
        let fini = cadres
            .iter()
            .any(|cadre| matches!(cadre, Cadre::Fin { .. }));
        if cadres.len() >= combien && (!jusqu_a_la_fin || fini) {
            if jusqu_a_la_fin {
                // L'instantané se termine : le flux aussi.
                while !client.fin_recue(flux) {
                    assert!(
                        depart.elapsed() < std::time::Duration::from_secs(10),
                        "l'instantané ne se ferme pas"
                    );
                    client.ecouter().await;
                    client.parler().await;
                }
            }
            return cadres;
        }
        assert!(
            depart.elapsed() < std::time::Duration::from_secs(10),
            "{combien} cadres attendus sur le flux {flux}, {} reçus : {cadres:?}",
            cadres.len()
        );
        client.ecouter().await;
        client.parler().await;
    }
}

/// Les cadres portés par les trames `DATA` entières d'un flux.
fn cadres_de(recu: &[u8]) -> Vec<Cadre> {
    let Ok(entete) = FrameHeader::parse(recu) else {
        return Vec::new();
    };
    let mut reste = recu
        .get(usize::try_from(entete.total()).expect("tient")..)
        .unwrap_or_default();
    let mut charge = Vec::new();
    while let Ok(trame) = FrameHeader::parse(reste) {
        let fin = usize::try_from(trame.total()).expect("tient");
        let Some(entiere) = reste.get(trame.header_len()..fin) else {
            break;
        };
        charge.extend_from_slice(entiere);
        reste = reste.get(fin..).unwrap_or_default();
    }
    let mut cadres = Vec::new();
    let mut a_lire = charge.as_slice();
    while !a_lire.is_empty() {
        let Ok((cadre, combien)) = Cadre::lire(a_lire) else {
            break;
        };
        cadres.push(cadre);
        a_lire = a_lire.get(combien..).unwrap_or_default();
    }
    cadres
}

#[tokio::test]
async fn deux_racines_se_prouvent_et_l_une_tire_chez_l_autre() {
    // **C'EST `replication.md` §2.2, §5.3 ET §5.4, SUR DEUX VRAIS BINAIRES.**
    // `nitrogen` et `argon`, chacun avec sa clé et la clé de l'autre ; le
    // harnais joue `argon` qui tire chez `nitrogen` — la connexion sortante
    // n'est pas écrite, mais tout ce qu'elle fera est servi ici.
    let (autorite, racine_tls) = materiel("racines");
    let (cle_nitrogen, pub_nitrogen, secrete_nitrogen, publique_nitrogen) = identite("nitrogen");
    let (cle_argon, pub_argon, secrete_argon, publique_argon) = identite("argon");
    let n_argon = identifiant_de_racine(&publique_argon);

    // L'entrepôt de `nitrogen`, garni avant le lancement : un compte, son
    // appareil — dont on tient la clé, pour écrire pendant que ça tourne —,
    // et une machine enrôlée, pour le tiers.
    let base_nitrogen =
        std::env::temp_dir().join(format!("asl-bin-{}-nitrogen.redb", std::process::id()));
    let base_argon =
        std::env::temp_dir().join(format!("asl-bin-{}-argon.redb", std::process::id()));
    let _ = std::fs::remove_file(&base_nitrogen);
    let _ = std::fs::remove_file(&base_argon);
    let thierry = Identifiant::depuis_entropie(Genre::Utilisateur, [0x11; 16]);
    let iphone = Identifiant::depuis_entropie(Genre::Appareil, [0x22; 16]);
    let grenier = Identifiant::depuis_entropie(Genre::Machine, [0x33; 16]);
    let secrete_iphone =
        asl_cle::CleSecreteAppareil::depuis_entropie([0x44; 32]).expect("un scalaire valide");
    let secrete_grenier = CleSecrete::depuis_entropie([0x55; 32]);
    {
        // Sous l'identité de `nitrogen`, comme le binaire le fera.
        let entrepot = Entrepot::ouvrir(&base_nitrogen, identifiant_de_racine(&publique_nitrogen))
            .expect("un entrepôt");
        entrepot
            .creer_compte(
                thierry,
                Provenance::Ici,
                Some(AliasRange::nouveau("thierry").expect("il tient")),
            )
            .expect("1");
        entrepot
            .creer_appareil(
                iphone,
                Provenance::Ici,
                thierry,
                secrete_iphone.publique().octets(),
                asl_registre::Attestation::Aucune,
            )
            .expect("2");
        entrepot
            .creer_machine(
                grenier,
                Provenance::Ici,
                thierry,
                asl_registre::NomRange::nouveau("grenier").expect("il tient"),
                asl_registre::Capacites {
                    annonce: true,
                    lecture: true,
                },
            )
            .expect("3");
        let code = asl_cle::CodeEnrolement::analyser("4K9M2P7R1T")
            .expect("un code")
            .empreinte();
        entrepot
            .emettre_enrolement(&code, Provenance::Ici, grenier, u64::MAX)
            .expect("4");
        let enrolement = entrepot
            .consommer_enrolement(&code)
            .expect("lisible")
            .expect("le code");
        entrepot
            .lier_cle(
                grenier,
                secrete_grenier.publique().octets(),
                code,
                enrolement.estampille,
            )
            .expect("5");
    }

    // `nitrogen` d'abord — l'adresse de son pair ne sert pas encore, et c'est
    // dit : la connexion sortante est la tranche suivante. `argon` ensuite,
    // avec la vraie adresse de `nitrogen`.
    let racine_ca = autorite.join("racine.crt");
    let ca = racine_ca.to_str().expect("utf-8");
    let (mut nitrogen, ou_nitrogen) = lancer_avec(
        &autorite,
        &base_nitrogen,
        &[
            "--identity-key",
            cle_nitrogen.to_str().expect("utf-8"),
            "--peer",
            "127.0.0.1:6630",
            "--peer-key",
            pub_argon.to_str().expect("utf-8"),
            "--peer-ca",
            ca,
        ],
    );
    let vers_nitrogen = SocketAddr::from(([127, 0, 0, 1], ou_nitrogen.port()));
    // **LES DEUX POINTENT SUR UN PORT MORT**, et c'est voulu : cet essai éprouve
    // le côté SERVI de la voie avec un FAUX tireur (le harnais `ams-quic-client`
    // ci-dessous). Les vrais tireurs des deux binaires ne doivent donc tirer de
    // personne — sinon `argon` répliquerait l'entrepôt de `nitrogen`, et son
    // instantané ne serait plus vide. Ils rappellent 6630 sans fin, sans effet.
    let (mut argon, ou_argon) = lancer_avec(
        &autorite,
        &base_argon,
        &[
            "--identity-key",
            cle_argon.to_str().expect("utf-8"),
            "--peer",
            "127.0.0.1:6630",
            "--peer-key",
            pub_nitrogen.to_str().expect("utf-8"),
            "--peer-ca",
            ca,
        ],
    );
    let vers_argon = SocketAddr::from(([127, 0, 0, 1], ou_argon.port()));

    // ── `argon` TIRE CHEZ `nitrogen` ────────────────────────────────────────
    let mut tireur =
        ams_quic_client::Client::new(ams_quic_client::config_client(&racine_tls), vers_nitrogen)
            .await;
    poignee(&mut tireur).await;

    // Sans preuve, la voie est fermée.
    ams_quic_client::envoyer_une_requete(&mut tireur, 0, 17, b"/v1/pair/instantane", None, b"")
        .await;
    let _ = ams_quic_client::attendre_la_reponse(&mut tireur, 0).await;
    assert_eq!(statut(&tireur, 0), "401");

    // Premier temps : `argon` prouve sa clé d'identité sous le genre `n`.
    assert_eq!(
        prouver(&mut tireur, n_argon, &secrete_argon, 4).await,
        "204",
        "la racine qui tire prouve sa clé comme une machine"
    );
    // Second temps : `nitrogen` prouve la sienne en retour.
    preuve_de_la_racine(&mut tireur, 12, &publique_nitrogen).await;

    // L'instantané : l'état entier, puis le compteur de coupe, et le flux se
    // ferme. Cinq écritures, mais ce qui sort reconstitue l'état, pas le
    // journal : le compte et sa réclamation, l'appareil, la machine et ses
    // champs et sa clé, le service — il n'y en a pas —, et la fin.
    ams_quic_client::envoyer_une_requete(&mut tireur, 16, 17, b"/v1/pair/instantane", None, b"")
        .await;
    let cadres = lire_les_cadres(&mut tireur, 16, 1, true).await;
    assert_eq!(statut(&tireur, 16), "200");
    let genres: Vec<String> = cadres
        .iter()
        .map(|cadre| match cadre {
            Cadre::Operation { operation, .. } => format!("{:?}", operation.genre()),
            Cadre::Fin { coupe } => format!("Fin({})", coupe.compteur),
        })
        .collect();
    assert_eq!(
        genres,
        [
            "Compte",
            "Alias",
            "Machine",
            "MachineModifiee",
            "CleMachine",
            "Appareil",
            "Fin(5)",
        ],
        "{cadres:?}"
    );
    let Some(Cadre::Fin { coupe }) = cadres.last() else {
        panic!("le dernier cadre est la fin");
    };
    assert_eq!(coupe.racine, identifiant_de_racine(&publique_nitrogen));

    // Le flux des opérations, depuis le début : les cinq écritures du
    // journal, dans l'ordre — et il ne se termine pas.
    ams_quic_client::envoyer_une_requete(
        &mut tireur,
        20,
        17,
        b"/v1/pair/operations?apres=0",
        None,
        b"",
    )
    .await;
    let cadres = lire_les_cadres(&mut tireur, 20, 5, false).await;
    assert_eq!(statut(&tireur, 20), "200");
    assert_eq!(cadres.len(), 5, "{cadres:?}");
    assert!(!tireur.fin_recue(20), "le flux ne se termine jamais");
    let compteurs: Vec<u64> = cadres
        .iter()
        .map(|cadre| match cadre {
            Cadre::Operation { estampille, .. } => estampille.compteur,
            Cadre::Fin { .. } => panic!("pas de fin sur le flux des opérations"),
        })
        .collect();
    assert_eq!(compteurs, [1, 2, 3, 4, 5]);

    // Un second flux sur la même connexion : conflit.
    ams_quic_client::envoyer_une_requete(
        &mut tireur,
        24,
        17,
        b"/v1/pair/operations?apres=5",
        None,
        b"",
    )
    .await;
    let _ = ams_quic_client::attendre_la_reponse(&mut tireur, 24).await;
    assert_eq!(statut(&tireur, 24), "409");

    // ── UNE ÉCRITURE PENDANT QUE LE FLUX EST OUVERT ─────────────────────────
    //
    // L'appareil de Thierry change l'alias, sur SA connexion ; le flux du
    // tireur reçoit l'opération, sans qu'il ait rien redemandé.
    let mut telephone =
        ams_quic_client::Client::new(ams_quic_client::config_client(&racine_tls), vers_nitrogen)
            .await;
    poignee(&mut telephone).await;
    {
        let defi = un_defi(&mut telephone, 0).await;
        let signature = secrete_iphone
            .signer(iphone, &defi, &liaison_du_client(&telephone))
            .expect("l'appareil signe");
        let mut preuve = Vec::with_capacity(81);
        preuve.push(Genre::Appareil.prefixe());
        preuve.extend_from_slice(iphone.octets());
        preuve.extend_from_slice(signature.octets());
        ams_quic_client::envoyer_avec_media(
            &mut telephone,
            4,
            20,
            b"/v1/defi",
            None,
            &preuve,
            b"application/octet-stream",
        )
        .await;
        let _ = ams_quic_client::attendre_la_reponse(&mut telephone, 4).await;
        assert_eq!(statut(&telephone, 4), "204");
    }
    ams_quic_client::envoyer_une_requete(
        &mut telephone,
        8,
        21, // `:method: PUT`
        b"/v1/alias",
        None,
        br#"{"alias":"nitrogen"}"#,
    )
    .await;
    let _ = ams_quic_client::attendre_la_reponse(&mut telephone, 8).await;
    assert_eq!(statut(&telephone, 8), "204");

    let cadres = lire_les_cadres(&mut tireur, 20, 6, false).await;
    match cadres.get(5) {
        Some(Cadre::Operation {
            estampille,
            operation: Operation::Alias { compte, alias },
        }) => {
            assert_eq!(estampille.compteur, 6);
            assert_eq!(*compte, thierry);
            assert_eq!(
                alias.as_ref().map(|quoi| quoi.octets().to_vec()),
                Some(b"nitrogen".to_vec())
            );
        }
        autre => panic!("la sixième opération n'est pas l'alias : {autre:?}"),
    }

    // ── UN TIERS AVEC UNE CLÉ DE MACHINE : `401` SUR LES TROIS VERBES ───────
    let mut tiers =
        ams_quic_client::Client::new(ams_quic_client::config_client(&racine_tls), vers_nitrogen)
            .await;
    poignee(&mut tiers).await;
    assert_eq!(
        prouver(&mut tiers, grenier, &secrete_grenier, 0).await,
        "204"
    );
    for (flux, verbe, cible, corps) in [
        (8_u64, 17_u8, &b"/v1/pair/operations?apres=0"[..], &b""[..]),
        (12, 17, b"/v1/pair/instantane", b""),
        (16, 20, b"/v1/pair/preuve", &[0x5A; 32]),
    ] {
        ams_quic_client::envoyer_avec_media(
            &mut tiers,
            flux,
            verbe,
            cible,
            None,
            corps,
            b"application/octet-stream",
        )
        .await;
        let _ = ams_quic_client::attendre_la_reponse(&mut tiers, flux).await;
        assert_eq!(
            statut(&tiers, flux),
            "401",
            "une clé de machine n'ouvre pas la voie : {}",
            String::from_utf8_lossy(cible)
        );
    }

    // ── UNE RACINE QUI N'EST PAS LE PAIR : REFUSÉE COMME UNE CLÉ INCONNUE ──
    let inconnue = CleSecrete::depuis_entropie([0x66; 32]);
    let mut intruse =
        ams_quic_client::Client::new(ams_quic_client::config_client(&racine_tls), vers_nitrogen)
            .await;
    poignee(&mut intruse).await;
    assert_eq!(
        prouver(
            &mut intruse,
            identifiant_de_racine(&inconnue.publique()),
            &inconnue,
            0
        )
        .await,
        "401",
        "une seule clé, aucune liste"
    );

    // ── ET DANS L'AUTRE SENS : `nitrogen` TIRE CHEZ `argon` ────────────────
    //
    // Le même code des deux côtés (`replication.md` §2.1) : `argon` reconnaît
    // `nitrogen` par la clé qu'il tient de lui, et prouve la sienne en retour.
    let mut autre_sens =
        ams_quic_client::Client::new(ams_quic_client::config_client(&racine_tls), vers_argon).await;
    poignee(&mut autre_sens).await;
    assert_eq!(
        prouver(
            &mut autre_sens,
            identifiant_de_racine(&publique_nitrogen),
            &secrete_nitrogen,
            0
        )
        .await,
        "204"
    );
    preuve_de_la_racine(&mut autre_sens, 8, &publique_argon).await;
    // Un entrepôt vide : un instantané qui ne porte que sa fin, à zéro.
    ams_quic_client::envoyer_une_requete(
        &mut autre_sens,
        12,
        17,
        b"/v1/pair/instantane",
        None,
        b"",
    )
    .await;
    let cadres = lire_les_cadres(&mut autre_sens, 12, 1, true).await;
    assert_eq!(cadres.len(), 1, "{cadres:?}");
    assert!(matches!(cadres[0], Cadre::Fin { coupe } if coupe.compteur == 0));

    eteindre(&mut nitrogen);
    eteindre(&mut argon);
    let _ = std::fs::remove_dir_all(&autorite);
    for fichier in [
        &base_nitrogen,
        &base_argon,
        &cle_nitrogen,
        &pub_nitrogen,
        &cle_argon,
        &pub_argon,
    ] {
        let _ = std::fs::remove_file(fichier);
    }
}

#[test]
fn un_pair_sans_identite_refuse_de_demarrer() {
    // **`replication.md` §8** : une racine sans identité ne peut ni prouver
    // ni être prouvée, et une adresse seule n'est pas une racine.
    let sortie = Command::new(env!("CARGO_BIN_EXE_asl-server"))
        .args([
            "--store",
            "/tmp/x",
            "--certificate",
            "/tmp/y",
            "--key",
            "/tmp/z",
            "--attestation",
            "optional",
            "--peer",
            "argon.air-desktop.org:6630",
            "--peer-key",
            "/tmp/argon.pub",
            "--peer-ca",
            "/tmp/racine.crt",
        ])
        .output()
        .expect("le binaire se lance");
    assert!(!sortie.status.success(), "il aurait dû refuser");
    let dit = String::from_utf8_lossy(&sortie.stderr);
    assert!(
        dit.contains("--identity-key"),
        "il doit nommer ce qui manque : {dit}"
    );
}

// ── La réplication, de bout en bout : le TIREUR réel (`replication.md` §3) ───

/// Un client qui parle à cet annuaire, la poignée de main faite.
async fn client_vers(vers: SocketAddr, racine_tls: &[u8]) -> ams_quic_client::Client {
    let mut client =
        ams_quic_client::Client::new(ams_quic_client::config_client(racine_tls), vers).await;
    poignee(&mut client).await;
    client
}

/// Prouve la clé d'un appareil (P-256) sur cette connexion, sur ce flux.
async fn prouver_appareil(
    client: &mut ams_quic_client::Client,
    appareil: Identifiant,
    secrete: &asl_cle::CleSecreteAppareil,
    flux: u64,
) {
    let defi = un_defi(client, flux).await;
    let signature = secrete
        .signer(appareil, &defi, &liaison_du_client(client))
        .expect("l'appareil signe");
    let mut preuve = Vec::with_capacity(81);
    preuve.push(Genre::Appareil.prefixe());
    preuve.extend_from_slice(appareil.octets());
    preuve.extend_from_slice(signature.octets());
    let suivant = flux.saturating_add(4);
    ams_quic_client::envoyer_avec_media(
        client,
        suivant,
        20,
        b"/v1/defi",
        None,
        &preuve,
        b"application/octet-stream",
    )
    .await;
    let _ = ams_quic_client::attendre_la_reponse(client, suivant).await;
    assert_eq!(statut(client, suivant), "204", "l'appareil s'authentifie");
}

/// Lit `GET /v1/alias/{alias}` chez cet annuaire, et rend son corps si `200`.
async fn alias_chez(vers: SocketAddr, racine_tls: &[u8], alias: &str) -> Option<String> {
    let mut client = client_vers(vers, racine_tls).await;
    ams_quic_client::envoyer_une_requete(
        &mut client,
        0,
        17,
        format!("/v1/alias/{alias}").as_bytes(),
        None,
        b"",
    )
    .await;
    let corps = ams_quic_client::attendre_la_reponse(&mut client, 0).await;
    (statut(&client, 0) == "200").then(|| String::from_utf8_lossy(&corps).into_owned())
}

/// Lit `GET /v1/replication` chez cet annuaire, depuis cette machine enrôlée,
/// et rend son corps.
async fn replication_chez(
    vers: SocketAddr,
    racine_tls: &[u8],
    machine: Identifiant,
    secrete: &CleSecrete,
) -> String {
    let mut client = client_vers(vers, racine_tls).await;
    assert_eq!(prouver(&mut client, machine, secrete, 0).await, "204");
    ams_quic_client::envoyer_une_requete(&mut client, 8, 17, b"/v1/replication", None, b"").await;
    let corps = ams_quic_client::attendre_la_reponse(&mut client, 8).await;
    assert_eq!(
        statut(&client, 8),
        "200",
        "{}",
        String::from_utf8_lossy(&corps)
    );
    String::from_utf8_lossy(&corps).into_owned()
}

/// La valeur d'un champ JSON — texte ou nombre — dans ce corps, sans
/// guillemets.
fn champ_json(corps: &str, nom: &str) -> Option<String> {
    let marque = format!("\"{nom}\":");
    let debut = corps.find(&marque)?.saturating_add(marque.len());
    let reste = corps.get(debut..)?;
    let reste = reste.strip_prefix('"').unwrap_or(reste);
    let fin = reste.find(['"', ',', '}'])?;
    reste.get(..fin).map(str::to_owned)
}

/// Un dossier où `fsync` ne coûte rien, s'il y en a un : garnir des milliers
/// d'enregistrements — une transaction chacun — prend une minute sur un disque,
/// et une seconde en mémoire. Le binaire, lui, ne voit qu'un chemin.
fn dossier_rapide() -> PathBuf {
    let shm = PathBuf::from("/dev/shm");
    if shm.is_dir() {
        shm
    } else {
        std::env::temp_dir()
    }
}

/// Réessaie cette vérification asynchrone jusqu'à ce qu'elle tienne, ou échoue.
///
/// **LA RÉPLICATION EST À MOINS D'UNE SECONDE VOIE OUVERTE**, mais le tireur se
/// connecte en arrière-plan et recule à chaque échec : on lui laisse le temps
/// de s'établir plutôt que de fixer un délai unique.
macro_rules! attendre {
    ($etiquette:expr, $corps:block) => {{
        let depart = std::time::Instant::now();
        loop {
            if $corps {
                break;
            }
            assert!(
                depart.elapsed() < std::time::Duration::from_secs(30),
                "{} n'est pas advenu à temps",
                $etiquette
            );
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }};
}

#[tokio::test]
async fn la_replication_de_bout_en_bout() {
    // **DEUX BINAIRES, CHACUN `--peer` DE L'AUTRE, ET LE TIREUR QUI TOURNE.**
    // `nitrogen` est garni avant le lancement ; `argon` part vide et s'amorce
    // de lui. On éprouve la chaîne entière : connexion sortante, deux preuves,
    // rattrapage, application, flux vivant, et l'effet d'une révocation.
    let (autorite, racine_tls) = materiel("bout");
    let (cle_nitrogen, pub_nitrogen, _sn, publique_nitrogen) = identite("e2e-nitrogen");
    let (cle_argon, pub_argon, _sa, publique_argon) = identite("e2e-argon");
    let n_nitrogen = identifiant_de_racine(&publique_nitrogen);
    let n_argon = identifiant_de_racine(&publique_argon);

    let base_nitrogen =
        std::env::temp_dir().join(format!("asl-bin-{}-e2e-nitrogen.redb", std::process::id()));
    let base_argon =
        std::env::temp_dir().join(format!("asl-bin-{}-e2e-argon.redb", std::process::id()));
    let _ = std::fs::remove_file(&base_nitrogen);
    let _ = std::fs::remove_file(&base_argon);

    let thierry = Identifiant::depuis_entropie(Genre::Utilisateur, [0x11; 16]);
    let iphone = Identifiant::depuis_entropie(Genre::Appareil, [0x22; 16]);
    let grenier = Identifiant::depuis_entropie(Genre::Machine, [0x33; 16]);
    let secrete_iphone =
        asl_cle::CleSecreteAppareil::depuis_entropie([0x44; 32]).expect("un scalaire valide");
    let secrete_grenier = CleSecrete::depuis_entropie([0x55; 32]);
    {
        let entrepot = Entrepot::ouvrir(&base_nitrogen, identifiant_de_racine(&publique_nitrogen))
            .expect("un entrepôt");
        entrepot
            .creer_compte(
                thierry,
                Provenance::Ici,
                Some(AliasRange::nouveau("thierry").unwrap()),
            )
            .expect("compte");
        entrepot
            .creer_appareil(
                iphone,
                Provenance::Ici,
                thierry,
                secrete_iphone.publique().octets(),
                asl_registre::Attestation::Aucune,
            )
            .expect("appareil");
        entrepot
            .creer_machine(
                grenier,
                Provenance::Ici,
                thierry,
                asl_registre::NomRange::nouveau("grenier").unwrap(),
                asl_registre::Capacites {
                    annonce: true,
                    lecture: true,
                },
            )
            .expect("machine");
        let code = asl_cle::CodeEnrolement::analyser("4K9M2P7R1T")
            .unwrap()
            .empreinte();
        entrepot
            .emettre_enrolement(&code, Provenance::Ici, grenier, u64::MAX)
            .expect("code");
        let enrolement = entrepot.consommer_enrolement(&code).unwrap().unwrap();
        entrepot
            .lier_cle(
                grenier,
                secrete_grenier.publique().octets(),
                code,
                enrolement.estampille,
            )
            .expect("clé");
    }

    let ca = autorite.join("racine.crt");
    let ca = ca.to_str().expect("utf-8");
    // **NITROGEN D'ABORD**, pour connaître son port — c'est chez lui qu'argon
    // tire. Nitrogen part avec une adresse de pair provisoire (son propre
    // tireur vers argon n'importe pas ici : toutes les écritures de l'essai se
    // font chez lui, et c'est argon qui les tire) ; ce qui compte est que sa
    // `--peer-key` soit celle d'argon, pour vérifier argon quand il se présente.
    let (mut nitrogen, ou_nitrogen) = lancer_avec(
        &autorite,
        &base_nitrogen,
        &[
            "--identity-key",
            cle_nitrogen.to_str().unwrap(),
            "--peer-key",
            pub_argon.to_str().unwrap(),
            "--peer-ca",
            ca,
            "--peer",
            "127.0.0.1:6630",
        ],
    );
    let vers_nitrogen = SocketAddr::from(([127, 0, 0, 1], ou_nitrogen.port()));
    let (mut argon, ou_argon) = lancer_avec(
        &autorite,
        &base_argon,
        &[
            "--identity-key",
            cle_argon.to_str().unwrap(),
            "--peer-key",
            pub_nitrogen.to_str().unwrap(),
            "--peer-ca",
            ca,
            "--peer",
            &vers_nitrogen.to_string(),
        ],
    );
    let vers_argon = SocketAddr::from(([127, 0, 0, 1], ou_argon.port()));

    // ── 1. UN COMPTE CRÉÉ CHEZ NITROGEN EST LU CHEZ ARGON ───────────────────
    attendre!("le compte de nitrogen chez argon", {
        alias_chez(vers_argon, &racine_tls, "thierry")
            .await
            .is_some_and(|corps| corps.contains(thierry.texte().as_str()))
    });

    // ── 2. LA CLÉ DE GRENIER, ENRÔLÉE CHEZ NITROGEN, EST ACCEPTÉE CHEZ ARGON ─
    attendre!("la clé de machine acceptée chez argon", {
        let mut client = client_vers(vers_argon, &racine_tls).await;
        prouver(&mut client, grenier, &secrete_grenier, 0).await == "204"
    });

    // ── 2 bis. `GET /v1/replication`, DEPUIS LA MACHINE ENRÔLÉE ─────────────
    //
    // Chez argon, la voie vers nitrogen est ouverte, et ce qu'il a appliqué
    // rejoint son compteur — il a tout tiré. Chez nitrogen, la voie vers son
    // pair (un port mort) est coupée, et rien n'a été appliqué de lui.
    attendre!("l'état de la voie chez argon", {
        let corps = replication_chez(vers_argon, &racine_tls, grenier, &secrete_grenier).await;
        champ_json(&corps, "voie").as_deref() == Some("ouverte")
            && champ_json(&corps, "pair") == Some(n_nitrogen.texte().as_str().to_owned())
            && champ_json(&corps, "applique") == champ_json(&corps, "compteur")
            && champ_json(&corps, "applique").as_deref() == Some("5")
    });
    {
        let corps = replication_chez(vers_nitrogen, &racine_tls, grenier, &secrete_grenier).await;
        assert_eq!(
            champ_json(&corps, "voie").as_deref(),
            Some("coupée"),
            "{corps}"
        );
        assert_eq!(
            champ_json(&corps, "pair"),
            Some(n_argon.texte().as_str().to_owned())
        );
        assert_eq!(champ_json(&corps, "compteur").as_deref(), Some("5"));
        assert_eq!(champ_json(&corps, "applique").as_deref(), Some("0"));
    }

    // ── 3. UN FLUX VIVANT : UN ALIAS POSÉ CHEZ NITROGEN ARRIVE CHEZ ARGON ────
    {
        let mut telephone = client_vers(vers_nitrogen, &racine_tls).await;
        prouver_appareil(&mut telephone, iphone, &secrete_iphone, 0).await;
        ams_quic_client::envoyer_une_requete(
            &mut telephone,
            8,
            21, // PUT
            b"/v1/alias",
            None,
            br#"{"alias":"grenier-hote"}"#,
        )
        .await;
        let _ = ams_quic_client::attendre_la_reponse(&mut telephone, 8).await;
        assert_eq!(
            statut(&telephone, 8),
            "204",
            "l'alias est posé chez nitrogen"
        );
    }
    attendre!("l'alias vivant chez argon", {
        alias_chez(vers_argon, &racine_tls, "grenier-hote")
            .await
            .is_some_and(|corps| corps.contains(thierry.texte().as_str()))
    });
    // Et `applique` rejoint `compteur` après l'écriture : six chez nitrogen,
    // six appliqués chez argon.
    attendre!("`applique` rejoint `compteur` chez argon", {
        let corps = replication_chez(vers_argon, &racine_tls, grenier, &secrete_grenier).await;
        champ_json(&corps, "applique").as_deref() == Some("6")
            && champ_json(&corps, "compteur").as_deref() == Some("6")
    });

    // ── 4. UNE RÉVOCATION CHEZ NITROGEN FERME LA MACHINE TENUE CHEZ ARGON ────
    //
    // Une machine tient une connexion chez argon (clé prouvée). On révoque sa
    // clé chez nitrogen ; la révocation se réplique, argon l'applique, et
    // l'effet vivant ferme la connexion ici (§3.3) — la clé n'ouvre plus rien.
    let mut tenue = client_vers(vers_argon, &racine_tls).await;
    assert_eq!(
        prouver(&mut tenue, grenier, &secrete_grenier, 0).await,
        "204",
        "la machine tient une connexion chez argon"
    );
    {
        let mut telephone = client_vers(vers_nitrogen, &racine_tls).await;
        prouver_appareil(&mut telephone, iphone, &secrete_iphone, 0).await;
        let cible = format!("/v1/machines/{}/cle", grenier.texte());
        ams_quic_client::envoyer_une_requete(
            &mut telephone,
            8,
            16, /* DELETE */
            cible.as_bytes(),
            None,
            b"",
        )
        .await;
        let _ = ams_quic_client::attendre_la_reponse(&mut telephone, 8).await;
        assert_eq!(
            statut(&telephone, 8),
            "204",
            "la clé est révoquée chez nitrogen"
        );
    }
    // La révocation appliquée chez argon : une NOUVELLE preuve de grenier y est
    // désormais refusée.
    attendre!("la clé révoquée refusée chez argon", {
        let mut client = client_vers(vers_argon, &racine_tls).await;
        prouver(&mut client, grenier, &secrete_grenier, 8).await == "401"
    });
    // Et la connexion qu'elle TENAIT chez argon tombe : le transport se ferme.
    attendre!("la connexion tenue tombe chez argon", {
        tenue.parler().await;
        !tenue.ecouter().await
    });

    eteindre(&mut nitrogen);
    eteindre(&mut argon);
    let _ = std::fs::remove_dir_all(&autorite);
    for fichier in [
        &base_nitrogen,
        &base_argon,
        &cle_nitrogen,
        &pub_nitrogen,
        &cle_argon,
        &pub_argon,
    ] {
        let _ = std::fs::remove_file(fichier);
    }
}

// ── Au-delà de la fenêtre d'un flux : les parts (`protocole.md` §3 bis) ──────

/// Garnit cet entrepôt de `combien` comptes, chacun avec un alias `compteN`,
/// et rend ce que son instantané pèse.
fn garnir(base: &Entrepot, combien: u32) -> usize {
    for rang in 0..combien {
        let mut entropie = [0_u8; 16];
        entropie[..4].copy_from_slice(&rang.to_be_bytes());
        base.creer_compte(
            Identifiant::depuis_entropie(Genre::Utilisateur, entropie),
            Provenance::Ici,
            Some(AliasRange::nouveau(&format!("compte{rang}")).expect("un alias")),
        )
        .expect("le compte s'écrit");
    }
    base.instantane()
        .expect("lisible")
        .iter()
        .map(Vec::len)
        .sum()
}

#[tokio::test]
async fn un_entrepot_de_plusieurs_milliers_d_enregistrements_s_amorce() {
    // **L'AMORÇAGE, AU-DELÀ DE SOIXANTE-QUATRE KIBIOCTETS, AVEC LE VRAI
    // TIREUR** : trois mille comptes chez nitrogen, argon part vide et les tire
    // tous — par parts, appliqués par lots —, puis `GET /v1/replication` chez
    // argon dit que tout est appliqué.
    let (autorite, racine_tls) = materiel("grand");
    let (cle_nitrogen, pub_nitrogen, _sn, publique_nitrogen) = identite("grand-nitrogen");
    let (cle_argon, pub_argon, _sa, _publique_argon) = identite("grand-argon");
    let base_nitrogen = dossier_rapide().join(format!(
        "asl-bin-{}-grand-nitrogen.redb",
        std::process::id()
    ));
    let base_argon =
        dossier_rapide().join(format!("asl-bin-{}-grand-argon.redb", std::process::id()));
    let _ = std::fs::remove_file(&base_nitrogen);
    let _ = std::fs::remove_file(&base_argon);
    const COMBIEN: u32 = 3_000;
    let grenier = Identifiant::depuis_entropie(Genre::Machine, [0x33; 16]);
    let secrete_grenier = CleSecrete::depuis_entropie([0x55; 32]);
    let (octets, compteur) = {
        let entrepot = Entrepot::ouvrir(&base_nitrogen, identifiant_de_racine(&publique_nitrogen))
            .expect("un entrepôt");
        garnir(&entrepot, COMBIEN);
        // Et une machine enrôlée, pour lire `/v1/replication` chez argon.
        let thierry = Identifiant::depuis_entropie(Genre::Utilisateur, [0x11; 16]);
        entrepot
            .creer_compte(thierry, Provenance::Ici, None)
            .expect("compte");
        entrepot
            .creer_machine(
                grenier,
                Provenance::Ici,
                thierry,
                asl_registre::NomRange::nouveau("grenier").unwrap(),
                asl_registre::Capacites {
                    annonce: false,
                    lecture: false,
                },
            )
            .expect("machine");
        let code = asl_cle::CodeEnrolement::analyser("4K9M2P7R1T")
            .unwrap()
            .empreinte();
        entrepot
            .emettre_enrolement(&code, Provenance::Ici, grenier, u64::MAX)
            .expect("code");
        let enrolement = entrepot.consommer_enrolement(&code).unwrap().unwrap();
        entrepot
            .lier_cle(
                grenier,
                secrete_grenier.publique().octets(),
                code,
                enrolement.estampille,
            )
            .expect("clé");
        let octets: usize = entrepot
            .instantane()
            .expect("lisible")
            .iter()
            .map(Vec::len)
            .sum();
        (octets, entrepot.compteur().expect("lisible"))
    };
    assert!(octets > 64 * 1024, "{octets} octets");

    let ca = autorite.join("racine.crt");
    let ca = ca.to_str().expect("utf-8");
    let (mut nitrogen, ou_nitrogen) = lancer_avec(
        &autorite,
        &base_nitrogen,
        &[
            "--identity-key",
            cle_nitrogen.to_str().unwrap(),
            "--peer-key",
            pub_argon.to_str().unwrap(),
            "--peer-ca",
            ca,
            "--peer",
            "127.0.0.1:6630",
        ],
    );
    let vers_nitrogen = SocketAddr::from(([127, 0, 0, 1], ou_nitrogen.port()));
    let (mut argon, ou_argon) = lancer_avec(
        &autorite,
        &base_argon,
        &[
            "--identity-key",
            cle_argon.to_str().unwrap(),
            "--peer-key",
            pub_nitrogen.to_str().unwrap(),
            "--peer-ca",
            ca,
            "--peer",
            &vers_nitrogen.to_string(),
        ],
    );
    let vers_argon = SocketAddr::from(([127, 0, 0, 1], ou_argon.port()));

    // Le dernier compte garni est chez argon, et le premier aussi.
    let dernier = format!("compte{}", COMBIEN - 1);
    attendre!("le dernier compte chez argon", {
        alias_chez(vers_argon, &racine_tls, &dernier)
            .await
            .is_some()
    });
    assert!(
        alias_chez(vers_argon, &racine_tls, "compte0")
            .await
            .is_some()
    );
    // Et l'état le dit : voie ouverte vers nitrogen, tout appliqué jusqu'au
    // compteur de nitrogen, que le compteur d'argon a rejoint.
    attendre!("tout appliqué chez argon", {
        let corps = replication_chez(vers_argon, &racine_tls, grenier, &secrete_grenier).await;
        champ_json(&corps, "voie").as_deref() == Some("ouverte")
            && champ_json(&corps, "pair")
                == Some(
                    identifiant_de_racine(&publique_nitrogen)
                        .texte()
                        .as_str()
                        .to_owned(),
                )
            && champ_json(&corps, "applique") == Some(compteur.to_string())
            && champ_json(&corps, "compteur") == Some(compteur.to_string())
    });

    eteindre(&mut nitrogen);
    eteindre(&mut argon);
    let _ = std::fs::remove_dir_all(&autorite);
    for fichier in [
        &base_nitrogen,
        &base_argon,
        &cle_nitrogen,
        &pub_nitrogen,
        &cle_argon,
        &pub_argon,
    ] {
        let _ = std::fs::remove_file(fichier);
    }
}

// ── `--forget` : effacer un compte hors ligne (`modele.md` §2.1) ─────────────

/// Le statut d'un `GET` sans corps sur cette cible, depuis une connexion neuve.
async fn statut_chez(vers: SocketAddr, racine_tls: &[u8], cible: &str) -> String {
    let mut client = client_vers(vers, racine_tls).await;
    ams_quic_client::envoyer_une_requete(&mut client, 0, 17, cible.as_bytes(), None, b"").await;
    let _ = ams_quic_client::attendre_la_reponse(&mut client, 0).await;
    statut(&client, 0)
}

/// Lance `asl-server --forget` sur ce compte et cet entrepôt, et rend le code
/// de retour et la sortie d'erreur.
fn oublier(compte: &str, base: &Path, en_plus: &[&str]) -> (bool, String) {
    let sortie = Command::new(env!("CARGO_BIN_EXE_asl-server"))
        .arg("--forget")
        .arg(compte)
        .arg("--store")
        .arg(base)
        .args(en_plus)
        .output()
        .expect("le binaire se lance");
    (
        sortie.status.success(),
        String::from_utf8_lossy(&sortie.stderr).into_owned(),
    )
}

#[tokio::test]
async fn forget_efface_un_compte_hors_ligne_et_refuse_si_le_daemon_tient_l_entrepot() {
    let (autorite, racine_tls) = materiel("forget");
    let base = std::env::temp_dir().join(format!("asl-bin-{}-forget.redb", std::process::id()));
    let _ = std::fs::remove_file(&base);
    let (cle_identite, pub_identite, _, publique) = identite("forget");
    let n = identifiant_de_racine(&publique);

    // Un compte qui a tout : un alias, un appareil, une machine enrôlée — et un
    // voisin qui doit rester.
    let orphelin = Identifiant::depuis_entropie(Genre::Utilisateur, [0x24; 16]);
    let voisin = Identifiant::depuis_entropie(Genre::Utilisateur, [0x25; 16]);
    let appareil = Identifiant::depuis_entropie(Genre::Appareil, [0x24; 16]);
    let machine = Identifiant::depuis_entropie(Genre::Machine, [0x24; 16]);
    let secrete_machine = CleSecrete::depuis_entropie([0x24; 32]);
    let compteur_avant;
    {
        let entrepot = Entrepot::ouvrir(&base, n).expect("un entrepôt");
        entrepot
            .creer_compte(
                orphelin,
                Provenance::Ici,
                Some(AliasRange::nouveau("perdu").unwrap()),
            )
            .expect("compte");
        entrepot
            .creer_compte(
                voisin,
                Provenance::Ici,
                Some(AliasRange::nouveau("voisin").unwrap()),
            )
            .expect("compte");
        entrepot
            .creer_appareil(
                appareil,
                Provenance::Ici,
                orphelin,
                [0x24; 33],
                asl_registre::Attestation::Aucune,
            )
            .expect("appareil");
        entrepot
            .creer_machine(
                machine,
                Provenance::Ici,
                orphelin,
                asl_registre::NomRange::nouveau("perdue").unwrap(),
                asl_registre::Capacites {
                    annonce: true,
                    lecture: true,
                },
            )
            .expect("machine");
        entrepot
            .lier_cle(
                machine,
                secrete_machine.publique().octets(),
                [0; 32],
                asl_registre::Estampille {
                    compteur: 0,
                    racine: n,
                },
            )
            .expect("clé");
        compteur_avant = entrepot.compteur().expect("lisible");
    }
    let texte = orphelin.texte().as_str().to_owned();
    let identite_arg = cle_identite.to_str().unwrap().to_owned();

    // ── LE DAEMON TIENT L'ENTREPÔT : REFUS, ET IL LE DIT ────────────────────
    let (mut serveur, ou) = lancer_avec(&autorite, &base, &["--identity-key", &identite_arg]);
    let (ok, dit) = oublier(&texte, &base, &["--identity-key", &identite_arg]);
    assert!(!ok, "il aurait dû refuser : {dit}");
    assert!(
        dit.contains("tenu par un autre processus"),
        "il doit dire pourquoi : {dit}"
    );
    let vers = SocketAddr::from(([127, 0, 0, 1], ou.port()));
    assert_eq!(
        statut_chez(vers, &racine_tls, &format!("/v1/utilisateurs/{texte}")).await,
        "200",
        "rien n'a été écrit"
    );
    eteindre(&mut serveur);

    // ── ENTREPÔT ARRÊTÉ : LE COMPTE EST EFFACÉ, ET C'EST DIT ────────────────
    let (ok, dit) = oublier(&texte, &base, &["--identity-key", &identite_arg]);
    assert!(ok, "le geste passe : {dit}");
    assert!(
        dit.contains(&format!("compte {texte} effacé, cause exploitant")),
        "la ligne du journal, avec l'identifiant et la cause : {dit}"
    );
    assert!(
        dit.contains("1 appareil(s), 1 machine(s)") && dit.contains("alias libéré"),
        "et ce qui est parti, en nombres : {dit}"
    );
    {
        let entrepot = Entrepot::ouvrir(&base, n).expect("un entrepôt");
        let marque = entrepot
            .compte(orphelin)
            .expect("lisible")
            .expect("la marque reste");
        assert_eq!(
            marque.efface.map(|quoi| quoi.cause),
            Some(Cause::Exploitant)
        );
        assert_eq!(
            marque.estampille.racine, n,
            "estampillé sous l'identité donnée"
        );
        assert!(entrepot.compte_vivant(orphelin).expect("lisible").is_none());
        assert!(entrepot.compte_vivant(voisin).expect("lisible").is_some());
        assert!(entrepot.appareil(appareil).expect("lisible").is_none());
        assert!(entrepot.machine(machine).expect("lisible").is_none());
        // **L'OPÉRATION EST AU JOURNAL**, pour l'autre racine.
        match entrepot.operations_apres(compteur_avant).expect("lisible") {
            Rattrapage::Operations(cadres) => {
                assert_eq!(cadres.len(), 1);
                let (_, operation, _) = Operation::lire(&cadres[0]).expect("un cadre");
                assert!(
                    matches!(
                        operation,
                        Operation::CompteEfface { compte, cause: Cause::Exploitant, .. } if compte == orphelin
                    ),
                    "{operation:?}"
                );
            }
            autre => panic!("le journal doit porter l'effacement : {autre:?}"),
        }
    }

    // ── DÉJÀ EFFACÉ : DIT TEL, RIEN D'ÉCRIT ; INCONNU : REFUSÉ ──────────────
    let (ok, dit) = oublier(&texte, &base, &[]);
    assert!(ok, "{dit}");
    assert!(dit.contains("déjà effacé"), "{dit}");
    let inconnu = Identifiant::depuis_entropie(Genre::Utilisateur, [0x99; 16]);
    let (ok, dit) = oublier(inconnu.texte().as_str(), &base, &[]);
    assert!(!ok, "un inconnu est refusé : {dit}");
    assert!(dit.contains("inconnu"), "{dit}");
    // Et un identifiant qui n'est pas un compte est refusé avant d'ouvrir quoi
    // que ce soit.
    let (ok, dit) = oublier(machine.texte().as_str(), &base, &[]);
    assert!(!ok, "{dit}");
    assert!(
        dit.contains("--forget attend l'identifiant d'un compte"),
        "{dit}"
    );

    // ── AU REDÉMARRAGE, LE COMPTE EST UN INCONNU ET SA MACHINE NE PASSE PLUS ─
    let (mut serveur, ou) = lancer_avec(&autorite, &base, &["--identity-key", &identite_arg]);
    let vers = SocketAddr::from(([127, 0, 0, 1], ou.port()));
    assert_eq!(
        statut_chez(vers, &racine_tls, &format!("/v1/utilisateurs/{texte}")).await,
        "404"
    );
    assert_eq!(
        statut_chez(vers, &racine_tls, "/v1/alias/perdu").await,
        "404"
    );
    assert_eq!(
        statut_chez(vers, &racine_tls, "/v1/alias/voisin").await,
        "200"
    );
    let mut client = client_vers(vers, &racine_tls).await;
    assert_eq!(
        prouver(&mut client, machine, &secrete_machine, 0).await,
        "401"
    );
    eteindre(&mut serveur);
    let _ = std::fs::remove_dir_all(&autorite);
    for fichier in [&base, &cle_identite, &pub_identite] {
        let _ = std::fs::remove_file(fichier);
    }
}

// ── L'effacement, de bout en bout, à deux racines (`replication.md` §3.3) ───

#[tokio::test]
async fn l_effacement_d_un_compte_se_replique_de_bout_en_bout() {
    // **DEUX BINAIRES, ET LE TIREUR QUI TOURNE.** Un compte créé chez nitrogen
    // avec une machine enrôlée, effacé chez nitrogen par son appareil ; chez
    // argon, la machine ne peut plus se connecter — celle qui tenait une
    // connexion est fermée —, l'alias est libre, et le compte est un inconnu.
    let (autorite, racine_tls) = materiel("efface-bout");
    let (cle_nitrogen, pub_nitrogen, _sn, publique_nitrogen) = identite("efface-nitrogen");
    let (cle_argon, pub_argon, _sa, _publique_argon) = identite("efface-argon");

    let base_nitrogen = std::env::temp_dir().join(format!(
        "asl-bin-{}-efface-nitrogen.redb",
        std::process::id()
    ));
    let base_argon =
        std::env::temp_dir().join(format!("asl-bin-{}-efface-argon.redb", std::process::id()));
    let _ = std::fs::remove_file(&base_nitrogen);
    let _ = std::fs::remove_file(&base_argon);

    let thierry = Identifiant::depuis_entropie(Genre::Utilisateur, [0x61; 16]);
    let iphone = Identifiant::depuis_entropie(Genre::Appareil, [0x62; 16]);
    let grenier = Identifiant::depuis_entropie(Genre::Machine, [0x63; 16]);
    let secrete_iphone =
        asl_cle::CleSecreteAppareil::depuis_entropie([0x64; 32]).expect("un scalaire valide");
    let secrete_grenier = CleSecrete::depuis_entropie([0x65; 32]);
    {
        let entrepot = Entrepot::ouvrir(&base_nitrogen, identifiant_de_racine(&publique_nitrogen))
            .expect("un entrepôt");
        entrepot
            .creer_compte(
                thierry,
                Provenance::Ici,
                Some(AliasRange::nouveau("qui-part").unwrap()),
            )
            .expect("compte");
        entrepot
            .creer_appareil(
                iphone,
                Provenance::Ici,
                thierry,
                secrete_iphone.publique().octets(),
                asl_registre::Attestation::Aucune,
            )
            .expect("appareil");
        entrepot
            .creer_machine(
                grenier,
                Provenance::Ici,
                thierry,
                asl_registre::NomRange::nouveau("grenier").unwrap(),
                asl_registre::Capacites {
                    annonce: true,
                    lecture: true,
                },
            )
            .expect("machine");
        let code = asl_cle::CodeEnrolement::analyser("4K9M2P7R1T")
            .unwrap()
            .empreinte();
        entrepot
            .emettre_enrolement(&code, Provenance::Ici, grenier, u64::MAX)
            .expect("code");
        let enrolement = entrepot.consommer_enrolement(&code).unwrap().unwrap();
        entrepot
            .lier_cle(
                grenier,
                secrete_grenier.publique().octets(),
                code,
                enrolement.estampille,
            )
            .expect("clé");
    }

    let ca = autorite.join("racine.crt");
    let ca = ca.to_str().expect("utf-8");
    let (mut nitrogen, ou_nitrogen) = lancer_avec(
        &autorite,
        &base_nitrogen,
        &[
            "--identity-key",
            cle_nitrogen.to_str().unwrap(),
            "--peer-key",
            pub_argon.to_str().unwrap(),
            "--peer-ca",
            ca,
            "--peer",
            "127.0.0.1:6630",
        ],
    );
    let vers_nitrogen = SocketAddr::from(([127, 0, 0, 1], ou_nitrogen.port()));
    let (mut argon, ou_argon) = lancer_avec(
        &autorite,
        &base_argon,
        &[
            "--identity-key",
            cle_argon.to_str().unwrap(),
            "--peer-key",
            pub_nitrogen.to_str().unwrap(),
            "--peer-ca",
            ca,
            "--peer",
            &vers_nitrogen.to_string(),
        ],
    );
    let vers_argon = SocketAddr::from(([127, 0, 0, 1], ou_argon.port()));

    // ── 1. LE COMPTE ET SA MACHINE SONT CHEZ ARGON ──────────────────────────
    attendre!("le compte de nitrogen chez argon", {
        alias_chez(vers_argon, &racine_tls, "qui-part")
            .await
            .is_some_and(|corps| corps.contains(thierry.texte().as_str()))
    });
    attendre!("la clé de machine acceptée chez argon", {
        let mut client = client_vers(vers_argon, &racine_tls).await;
        prouver(&mut client, grenier, &secrete_grenier, 0).await == "204"
    });
    // Une machine tient une connexion chez argon : c'est elle qui devra tomber.
    let mut tenue = client_vers(vers_argon, &racine_tls).await;
    assert_eq!(
        prouver(&mut tenue, grenier, &secrete_grenier, 0).await,
        "204",
        "la machine tient une connexion chez argon"
    );

    // ── 2. LE TITULAIRE EFFACE SON COMPTE CHEZ NITROGEN ─────────────────────
    {
        let mut telephone = client_vers(vers_nitrogen, &racine_tls).await;
        prouver_appareil(&mut telephone, iphone, &secrete_iphone, 0).await;
        ams_quic_client::envoyer_une_requete(
            &mut telephone,
            8,
            16, /* DELETE */
            b"/v1/compte",
            None,
            b"",
        )
        .await;
        let _ = ams_quic_client::attendre_la_reponse(&mut telephone, 8).await;
        assert_eq!(
            statut(&telephone, 8),
            "204",
            "le compte est effacé chez nitrogen"
        );
    }
    assert_eq!(
        statut_chez(
            vers_nitrogen,
            &racine_tls,
            &format!("/v1/utilisateurs/{thierry}")
        )
        .await,
        "404"
    );

    // ── 3. CHEZ ARGON : PLUS DE MACHINE, PLUS D'ALIAS, PLUS DE COMPTE ───────
    attendre!("la clé de la machine refusée chez argon", {
        let mut client = client_vers(vers_argon, &racine_tls).await;
        prouver(&mut client, grenier, &secrete_grenier, 8).await == "401"
    });
    attendre!("la connexion tenue tombe chez argon", {
        tenue.parler().await;
        !tenue.ecouter().await
    });
    assert!(
        alias_chez(vers_argon, &racine_tls, "qui-part")
            .await
            .is_none(),
        "l'alias est libre chez argon"
    );
    assert_eq!(
        statut_chez(
            vers_argon,
            &racine_tls,
            &format!("/v1/utilisateurs/{thierry}")
        )
        .await,
        "404",
        "le compte effacé est un inconnu chez argon"
    );
    // Et l'appareil non plus ne passe plus, nulle part.
    for vers in [vers_nitrogen, vers_argon] {
        let mut client = client_vers(vers, &racine_tls).await;
        let defi = un_defi(&mut client, 0).await;
        let signature = secrete_iphone
            .signer(iphone, &defi, &liaison_du_client(&client))
            .expect("l'appareil signe");
        let mut preuve = Vec::with_capacity(81);
        preuve.push(Genre::Appareil.prefixe());
        preuve.extend_from_slice(iphone.octets());
        preuve.extend_from_slice(signature.octets());
        ams_quic_client::envoyer_avec_media(
            &mut client,
            4,
            20,
            b"/v1/defi",
            None,
            &preuve,
            b"application/octet-stream",
        )
        .await;
        let _ = ams_quic_client::attendre_la_reponse(&mut client, 4).await;
        assert_eq!(statut(&client, 4), "401", "chez {vers}");
    }

    eteindre(&mut nitrogen);
    eteindre(&mut argon);
    let _ = std::fs::remove_dir_all(&autorite);
    for fichier in [
        &base_nitrogen,
        &base_argon,
        &cle_nitrogen,
        &pub_nitrogen,
        &cle_argon,
        &pub_argon,
    ] {
        let _ = std::fs::remove_file(fichier);
    }
}

/// Lance le binaire sous la posture `invitation`, avec cette clé d'exploitant.
///
/// **Un lanceur à part plutôt qu'un paramètre de plus** : `lancer_avec` pose
/// `--attestation optional` pour tous les autres essais, et cette posture-ci
/// n'admet personne sans code — les deux ne se mélangent pas.
fn lancer_en_invitation(autorite: &Path, base: &Path, cle_publique: &Path) -> (Child, SocketAddr) {
    let mut enfant = Command::new(env!("CARGO_BIN_EXE_asl-server"))
        .arg("--store")
        .arg(base)
        .arg("--certificate")
        .arg(autorite.join("banc/chaine.pem"))
        .arg("--key")
        .arg(autorite.join("banc/serveur.key"))
        .args(["--port", "0"])
        .args(["--attestation", "invitation"])
        .arg("--operator-key")
        .arg(cle_publique)
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
    let montrer = std::env::var_os("ASL_ESSAI_JOURNAL").is_some();
    std::thread::spawn(move || {
        for ligne in lignes.map_while(Result::ok) {
            if montrer {
                eprintln!("[{}] {ligne}", annonce.port());
            }
        }
    });
    (enfant, annonce)
}

/// Frappe une clé d'exploitant par `--new-operator-key`, et rend les deux
/// chemins.
fn cle_d_exploitant(quoi: &str) -> (PathBuf, PathBuf) {
    let privee = std::env::temp_dir().join(format!("asl-bin-{}-{quoi}.op", std::process::id()));
    let publique = privee.with_extension("op.pub");
    let _ = std::fs::remove_file(&privee);
    let _ = std::fs::remove_file(&publique);
    let sortie = Command::new(env!("CARGO_BIN_EXE_asl-server"))
        .arg("--new-operator-key")
        .arg(&privee)
        .output()
        .expect("le binaire se lance");
    assert!(
        sortie.status.success(),
        "la frappe a échoué : {}",
        String::from_utf8_lossy(&sortie.stderr)
    );
    // **CE QU'IL IMPRIME EST UN MODE D'EMPLOI**, et il nomme les deux racines :
    // une clé d'exploitant qui n'irait que sur l'une laisserait la moitié des
    // invitations inconnues (`protocole.md` §2.2).
    let dit = String::from_utf8_lossy(&sortie.stdout);
    assert!(dit.contains("--operator-key"), "{dit}");
    assert!(dit.contains("DEUX racines"), "{dit}");
    // **PAS DE LIGNE `identifiant`**, que `--new-identity-key` imprime : un
    // exploitant n'est pas une racine, et n'a pas de `n-…` à comparer à l'œil.
    assert!(
        !dit.contains("identifiant"),
        "un exploitant n'a pas d'identifiant de racine : {dit}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let droits = std::fs::metadata(&privee).expect("là").permissions().mode() & 0o777;
        assert_eq!(droits, 0o600, "la clé privée de l'exploitant est en 0600");
    }
    (privee, publique)
}

/// Lance `--invite` contre cet annuaire, et rend `(succès, stdout, stderr)`.
fn inviter(annuaire: SocketAddr, autorite: &Path, secrete: &Path) -> (bool, String, String) {
    let sortie = Command::new(env!("CARGO_BIN_EXE_asl-server"))
        .arg("--invite")
        .args(["--directory", &format!("localhost:{}", annuaire.port())])
        .arg("--ca")
        .arg(autorite.join("racine.crt"))
        .arg("--operator-secret")
        .arg(secrete)
        .output()
        .expect("le binaire se lance");
    (
        sortie.status.success(),
        String::from_utf8_lossy(&sortie.stdout).trim().to_owned(),
        String::from_utf8_lossy(&sortie.stderr).into_owned(),
    )
}

#[tokio::test]
async fn l_exploitant_emet_une_invitation_et_un_compte_s_ouvre_dessus() {
    // **`protocole.md` §2.2, le geste d'émission de bout en bout.** La clé se
    // frappe ici, sa publique va sur le banc, et `--invite` parle à un
    // annuaire QUI TOURNE — rien n'est arrêté, aucun entrepôt n'est ouvert par
    // l'outil. Le code rendu ouvre un compte, une fois, et une seule.
    let (autorite, racine) = materiel("invite");
    let base = std::env::temp_dir().join(format!("asl-bin-{}-invite.redb", std::process::id()));
    let _ = std::fs::remove_file(&base);
    let (secrete, publique) = cle_d_exploitant("invite");
    let (mut serveur, adresse) = lancer_en_invitation(&autorite, &base, &publique);

    // ── 1. L'exploitant émet ────────────────────────────────────────────────
    let (succes, code, dit) = inviter(adresse, &autorite, &secrete);
    assert!(succes, "l'émission doit aboutir : {dit}");
    assert_eq!(code.len(), 11, "dix symboles et un tiret : {code}");
    // **LE CODE EST SEUL SUR LA SORTIE STANDARD** — un `| pbcopy` ne doit rien
    // copier d'autre —, et son échéance va sur la sortie d'erreur.
    assert!(
        !code.contains('\n'),
        "le code est seul sur stdout : {code:?}"
    );
    assert!(dit.contains("valable jusqu'à"), "{dit}");
    assert!(
        dit.contains("ne sera pas réaffiché"),
        "l'outil dit que le code ne revient pas : {dit}"
    );
    assert!(
        !dit.contains(&code),
        "le code ne se répète pas ailleurs : {dit}"
    );

    // ── 2. Ce code ouvre un compte, sous la plate-forme 3 ───────────────────
    // L'annonce porte l'adresse d'écoute — la joker `[::]` —, et l'on ne se
    // connecte pas à une joker : on vise la boucle locale sur ce port-là,
    // comme les autres essais de ce fichier.
    let vers = SocketAddr::from(([127, 0, 0, 1], adresse.port()));
    let ouvrir = |code: String, graine: u8| {
        let racine = racine.clone();
        async move {
            let mut client = client_vers(vers, &racine).await;
            let defi = un_defi(&mut client, 0).await;
            let liaison = liaison_du_client(&client);
            let cle = asl_cle::CleSecreteAppareil::depuis_entropie([graine; 32])
                .expect("un scalaire valide");
            let preuve = cle.prouver_la_possession(&defi, &liaison);
            let sans_tiret = code.replace('-', "");
            let objet = asl_api::corps::CreationDeCompte {
                plateforme: asl_api::corps::PlateformeAttestation::Invitation,
                cle: &cle.publique().octets(),
                preuve: preuve.octets(),
                attestation: sans_tiret.as_bytes(),
            };
            let mut tampon = [0_u8; asl_api::corps::COMPTE_CORPS_MAX];
            let n = objet.encoder(&mut tampon).expect("un corps bien formé");
            ams_quic_client::envoyer_avec_media(
                &mut client,
                4,
                20,
                b"/v1/comptes",
                None,
                &tampon[..n],
                b"application/octet-stream",
            )
            .await;
            let corps = ams_quic_client::attendre_la_reponse(&mut client, 4).await;
            (
                statut(&client, 4),
                String::from_utf8_lossy(&corps).into_owned(),
            )
        }
    };

    let (etat, corps) = ouvrir(code.clone(), 0x5C).await;
    assert_eq!(etat, "201", "le compte s'ouvre sur l'invitation : {corps}");
    assert!(corps.contains("\"compte\":\"u-"), "{corps}");

    // ── 3. Le même code ne sert pas deux fois ───────────────────────────────
    let (etat, _) = ouvrir(code, 0x6D).await;
    assert_eq!(etat, "403", "un code consommé ne rouvre pas de compte");

    eteindre(&mut serveur);
    let _ = std::fs::remove_file(&base);
    let _ = std::fs::remove_dir_all(&autorite);
}

#[tokio::test]
async fn une_autre_cle_n_emet_rien_et_une_racine_sans_posture_non_plus() {
    // Les deux refus que l'exploitant doit pouvoir distinguer sans rien lire
    // d'autre : « ce n'est pas ma clé » et « cette racine n'invite pas ».
    let (autorite, _racine) = materiel("invite-refus");
    let base =
        std::env::temp_dir().join(format!("asl-bin-{}-invite-refus.redb", std::process::id()));
    let _ = std::fs::remove_file(&base);
    let (_secrete, publique) = cle_d_exploitant("invite-refus");
    let (imposteur, _) = cle_d_exploitant("invite-imposteur");

    // ── Une clé qui n'est pas celle du réglage : `401` ──────────────────────
    let (mut serveur, adresse) = lancer_en_invitation(&autorite, &base, &publique);
    let (succes, code, dit) = inviter(adresse, &autorite, &imposteur);
    assert!(!succes, "une autre clé n'émet pas");
    assert!(code.is_empty(), "aucun code ne sort : {code:?}");
    assert!(
        dit.contains("la racine a refusé la signature"),
        "le refus dit quoi faire : {dit}"
    );
    eteindre(&mut serveur);

    // ── La même clé, mais une racine en `optional` : `404` ──────────────────
    let base2 = std::env::temp_dir().join(format!(
        "asl-bin-{}-invite-optional.redb",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&base2);
    let (mut serveur, adresse) = lancer(&autorite, &base2);
    let (succes, code, dit) = inviter(adresse, &autorite, &_secrete);
    assert!(!succes, "une racine en `optional` n'émet pas d'invitations");
    assert!(code.is_empty(), "aucun code ne sort : {code:?}");
    assert!(
        dit.contains("n'émet pas d'invitations"),
        "le refus nomme la posture : {dit}"
    );
    eteindre(&mut serveur);

    let _ = std::fs::remove_file(&base);
    let _ = std::fs::remove_file(&base2);
    let _ = std::fs::remove_dir_all(&autorite);
}
