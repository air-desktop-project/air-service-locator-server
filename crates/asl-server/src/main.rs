//! L'annuaire : le binaire qui assemble, et qui ne décide de rien.
//!
//! # CE QU'IL FAIT, DANS L'ORDRE, ET POURQUOI CET ORDRE
//!
//! 1. **Il refuse de tourner en root** (C8). En premier, avant même de lire ses
//!    arguments : ce qui est refusé doit l'être avant d'avoir ouvert quoi que ce
//!    soit.
//! 2. Il lit ses réglages.
//! 3. Il lit sa clé d'identité et celle de l'autre racine, s'il en a : c'est
//!    l'identité qui dit sous quel `n-…` l'entrepôt estampille, donc elle
//!    passe avant lui.
//! 4. Il ouvre l'entrepôt, **puis** lit le certificat et la clé TLS. Dans cet
//!    ordre parce qu'une base verrouillée par une autre instance est la panne
//!    la plus probable, et qu'on préfère l'apprendre avant d'avoir lu des
//!    secrets.
//! 5. Il ouvre la socket en double pile.
//! 6. Il lance l'expiration du journal, puis l'écoute.
//!
//! # IL N'AJOUTE AUCUNE DÉCISION, ET C'EST LA PROPRIÉTÉ QU'IL FAUT GARDER
//!
//! Tout ce qui décide est ailleurs et couvert à 100 % : le routage dans
//! `asl-api`, la réponse dans `asl-session`, le format dans `asl-registre`, le
//! refus de root dans `asl-loop-tokio::privileges`. Ce fichier tient une
//! séquence et des messages d'erreur — rien qu'un essai de logique aurait à
//! examiner.
//!
//! # POURQUOI IL ÉCRIT SUR LA SORTIE D'ERREUR PLUTÔT QUE DANS UN JOURNAL
//!
//! Un service lancé par systemd voit sa sortie captée par le journal du système.
//! Écrire nous-mêmes dans un fichier ferait un second endroit où chercher, avec
//! sa rotation, ses droits et ses pannes propres.

mod entropie;
mod identite;
mod reglages;
mod socket;

use std::sync::Arc;

use asl_loop_tokio::h3::Voie;
use asl_loop_tokio::{
    Annuaire, EtatDeLaVoie, Tireur, configuration_tls, refuser_root, servir_quic,
};
use asl_store::{Entrepot, RACINE_SANS_IDENTITE};

use crate::reglages::{Reglages, USAGE};

/// Combien de temps entre deux passages d'expiration du journal.
///
/// **UNE HEURE, ET NON UNE FOIS AU DÉMARRAGE.** Un annuaire tourne des mois : ne
/// nettoyer qu'au lancement ferait de la rétention de quatre-vingt-dix jours une
/// promesse que seul un redémarrage tiendrait — et C18 serait tenue par accident.
const EXPIRATION_TOUTES_LES: core::time::Duration = core::time::Duration::from_secs(3_600);

fn main() -> std::process::ExitCode {
    match demarrer() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(quoi) => {
            eprintln!("asl-server : {quoi}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Ce que `asl-server --version` imprime : `asl-server 0.2.0 (181e291)`.
///
/// La version est celle du workspace, en lockstep (`Cargo.toml`) ; le commit
/// vient de `build.rs`, et manque quand le binaire n'a pas été construit dans
/// un dépôt — on l'omet alors plutôt que d'écrire « inconnu », qui aurait
/// l'air d'une valeur. Un `+` derrière le commit dit que l'arbre était modifié.
fn version() -> String {
    let commit = env!("ASL_COMMIT");
    if commit.is_empty() {
        format!("asl-server {}", env!("CARGO_PKG_VERSION"))
    } else {
        format!("asl-server {} ({commit})", env!("CARGO_PKG_VERSION"))
    }
}

/// Tout ce qui peut échouer, rassemblé pour que `main` reste lisible.
fn demarrer() -> Result<(), Box<dyn std::error::Error>> {
    // **EN PREMIER** : voir l'en-tête, et `asl-loop-tokio::privileges`.
    refuser_root()?;

    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments
        .iter()
        .any(|quoi| quoi == "--help" || quoi == "-h")
    {
        print!("{USAGE}");
        return Ok(());
    }
    if arguments.iter().any(|quoi| quoi == "--version") {
        println!("{}", version());
        return Ok(());
    }
    // **FRAPPER UNE CLÉ EST UN GESTE, PAS UN RÉGLAGE** : on l'écrit, on
    // l'imprime, on s'arrête — sans entrepôt, sans certificat, sans socket.
    if let Some(rang) = arguments
        .iter()
        .position(|quoi| quoi == "--new-identity-key")
    {
        let Some(chemin) = arguments.get(rang.saturating_add(1)) else {
            eprint!("{USAGE}");
            return Err("--new-identity-key attend un chemin".into());
        };
        return nouvelle_identite(std::path::Path::new(chemin));
    }
    let reglages = Reglages::depuis(&arguments).inspect_err(|_| eprint!("{USAGE}"))?;

    // **LE BAIL SE VALIDE AVANT D'OUVRIR QUOI QUE CE SOIT.** Un `--keepalive`
    // absurde doit se dire tout de suite, et non après avoir verrouillé une
    // base et lu une clé privée : ce qui est refusé doit l'être avant d'avoir
    // ouvert quelque chose.
    // `asl_proto::Erreur` ne porte pas `std::error::Error` — c'est une crate
    // `no_std`, et l'y ajouter pour un seul appelant serait faire porter à
    // trente daemons ce dont un binaire a besoin. On la met en mots ici.
    let bail = reglages
        .bail()
        .map_err(|quoi| format!("--keepalive et --idle ne forment pas un bail : {quoi}"))?;

    // **L'IDENTITÉ AVANT L'ENTREPÔT** : c'est elle qui dit sous quel `n-…`
    // il estampille. Et la clé de l'autre racine tout de suite après — un
    // fichier qui manque doit se dire avant d'avoir verrouillé une base.
    let identite = reglages
        .identite
        .as_ref()
        .map(|chemin| identite::lire_secrete(chemin))
        .transpose()?;
    let cle_du_pair = reglages
        .pair
        .as_ref()
        .map(|pair| identite::lire_publique(&pair.cle))
        .transpose()?;
    // **SANS CLÉ, SEIZE ZÉROS — ET C'EST DIT AU DÉMARRAGE.** Une clé générée
    // en silence aurait été pire (§8) : une clé que personne n'a copiée nulle
    // part. `asl_store::RACINE_SANS_IDENTITE` dit le reste, et l'entrepôt
    // ré-estampille ce qui a été écrit sous elle au premier démarrage avec
    // une clé (§11.4).
    let racine = identite.as_ref().map_or(RACINE_SANS_IDENTITE, |cle| {
        asl_cle::identifiant_de_racine(&cle.publique())
    });

    let entrepot = Arc::new(Entrepot::ouvrir(&reglages.entrepot, racine)?);
    let chaine = std::fs::read(&reglages.certificat)?;
    let cle = std::fs::read(&reglages.cle)?;
    let tls = Arc::new(configuration_tls(&chaine, &cle)?);
    let socket = socket::ecouter(reglages.port)?;
    let ou = socket.local_addr()?;

    let execution = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    execution.block_on(async move {
        let socket = tokio::net::UdpSocket::from_std(socket)?;
        eprintln!(
            "asl-server : écoute sur {ou} (double pile), entrepôt {}, \
             bail {} s / {} s, rétention {} jours",
            reglages.entrepot.display(),
            bail.keepalive_secondes(),
            bail.inactivite_secondes(),
            reglages.retention_jours,
        );

        // **L'IDENTITÉ SE DIT AU DÉMARRAGE** — et son absence aussi, fort :
        // une racine qui estampille sous seize zéros ne se réplique avec
        // personne, et l'exploitant doit le lire là où il relit ses réglages.
        match &identite {
            Some(cle) => eprintln!(
                "asl-server : identité {}, clé publique {} — compteur à {}.",
                entrepot.racine(),
                identite::en_hexadecimal(&cle.publique().octets()),
                entrepot.compteur().unwrap_or(0),
            ),
            None => eprintln!(
                "asl-server : SANS CLÉ D'IDENTITÉ (--identity-key) : les écritures sont \
                 estampillées {} — compteur à {} —, et aucune autre racine ne peut \
                 tirer d'ici.",
                entrepot.racine(),
                entrepot.compteur().unwrap_or(0),
            ),
        }
        // **LA REPRISE SE DIT, AVEC LE NOMBRE** (§11.4) : ce qui avait été
        // estampillé sans identité est passé sous celle-ci, une fois.
        if entrepot.reestampilles() > 0 {
            eprintln!(
                "asl-server : {} enregistrements et opérations estampillés sans identité \
                 ({RACINE_SANS_IDENTITE}) sont passés sous {} — une fois, dans une transaction.",
                entrepot.reestampilles(),
                entrepot.racine(),
            );
        }
        match (&reglages.pair, &cle_du_pair) {
            (Some(pair), Some(cle)) => eprintln!(
                "asl-server : pair {} à {} — il tire d'ici, et l'on tire chez lui \
                 (docs/replication.md §2.1).",
                asl_cle::identifiant_de_racine(cle),
                pair.adresse,
            ),
            _ => eprintln!("asl-server : sans pair (--peer) : cette racine tourne seule."),
        }

        let balayeur = tokio::spawn(expirer_sans_fin(
            Arc::clone(&entrepot),
            reglages.retention_ms(),
        ));

        // **UN DÉFI PAR REQUÊTE, TIRÉ DU NOYAU.** Voir `entropie`.
        //
        // Un noyau qui refuse rend `None`, et surtout PAS un défi de repli : un
        // défi prévisible ne défie personne. Le client reçoit alors un `500`,
        // qui dit la vérité — la panne est de notre côté.
        let tirer = || entropie::un_defi().ok();
        let nommer = || entropie::un_identifiant().ok();
        // **LA POSTURE SE DIT AU DÉMARRAGE, ET FORT.** Un annuaire qui laisse
        // n'importe qui créer un compte doit l'annoncer dans son journal
        // d'exploitation : c'est là qu'on relit ce qu'on croyait avoir réglé.
        if reglages.politique == asl_auth::Politique::AttestationFacultative {
            eprintln!(
                "asl-server : ATTENTION — l'attestation de plate-forme n'est pas exigée. \
                 N'IMPORTE QUI peut créer un compte sur cet annuaire."
            );
        } else if reglages.apple.is_none() {
            eprintln!(
                "asl-server : l'attestation est exigée, mais aucune app Apple n'est \
                 configurée (--apple-app / --apple-environment) : AUCUN appareil ne \
                 pourra s'enrôler."
            );
        }
        // La racine d'Apple est la même pour tous ; seuls l'app et
        // l'environnement viennent de l'exploitant.
        let apple = reglages
            .apple
            .as_ref()
            .map(|reglage| asl_loop_tokio::h3::ConfigApple {
                identifiant_app: reglage.identifiant_app.as_str(),
                environnement: reglage.environnement,
            });
        // Le journal d'exploitation de la voie entre racines
        // (`replication.md` §8) : la même sortie que le reste.
        let dire = |ligne: &str| eprintln!("asl-server : {ligne}");
        // L'état vivant de la voie sortante : le tireur l'écrit, la ressource
        // `/v1/replication` le lit (§8).
        let etat_de_la_voie = Arc::new(EtatDeLaVoie::nouvelle());
        let voie = Voie {
            identite: identite.as_ref(),
            pair: cle_du_pair,
            journal: &dire,
            etat: reglages.pair.as_ref().map(|_| etat_de_la_voie.as_ref()),
        };
        let mut application = Annuaire::new(
            &entrepot,
            &tirer,
            &nommer,
            reglages.politique,
            apple,
            bail,
            voie,
        );

        // **LE TIREUR : LA CONNEXION SORTANTE** (`docs/replication.md` §2.1).
        // Quand `--peer` est réglé, une tâche ouvre une connexion vers le pair,
        // prouve les deux identités, et applique ce qu'il a écrit. Ce qu'elle
        // ferme ici — une clé révoquée, une annonce retirée — remonte par un
        // canal que la boucle draine (§3.3).
        let tireur = match (&reglages.pair, &identite) {
            (Some(pair), Some(_)) => {
                let (fermetures, entendre_fermetures) = tokio::sync::mpsc::unbounded_channel();
                application.ecouter_les_fermetures(entendre_fermetures);
                // La tâche possède sa propre clé d'identité : on la relit du
                // fichier plutôt que de la partager avec la voie servie.
                let chemin_identite = reglages
                    .identite
                    .as_ref()
                    .expect("--peer exige --identity-key");
                let tireur = Tireur {
                    entrepot: Arc::clone(&entrepot),
                    adresse: pair.adresse.clone(),
                    racines_pem: std::fs::read(&pair.ca)?,
                    identite: identite::lire_secrete(chemin_identite)?,
                    cle_du_pair: cle_du_pair.expect("la clé du pair est lue avec le pair"),
                    keepalive_us: reglages.keepalive_s.saturating_mul(1_000_000),
                    idle_us: reglages.inactivite_us(),
                    tirer_un_defi: Box::new(|| entropie::un_defi().ok()),
                    alea: Box::new(|| {
                        entropie::un_identifiant()
                            .map(|octets| u16::from_be_bytes([octets[0], octets[1]]))
                            .unwrap_or(0)
                    }),
                    journal: Box::new(|ligne| eprintln!("asl-server : {ligne}")),
                    fermetures,
                    plafond_recul_ms: reglages.keepalive_s.saturating_mul(1_000).max(1),
                    etat: Arc::clone(&etat_de_la_voie),
                };
                Some(tokio::spawn(tireur.tirer_sans_fin()))
            }
            _ => None,
        };

        let comptes = servir_quic(
            socket,
            tls,
            reglages.connexions_max,
            reglages.inactivite_us(),
            &mut application,
            arret(),
        )
        .await?;

        balayeur.abort();
        if let Some(tireur) = tireur {
            tireur.abort();
        }
        eprintln!(
            "asl-server : arrêté. {} connexions acceptées, {} refusées, \
             {} fermées, {} datagrammes jetés.",
            comptes.acceptees, comptes.refusees, comptes.fermees, comptes.jetes,
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

/// Frappe une clé d'identité, imprime ce que l'autre racine doit en savoir,
/// et s'arrête.
///
/// **C'est la clé PUBLIQUE qu'on porte chez l'autre racine** — le fichier
/// `<chemin>.pub`, à donner en `--peer-key` —, et l'identifiant `n-…` est ce
/// qu'on compare à l'œil : il se déduit de la clé, et deux racines qui
/// impriment le même parlent de la même clé.
fn nouvelle_identite(chemin: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let publique = identite::generer(chemin)?;
    println!(
        "clé privée   : {} (0600)\nclé publique : {} — {}\nidentifiant  : {}",
        chemin.display(),
        identite::chemin_public(chemin).display(),
        identite::en_hexadecimal(&publique.octets()),
        asl_cle::identifiant_de_racine(&publique),
    );
    Ok(())
}

/// Attend le signal d'arrêt.
///
/// **DEUX SIGNAUX, ET LE MÊME TRAITEMENT.** `SIGTERM` est ce que systemd envoie,
/// `SIGINT` ce qu'un exploitant tape. Les distinguer ferait deux chemins
/// d'extinction, et le moins emprunté serait le moins juste.
async fn arret() {
    let mut terme = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        Ok(quoi) => quoi,
        // **SANS SIGNAL, ON NE S'ARRÊTE PAS DE NOUS-MÊMES.** Rendre ici ferait
        // s'éteindre l'annuaire aussitôt démarré, ce qui est bien pire que de
        // devoir le tuer.
        Err(_) => return core::future::pending().await,
    };
    tokio::select! {
        _ = terme.recv() => {}
        Ok(()) = tokio::signal::ctrl_c() => {}
    }
    eprintln!("asl-server : signal reçu, extinction en deux temps (§5.2).");
}

/// Efface des deux journaux ce qui a passé l'âge, indéfiniment.
///
/// **Deux journaux, deux rétentions.** Celui des requêtes suit `--retention`
/// (C18, quatre-vingt-dix jours par défaut) ; celui des opérations suit
/// `asl_store::RETENTION_DES_OPERATIONS_MS` — trente jours, décidés par
/// `docs/replication.md` §5.4 et non réglables : au-delà, une racine absente
/// se reconstruit par instantané, et ce chiffre est ce qui le rend vrai.
///
/// # UNE FAUTE N'ARRÊTE PAS LE BALAYAGE
///
/// Un passage qui échoue est dit et l'on réessaiera dans une heure. S'arrêter
/// ferait cesser la rétention en silence, et un journal qui ne s'expire plus est
/// exactement ce que C18 interdit — **une archive comportementale permanente**.
async fn expirer_sans_fin(entrepot: Arc<Entrepot>, retention_ms: u64) {
    loop {
        let maintenant = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |ecoule| {
                u64::try_from(ecoule.as_millis()).unwrap_or(u64::MAX)
            });
        match entrepot.expirer_le_journal(maintenant.saturating_sub(retention_ms)) {
            Ok(0) => {}
            Ok(combien) => eprintln!("asl-server : {combien} entrées de journal expirées."),
            Err(quoi) => eprintln!("asl-server : l'expiration du journal a échoué : {quoi}"),
        }
        match entrepot.expirer_les_operations(
            maintenant.saturating_sub(asl_store::RETENTION_DES_OPERATIONS_MS),
        ) {
            Ok(0) => {}
            Ok(combien) => eprintln!("asl-server : {combien} opérations retirées du journal."),
            Err(quoi) => {
                eprintln!("asl-server : l'expiration du journal d'opérations a échoué : {quoi}")
            }
        }
        tokio::time::sleep(EXPIRATION_TOUTES_LES).await;
    }
}
