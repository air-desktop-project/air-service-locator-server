//! L'annuaire : le binaire qui assemble, et qui ne décide de rien.
//!
//! # CE QU'IL FAIT, DANS L'ORDRE, ET POURQUOI CET ORDRE
//!
//! 1. **Il refuse de tourner en root** (C8). En premier, avant même de lire ses
//!    arguments : ce qui est refusé doit l'être avant d'avoir ouvert quoi que ce
//!    soit.
//! 2. Il lit ses réglages.
//! 3. Il ouvre l'entrepôt, **puis** lit le certificat et la clé. Dans cet ordre
//!    parce qu'une base verrouillée par une autre instance est la panne la plus
//!    probable, et qu'on préfère l'apprendre avant d'avoir lu des secrets.
//! 4. Il ouvre la socket en double pile.
//! 5. Il lance l'expiration du journal, puis l'écoute.
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
mod reglages;
mod socket;

use std::sync::Arc;

use asl_loop_tokio::{
    Annuaire, configuration_tls, liaison_du_certificat, refuser_root, servir_quic,
};
use asl_store::Entrepot;

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

/// Tout ce qui peut échouer, rassemblé pour que `main` reste lisible.
fn demarrer() -> Result<(), Box<dyn std::error::Error>> {
    // **EN PREMIER** : voir l'en-tête, et `asl-loop-tokio::privileges`.
    refuser_root()?;

    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments
        .iter()
        .any(|quoi| quoi == "--aide" || quoi == "-h")
    {
        print!("{USAGE}");
        return Ok(());
    }
    let reglages = Reglages::depuis(&arguments).inspect_err(|_| eprint!("{USAGE}"))?;

    let entrepot = Arc::new(Entrepot::ouvrir(&reglages.entrepot)?);
    let chaine = std::fs::read(&reglages.certificat)?;
    let cle = std::fs::read(&reglages.cle)?;
    let tls = Arc::new(configuration_tls(&chaine, &cle)?);
    // **APRÈS `configuration_tls`, ET PAS AVANT** : elle a déjà refusé une
    // chaîne illisible, donc l'absence de certificat de tête est ici
    // impossible — et le message le dit plutôt que de la taire.
    let liaison =
        liaison_du_certificat(&chaine).ok_or("la chaîne ne porte aucun certificat lisible")?;

    let socket = socket::ecouter(reglages.port)?;
    let ou = socket.local_addr()?;

    let execution = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    execution.block_on(async move {
        let socket = tokio::net::UdpSocket::from_std(socket)?;
        eprintln!(
            "asl-server : écoute sur {ou} (double pile), entrepôt {}, \
             rétention {} jours",
            reglages.entrepot.display(),
            reglages.retention_jours,
        );

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
        let mut application = Annuaire::new(&entrepot, liaison, &tirer, &nommer);
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
        eprintln!(
            "asl-server : arrêté. {} connexions acceptées, {} refusées, \
             {} fermées, {} datagrammes jetés.",
            comptes.acceptees, comptes.refusees, comptes.fermees, comptes.jetes,
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    })
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

/// Efface du journal ce qui a passé l'âge, indéfiniment (C18).
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
        let avant = maintenant.saturating_sub(retention_ms);
        match entrepot.expirer_le_journal(avant) {
            Ok(0) => {}
            Ok(combien) => eprintln!("asl-server : {combien} entrées de journal expirées."),
            Err(quoi) => eprintln!("asl-server : l'expiration du journal a échoué : {quoi}"),
        }
        tokio::time::sleep(EXPIRATION_TOUTES_LES).await;
    }
}
