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

use crate::reglages::{Invite, Oubli, Reglages, USAGE};

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
    // **FRAPPER LA CLÉ DE L'EXPLOITANT EST LE MÊME GESTE**, et volontairement
    // le même code : une paire Ed25519, la privée en 0600, la publique à
    // côté. Ce qui change est ce qu'on en dit — un exploitant n'a pas de
    // `n-…`, et ce qu'il doit faire du fichier n'est pas ce qu'on fait d'une
    // clé de racine (`protocole.md` §2.2).
    if let Some(rang) = arguments
        .iter()
        .position(|quoi| quoi == "--new-operator-key")
    {
        let Some(chemin) = arguments.get(rang.saturating_add(1)) else {
            eprint!("{USAGE}");
            return Err("--new-operator-key attend un chemin".into());
        };
        return nouvelle_cle_d_exploitant(std::path::Path::new(chemin));
    }
    // **ÉMETTRE UNE INVITATION EST UN GESTE EN LIGNE**, et c'est ce qui le
    // distingue de tous les autres : il parle à un annuaire QUI TOURNE
    // (`protocole.md` §2.2). Il ne veut ni entrepôt, ni certificat de
    // serveur, ni posture — et il n'a aucune raison de s'exécuter sur un
    // banc.
    if let Some(invite) =
        Reglages::geste_d_invitation(&arguments).inspect_err(|_| eprint!("{USAGE}"))?
    {
        return inviter(&invite);
    }
    // **EFFACER UN COMPTE HORS LIGNE EST UN GESTE AUSSI** (`modele.md` §2.1,
    // `replication.md` §8) : l'entrepôt, l'identité si on l'a, et rien
    // d'autre — ni certificat, ni socket, ni posture.
    if let Some(oubli) = Reglages::geste_d_oubli(&arguments).inspect_err(|_| eprint!("{USAGE}"))? {
        return oublier(&oubli);
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
    // **LA CLÉ DE L'EXPLOITANT SE LIT ICI, COMME CELLE DU PAIR** : un fichier
    // absent ou mal formé doit se dire avant d'avoir verrouillé une base. Sa
    // partie PRIVÉE ne vient jamais sur le banc (`protocole.md` §2.2).
    let cle_de_l_exploitant = reglages
        .exploitant
        .as_ref()
        .map(|chemin| identite::lire_publique(chemin))
        .transpose()?;
    // **SANS CLÉ, SEIZE ZÉROS — ET C'EST DIT AU DÉMARRAGE.** Une clé générée
    // en silence aurait été pire (§8) : une clé que personne n'a copiée nulle
    // part. `asl_store::RACINE_SANS_IDENTITE` dit le reste, et l'entrepôt
    // ré-estampille ce qui a été écrit sous elle au premier démarrage avec
    // une clé (§11.4).
    let racine = identite.as_ref().map_or(RACINE_SANS_IDENTITE, |cle| {
        asl_cle::identifiant_de_racine(&cle.publique())
    });
    // **LES RACINES ANDROID SE LISENT AVANT L'ENTREPÔT, ELLES AUSSI** : un
    // PEM absent ou vide doit se dire avant d'avoir verrouillé une base. Ce
    // sont des fichiers de l'exploitant (C19), jamais des constantes.
    let racines_android = reglages
        .android
        .as_ref()
        .map(|android| racines_android(&android.racines))
        .transpose()?;

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
        // **ET LA REPRISE DES DATES AUSSI** (`modele.md` §2.2) : les appareils
        // déjà révoqués ont reçu la date de ce démarrage pour `révoqué le`,
        // et c'est de là que la règle des orphelins comptera pour eux.
        if entrepot.dates_de_reprise() > 0 {
            eprintln!(
                "asl-server : entrepôt repris au format des dates — {} appareil(s) déjà \
                 révoqué(s) ont reçu la date de cette reprise pour « révoqué le » ; le journal \
                 d'opérations repart vide, l'autre racine s'amorcera par instantané.",
                entrepot.dates_de_reprise(),
            );
        }
        // **LA RÈGLE DES ORPHELINS SE DIT AU DÉMARRAGE**, et « jamais » aussi
        // (`replication.md` §8) : c'est là qu'on relit ce qu'on croyait avoir
        // réglé.
        match reglages.orphelins_ms() {
            Some(_) => eprintln!(
                "asl-server : orphelins (--orphans) : un compte dont tous les appareils sont \
                 révoqués depuis plus de {} jours est effacé, cause orphelin.",
                reglages.orphelins_jours,
            ),
            None => eprintln!(
                "asl-server : orphelins (--orphans 0) : cette racine n'efface JAMAIS un compte \
                 d'elle-même — seuls le titulaire et --forget le font."
            ),
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
        } else if reglages.politique == asl_auth::Politique::Invitation {
            eprintln!(
                "asl-server : posture `invitation` — personne n'ouvre de compte sans un code \
                 que vous avez émis (POST /v1/invitations), et une invitation vit {} heure(s). \
                 Aucun fabricant n'est dans la boucle.",
                reglages.invitation_ttl_s.saturating_div(3_600),
            );
        } else if reglages.apple.is_none() && reglages.android.is_none() {
            eprintln!(
                "asl-server : l'attestation est exigée, mais aucune plate-forme n'est \
                 configurée (--apple-app / --apple-environment, --android-roots / \
                 --android-app / --android-signer) : AUCUN appareil ne pourra s'enrôler."
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
        // **LES RACINES ANDROID SE DISENT AU DÉMARRAGE**, par leur nombre :
        // c'est là qu'on relit ce qu'on croyait avoir épinglé.
        let android = reglages
            .android
            .as_ref()
            .zip(racines_android.as_deref())
            .map(|(reglage, racines)| {
                eprintln!(
                    "asl-server : attestation Android — {} racine(s) épinglée(s), \
                     paquet {}, signataire {}.",
                    racines.len(),
                    reglage.paquet,
                    identite::en_hexadecimal(&reglage.signataire),
                );
                asl_loop_tokio::h3::ConfigAndroid {
                    racines,
                    paquet: reglage.paquet.as_str(),
                    signataire: reglage.signataire,
                }
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
            exploitant: cle_de_l_exploitant,
            journal: &dire,
            etat: reglages.pair.as_ref().map(|_| etat_de_la_voie.as_ref()),
        };
        let mut application = Annuaire::new(
            &entrepot,
            &tirer,
            &nommer,
            reglages.politique,
            asl_loop_tokio::h3::Attestations { apple, android },
            bail,
            voie,
        );
        // **LA RÈGLE DES ORPHELINS, SI ELLE EST RÉGLÉE** — et `--orphans 0`
        // ne la règle pas : la racine n'efface alors jamais d'elle-même.
        if let Some(delai) = reglages.orphelins_ms() {
            application.effacer_les_orphelins_apres(delai);
        }
        application.invitations_vivent(reglages.invitation_ttl_s.saturating_mul(1_000));

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

/// Lit les racines d'attestation Android, fichier par fichier.
///
/// Chaque fichier est nommé dans sa faute : un exploitant qui a posé trois PEM
/// doit savoir lequel ne se lit pas.
fn racines_android(chemins: &[std::path::PathBuf]) -> Result<Vec<Vec<u8>>, String> {
    let mut racines = Vec::new();
    for chemin in chemins {
        let pem = std::fs::read(chemin)
            .map_err(|quoi| format!("--android-roots {} : {quoi}", chemin.display()))?;
        let lues = asl_loop_tokio::racines_depuis_pem(&pem)
            .map_err(|quoi| format!("--android-roots {} : {quoi}", chemin.display()))?;
        racines.extend(lues);
    }
    Ok(racines)
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

/// Frappe la clé de l'exploitant, dit où poser chaque moitié, et s'arrête.
///
/// # LA MÊME PAIRE QU'UNE IDENTITÉ, ET UN USAGE QUI N'A RIEN À VOIR
///
/// Les octets sont les mêmes — Ed25519, trente-deux bruts, la privée en 0600
/// et la publique à côté —, et c'est pourquoi le geste réemploie `identite`.
/// Ce qui diffère est le mode d'emploi : une clé de racine se copie vers
/// l'autre racine comme `--peer-key`, celle-ci se copie vers **les deux**
/// comme `--operator-key`, et sa moitié privée ne va sur aucune des deux.
fn nouvelle_cle_d_exploitant(chemin: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let publique = identite::generer(chemin)?;
    let public = identite::chemin_public(chemin);
    println!(
        "clé privée   : {} (0600) — elle reste ICI, sur aucun banc",
        chemin.display()
    );
    println!(
        "clé publique : {} — {}",
        public.display(),
        identite::en_hexadecimal(&publique.octets()),
    );
    println!();
    println!("Posez la clé PUBLIQUE sur les DEUX racines, la même, et réglez-les :");
    println!(
        "  --attestation invitation --operator-key {}",
        public.display()
    );
    println!("Puis émettez depuis cette machine :");
    println!(
        "  asl-server --invite --directory <hôte:port> --ca <racine.crt> --operator-secret {}",
        chemin.display(),
    );
    Ok(())
}

/// Émet une invitation sur un annuaire en marche, imprime le code, et s'arrête.
///
/// # LE CODE S'IMPRIME, ET NE SE RANGE NULLE PART
///
/// C'est le seul secret que l'exploitant tient (`protocole.md` §2.2), et
/// l'annuaire n'en garde que l'empreinte : il n'est rendu qu'une fois. On
/// l'écrit donc sur la sortie standard — que l'exploitant lit, copie et
/// oublie — et jamais dans un fichier, jamais dans un message d'erreur.
/// L'échéance va sur la sortie d'erreur, pour qu'un `asl-server --invite …
/// | pbcopy` ne copie que le code.
fn inviter(invite: &Invite) -> Result<(), Box<dyn std::error::Error>> {
    let racines =
        std::fs::read(&invite.ca).map_err(|quoi| format!("{} : {quoi}", invite.ca.display()))?;
    let secrete = identite::lire_secrete(&invite.secrete)?;

    // Un geste ne dure qu'un aller-retour : un fil suffit, là où l'annuaire
    // qui sert en veut autant que la machine en a.
    let execution = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let invitation = execution
        .block_on(asl_loop_tokio::exploitant::emettre(
            &invite.annuaire,
            &racines,
            &secrete,
        ))
        .map_err(|quoi| format!("{} : {quoi}", invite.annuaire))?;

    println!("{}", invitation.code);
    eprintln!(
        "asl-server : code émis, valable jusqu'à {} — il ne sera pas réaffiché.",
        invitation.expire_a
    );
    Ok(())
}

/// Efface ce compte, hors ligne, dit ce qui est parti, et s'arrête.
///
/// # ENTREPÔT ARRÊTÉ, ET C'EST `redb` QUI LE TIENT
///
/// Le daemon prend un verrou exclusif sur le fichier (`File::try_lock`) à
/// l'ouverture, et `redb` refuse d'ouvrir un fichier qu'un autre processus
/// tient — `DatabaseAlreadyOpen`. C'est ce refus qu'on traduit : le geste ne
/// s'exécute pas pendant que l'annuaire sert, et il le dit plutôt que
/// d'attendre. **Aucune connexion à fermer** : l'entrepôt étant arrêté, la
/// clé d'un appareil ou d'une machine de ce compte n'existe plus au
/// redémarrage, et sa connexion rend `401`.
///
/// **L'opération `compte-efface` est journalisée** dans le journal
/// d'opérations, pour que l'autre racine l'applique au prochain rattrapage —
/// sous l'identité de `--identity-key` si elle est donnée, sous seize zéros
/// sinon, que le daemon fera passer sous la sienne au démarrage suivant.
fn oublier(oubli: &Oubli) -> Result<(), Box<dyn std::error::Error>> {
    let racine = match &oubli.identite {
        Some(chemin) => asl_cle::identifiant_de_racine(&identite::lire_secrete(chemin)?.publique()),
        None => RACINE_SANS_IDENTITE,
    };
    let entrepot = match Entrepot::ouvrir(&oubli.entrepot, racine) {
        Ok(entrepot) => entrepot,
        Err(quoi) if quoi.entrepot_tenu() => {
            return Err(format!(
                "l'entrepôt {} est tenu par un autre processus — l'annuaire tourne ? \
                 --forget s'exécute entrepôt arrêté (systemctl stop asl-server), et jamais \
                 pendant qu'il sert.",
                oubli.entrepot.display()
            )
            .into());
        }
        Err(quoi) => return Err(quoi.into()),
    };
    let maintenant = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |ecoule| {
            u64::try_from(ecoule.as_millis()).unwrap_or(u64::MAX)
        });
    match entrepot.effacer_compte(oubli.compte, asl_registre::Cause::Exploitant, maintenant)? {
        Some(asl_store::Efface::Fait(retrait)) => {
            eprintln!(
                "asl-server : compte {} effacé, cause exploitant — {} appareil(s), {} machine(s), \
                 {} service(s), {} autorisation(s) retirés{} ; l'opération est au journal, \
                 l'autre racine l'appliquera au prochain rattrapage.",
                oubli.compte,
                retrait.appareils,
                retrait.machines,
                retrait.services,
                retrait.autorisations,
                if retrait.alias {
                    ", alias libéré"
                } else {
                    ""
                },
            );
            if oubli.identite.is_none() {
                eprintln!(
                    "asl-server : sans --identity-key, l'opération est estampillée \
                     {RACINE_SANS_IDENTITE} ; le daemon la fera passer sous son identité au \
                     prochain démarrage."
                );
            }
            Ok(())
        }
        Some(asl_store::Efface::Deja(marque)) => {
            eprintln!(
                "asl-server : compte {} déjà effacé le {} (ms d'époque), cause {} : rien n'a été écrit.",
                oubli.compte, marque.le, marque.cause,
            );
            Ok(())
        }
        None => Err(format!(
            "compte {} inconnu de cet entrepôt : rien n'a été écrit.",
            oubli.compte
        )
        .into()),
    }
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
