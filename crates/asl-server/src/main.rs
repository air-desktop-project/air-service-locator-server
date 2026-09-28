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
    Annuaire, Confiance, EtatDeLaVoie, Tireur, configuration_d_annuaire, refuser_root,
    reveil::Reveilleur, servir_quic,
};
use asl_store::{Entrepot, RACINE_SANS_IDENTITE};

use crate::reglages::{Administration, Inscription, Invite, Oubli, Reglages, USAGE};

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
    // **LE CERTIFICAT D'IDENTITÉ D'UNE CLÉ QU'ON A DÉJÀ** (décision 55) : il
    // se déduit d'elle, on l'imprime en PEM, on s'arrête. Pour l'inspecter, ou
    // pour une clé frappée avant 0.29.0 — le démarrage, lui, le refrappe seul.
    if let Some(rang) = arguments
        .iter()
        .position(|quoi| quoi == "--identity-certificate")
    {
        let Some(chemin) = arguments.get(rang.saturating_add(1)) else {
            eprint!("{USAGE}");
            return Err("--identity-certificate attend le chemin d'une clé d'identité".into());
        };
        let secrete = identite::lire_secrete(std::path::Path::new(chemin))?;
        print!("{}", identite::certificat_pem(&secrete));
        return Ok(());
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
    // **NOMMER OU RETIRER UN ADMINISTRATEUR DES RACINES** (`modele.md`
    // §2.12) : le même geste en ligne, la même clé, un compte de plus.
    if let Some(administration) =
        Reglages::geste_d_administration(&arguments).inspect_err(|_| eprint!("{USAGE}"))?
    {
        return administrer(&administration);
    }
    // **UN ANNUAIRE LOCAL SE PRÉSENTE AUX RACINES** (`annuaires.md` §4.1) :
    // un geste en ligne aussi, sous la clé d'identité de cet annuaire.
    if let Some(inscription) =
        Reglages::geste_d_inscription(&arguments).inspect_err(|_| eprint!("{USAGE}"))?
    {
        return inscrire(&inscription);
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
    let identite = identite::lire_secrete(&reglages.identite)?;
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
    // **L'ENTREPÔT ESTAMPILLE SOUS CETTE IDENTITÉ**, et ré-estampille ce
    // qu'une version d'avant 0.34.0 avait écrit sans clé, sous
    // `asl_store::RACINE_SANS_IDENTITE`, au premier démarrage (§11.4).
    let racine = asl_cle::identifiant_de_racine(&identite.publique());
    // **LES RACINES ANDROID SE LISENT AVANT L'ENTREPÔT, ELLES AUSSI** : un
    // PEM absent ou vide doit se dire avant d'avoir verrouillé une base. Ce
    // sont des fichiers de l'exploitant (C19), jamais des constantes.
    let racines_android = reglages
        .android
        .as_ref()
        .map(|android| racines_android(&android.racines))
        .transpose()?;

    // **LES RACINES DE POUSSÉE AUSSI** (`--push-roots`) : un fichier absent,
    // illisible ou sans autorité se dit avant qu'une base soit verrouillée.
    let racines_de_poussee = reglages
        .racines_de_poussee
        .as_ref()
        .map(|chemin| {
            std::fs::read(chemin)
                .map_err(|quoi| format!("--push-roots {} : {quoi}", chemin.display()))
                .map(|pem| (chemin.clone(), pem))
        })
        .transpose()?;

    let entrepot = Arc::new(Entrepot::ouvrir(&reglages.entrepot, racine)?);
    // **CE QUE L'ANNUAIRE PRÉSENTE À LA POIGNÉE DE MAIN** (décisions 53, 55,
    // 58) : son certificat d'identité, frappé ici depuis la clé d'identité —
    // aucun fichier à tenir, aucune date à renouveler —, et rien d'autre.
    let tls = Arc::new(configuration_d_annuaire(&identite)?);
    let socket = socket::ecouter(reglages.port)?;
    let ou = socket.local_addr()?;

    let execution = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    execution.block_on(async move {
        let socket = tokio::net::UdpSocket::from_std(socket)?;
        eprintln!(
            "asl-server : TLS — l'annuaire présente son certificat d'identité, et lui seul \
             (décisions 53, 58)."
        );
        eprintln!(
            "asl-server : écoute sur {ou} (double pile), entrepôt {}, \
             bail {} s / {} s, rétention {} jours",
            reglages.entrepot.display(),
            bail.keepalive_secondes(),
            bail.inactivite_secondes(),
            reglages.retention_jours,
        );

        // **L'IDENTITÉ SE DIT AU DÉMARRAGE** : c'est sous elle que l'annuaire
        // estampille, et c'est elle qu'il présente.
        eprintln!(
            "asl-server : identité {}, clé publique {} — compteur à {}.",
            entrepot.racine(),
            identite::en_hexadecimal(&identite.publique().octets()),
            entrepot.compteur().unwrap_or(0),
        );
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
        // **ET LE PREMIER DOMAINE DES COMPTES D'HIER** (`modele.md` §2.11) :
        // une fois, à la première ouverture par un binaire qui connaît les
        // domaines — déduit, donc le même sur l'autre racine.
        if entrepot.groupes_deduits() > 0 {
            eprintln!(
                "asl-server : groupes — {} groupe(s) déduit(s) nés pour les comptes et les \
                 domaines d'avant les groupes (personnels, d'administrateurs).",
                entrepot.groupes_deduits(),
            );
        }
        if entrepot.premiers_domaines() > 0 {
            eprintln!(
                "asl-server : domaines — {} compte(s) d'avant les domaines ont reçu leur premier \
                 domaine, déduit de leur identifiant.",
                entrepot.premiers_domaines(),
            );
        }
        // **ET LES AUTORISATIONS D'HIER, DEVENUES DES DROITS** (décision 41) :
        // une fois, sous le même `g-…`, au même résultat sur l'autre racine.
        if entrepot.autorisations_converties() > 0 {
            eprintln!(
                "asl-server : droits — {} autorisation(s) d'hier converties en droits `voir` + \
                 `localiser` au groupe personnel du bénéficiaire, sous le même identifiant.",
                entrepot.autorisations_converties(),
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
        //
        // **UN ANNUAIRE LOCAL N'A PAS DE POSTURE À DIRE** (décision 62) : il ne
        // crée aucun compte, quelle que soit `--attestation`, que l'unité
        // systemd passe toujours et qu'on accepte donc sans en rien faire.
        // Annoncer « n'importe qui peut créer un compte » serait faux.
        if reglages.federation.is_some() {
            eprintln!(
                "asl-server : annuaire LOCAL — aucun compte ne se crée ici, et rien de ce \
                 qui vit aux racines (comptes, appareils, domaines, droits) ne s'y lit ni \
                 ne s'y écrit : ces verbes sont renvoyés aux racines (421). --attestation \
                 est sans effet."
            );
        } else if reglages.politique == asl_auth::Politique::AttestationFacultative {
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
            identite: Some(&identite),
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

        // **LE RÉVEILLEUR, S'IL Y A DES RACINES** (`protocole.md` §2.2). Une
        // tâche à part : la boucle lui passe le compte bénéficiaire de chaque
        // autorisation écrite ICI, et c'est elle qui résout, se connecte et
        // attend. Sans `--push-roots`, rien ne part — et c'est dit.
        let reveilleur = match &racines_de_poussee {
            Some((chemin, pem)) => {
                let reveilleur = Reveilleur::nouveau(
                    Arc::clone(&entrepot),
                    pem,
                    Box::new(|ligne| eprintln!("asl-server : {ligne}")),
                )
                .map_err(|quoi| format!("--push-roots {} : {quoi}", chemin.display()))?;
                eprintln!(
                    "asl-server : notifications — {} racine(s) de poussée épinglée(s) \
                     (--push-roots {}) : une autorisation accordée ICI réveille les appareils \
                     du bénéficiaire, d'un POST vide vers leur point UnifiedPush (TLS 1.3, \
                     cinq secondes, une tentative).",
                    reveilleur.racines(),
                    chemin.display(),
                );
                let (reveil, entendre_reveil) = tokio::sync::mpsc::unbounded_channel();
                application.reveiller_par(reveil);
                Some(tokio::spawn(reveilleur.reveiller_sans_fin(entendre_reveil)))
            }
            None => {
                eprintln!(
                    "asl-server : sans --push-roots : AUCUNE notification ne part — ni \
                     résolution, ni connexion. GET /v1/nouvelles reste servi."
                );
                None
            }
        };

        // **LE TIREUR : LA CONNEXION SORTANTE** (`docs/replication.md` §2.1).
        // Quand `--peer` est réglé, une tâche ouvre une connexion vers le pair,
        // prouve les deux identités, et applique ce qu'il a écrit. Ce qu'elle
        // ferme ici — une clé révoquée, une annonce retirée — remonte par un
        // canal que la boucle draine (§3.3).
        //
        // **UN SEUL CANAL DE FERMETURES** : `Annuaire::fermetures` remplace le
        // précédent à chaque appel, et le tireur comme les fédérateurs y
        // déposent — on le crée une fois, et chacun en tient un clone.
        let fermetures = (reglages.pair.is_some() || reglages.federation.is_some())
            .then(|| application.fermetures());
        let tireur = match &reglages.pair {
            Some(pair) => {
                let fermetures = fermetures.clone().expect("créé avec le pair");
                let tireur = Tireur {
                    entrepot: Arc::clone(&entrepot),
                    adresse: pair.adresse.clone(),
                    // **LE PAIR EST CRU PAR SA CLÉ, ET PAR RIEN D'AUTRE**
                    // (décisions 53, 58).
                    confiance: Confiance::par_identite(&[
                        cle_du_pair.expect("la clé du pair est lue avec le pair")
                    ]),
                    // La tâche possède sa propre clé d'identité : on la relit
                    // du fichier plutôt que de la partager avec la voie servie.
                    identite: identite::lire_secrete(&reglages.identite)?,
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
            None => None,
        };

        // **LES FÉDÉRATEURS : CET ANNUAIRE EST LOCAL** (`protocole.md` §3 ter,
        // 0.28.0). Une tâche par racine : elle ouvre, prouve notre clé
        // d'identité, tire les machines de nos domaines et pousse l'état de
        // leurs services — que la boucle publie pour elles.
        let mut federateurs = Vec::new();
        if let Some(federation) = &reglages.federation {
            let publies = Arc::new(asl_loop_tokio::ServicesPublies::nouvelle());
            application.publier_l_etat_dans(Arc::clone(&publies));
            eprintln!(
                "asl-server : annuaire LOCAL — fédère vers {} racine(s) : {}.",
                federation.racines.len(),
                federation
                    .racines
                    .iter()
                    .map(|cible| cible.adresse.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            // **OÙ L'ON NOUS JOINT** (décisions 57, 64) : fixes, ils sont
            // posés une fois ; détectés, une tâche les relit à la cadence de
            // la fédération, et chaque fédérateur pousse le changement aussitôt.
            let locateurs = Arc::new(match &federation.auto {
                None => asl_loop_tokio::LocateursPublies::fixes(federation.locateurs.clone()),
                Some(_) => asl_loop_tokio::LocateursPublies::inconnus(),
            });
            if let Some(auto) = &federation.auto {
                eprintln!(
                    "asl-server : localisateur DÉTECTÉ — l'adresse IPv6 globale stable {}, \
                     port {}, relue toutes les {} s.",
                    auto.interface.as_deref().map_or_else(
                        || "de l'interface de la route par défaut".to_owned(),
                        |nom| format!("de {nom}")
                    ),
                    ou.port(),
                    asl_loop_tokio::federation::CADENCE_MS / 1_000,
                );
                let detecteur = asl_loop_tokio::localisateur::Detecteur {
                    interface: auto.interface.clone(),
                    // Le port où l'on ÉCOUTE vraiment — `--port 0` en tire un.
                    port: ou.port(),
                    fixes: federation.locateurs.clone(),
                    publies: Arc::clone(&locateurs),
                    lire: Box::new(asl_loop_tokio::localisateur::lire_le_noyau),
                    journal: Box::new(|ligne| eprintln!("asl-server : {ligne}")),
                    cadence_ms: asl_loop_tokio::federation::CADENCE_MS,
                };
                // Un premier tour AVANT les fédérateurs : la première ouverture
                // de chaque voie publie déjà l'adresse, sans attendre un tour.
                let mut souvenir = asl_loop_tokio::localisateur::Souvenir::default();
                detecteur.un_tour(&mut souvenir);
                federateurs.push(tokio::spawn(detecteur.continuer_sans_fin(souvenir)));
            }
            for cible in &federation.racines {
                let adresse = &cible.adresse;
                let federateur = asl_loop_tokio::Federateur {
                    entrepot: Arc::clone(&entrepot),
                    adresse: adresse.clone(),
                    confiance: match cible.identite {
                        // `<locateur>=<n-…>` : l'identité est dite.
                        Some(identite) => Confiance::par_identifiants(&[identite]),
                        None => confiance_embarquee(adresse, "--federation <locateur>=<n-…>")?,
                    },
                    identite: identite::lire_secrete(&reglages.identite)?,
                    keepalive_us: reglages.keepalive_s.saturating_mul(1_000_000),
                    idle_us: reglages.inactivite_us(),
                    cadence_ms: asl_loop_tokio::federation::CADENCE_MS,
                    publies: Arc::clone(&publies),
                    fermetures: fermetures.clone().expect("créé avec la fédération"),
                    alea: Box::new(|| {
                        entropie::un_identifiant()
                            .map(|octets| u16::from_be_bytes([octets[0], octets[1]]))
                            .unwrap_or(0)
                    }),
                    journal: Box::new(|ligne| eprintln!("asl-server : {ligne}")),
                    plafond_recul_ms: reglages.keepalive_s.saturating_mul(1_000).max(1),
                    locateurs: Arc::clone(&locateurs),
                };
                federateurs.push(tokio::spawn(federateur.federer_sans_fin()));
            }
        }

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
        if let Some(reveilleur) = reveilleur {
            reveilleur.abort();
        }
        for federateur in federateurs {
            federateur.abort();
        }
        eprintln!(
            "asl-server : arrêté. {} connexions acceptées, {} refusées, \
             {} fermées, {} datagrammes jetés.",
            comptes.acceptees, comptes.refusees, comptes.fermees, comptes.jetes,
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

/// Le locateur d'un geste d'exploitant (`--invite`, `--add-admin`,
/// `--register`…) et ce qu'on croit au bout : `<locateur>=<n-…>` dit
/// l'identité attendue, comme `--federation` ; un locateur seul se reconnaît
/// dans la liste embarquée des racines.
fn geste_vers(texte: &str) -> Result<(String, Confiance), String> {
    if let Some((adresse, identite)) = texte.split_once('=') {
        let identite = asl_id::Identifiant::analyser(identite)
            .ok()
            .filter(|quoi| quoi.genre() == asl_id::Genre::Annuaire)
            .ok_or_else(|| {
                format!("{texte} : « {identite} » n'est pas un identifiant d'annuaire (n-…)")
            })?;
        return Ok((adresse.to_owned(), Confiance::par_identifiants(&[identite])));
    }
    Ok((
        texte.to_owned(),
        confiance_embarquee(texte, "--directory <locateur>=<n-…>")?,
    ))
}

/// Ce qu'on croit de l'annuaire au bout de ce locateur quand l'identité n'est
/// pas dite (`protocole.md` §0) : celles que la liste embarquée des racines
/// lui associe.
///
/// **Rien à croire est une faute de démarrage**, dite avec le locateur et ce
/// qu'il faut écrire à la place : un locateur hors de la liste ne désigne
/// personne — un nom, en particulier, ne dit jamais qui l'on trouvera (C20).
fn confiance_embarquee(locateur: &str, forme: &str) -> Result<Confiance, String> {
    let identites = asl_loop_tokio::racines::identites_du_locateur(locateur);
    if identites.is_empty() {
        return Err(format!(
            "{locateur} : aucune identité connue — ce n'est pas un locateur de la liste \
             embarquée des racines ; dites qui l'on doit y trouver : {forme}"
        ));
    }
    Ok(Confiance::par_identite(&identites))
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
        "clé privée   : {} (0600)\nclé publique : {} — {}\nidentifiant  : {}\ncertificat   : {} (d'identité, auto-signé — décision 55)",
        chemin.display(),
        identite::chemin_public(chemin).display(),
        identite::en_hexadecimal(&publique.octets()),
        asl_cle::identifiant_de_racine(&publique),
        identite::chemin_certificat(chemin).display(),
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
        "  asl-server --invite --directory <hôte:port>=<n-…> --operator-secret {}",
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
    let (adresse, racines) = geste_vers(&invite.annuaire)?;
    let secrete = identite::lire_secrete(&invite.secrete)?;

    // Un geste ne dure qu'un aller-retour : un fil suffit, là où l'annuaire
    // qui sert en veut autant que la machine en a.
    let execution = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let invitation = execution
        .block_on(asl_loop_tokio::exploitant::emettre(
            &adresse, &racines, &secrete,
        ))
        .map_err(|quoi| format!("{} : {quoi}", invite.annuaire))?;

    println!("{}", invitation.code);
    eprintln!(
        "asl-server : code émis, valable jusqu'à {} — il ne sera pas réaffiché.",
        invitation.expire_a
    );
    Ok(())
}

/// Nomme ou retire un administrateur des racines sur un annuaire EN MARCHE,
/// le dit, et s'arrête — le geste d'[`inviter`], sans secret à imprimer.
fn administrer(administration: &Administration) -> Result<(), Box<dyn std::error::Error>> {
    let joindre = &administration.joindre;
    let (adresse, racines) = geste_vers(&joindre.annuaire)?;
    let secrete = identite::lire_secrete(&joindre.secrete)?;
    let execution = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    execution
        .block_on(asl_loop_tokio::exploitant::changer_les_administrateurs(
            &adresse,
            &racines,
            &secrete,
            administration.compte,
            administration.nomme,
        ))
        .map_err(|quoi| format!("{} : {quoi}", joindre.annuaire))?;
    eprintln!(
        "asl-server : {} {} sur {} — l'autre racine l'apprendra par la réplication.",
        administration.compte,
        if administration.nomme {
            "nommé administrateur des racines"
        } else {
            "retiré des administrateurs des racines"
        },
        adresse,
    );
    Ok(())
}

/// Présente cet annuaire local à une racine — ou relit son inscription —,
/// imprime l'état, et s'arrête.
///
/// L'état va sur la sortie standard, seul : `en attente`, `acceptée`,
/// `refusée`, `retirée`. Le reste — le `n-…` de la clé, l'annuaire — sur la
/// sortie d'erreur.
fn inscrire(inscription: &Inscription) -> Result<(), Box<dyn std::error::Error>> {
    let (adresse, racines) = geste_vers(&inscription.racine)?;
    let identite_secrete = identite::lire_secrete(&inscription.identite)?;
    let execution = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let lu = match &inscription.code {
        Some(code) => execution.block_on(asl_loop_tokio::inscription::presenter(
            &adresse,
            &racines,
            &identite_secrete,
            code,
        )),
        None => execution.block_on(asl_loop_tokio::inscription::relire(
            &adresse,
            &racines,
            &identite_secrete,
        )),
    }
    .map_err(|quoi| format!("{} : {quoi}", inscription.racine))?;
    println!("{}", lu.etat);
    eprintln!(
        "asl-server : annuaire local {} (membre {}) — inscription {} sur {}.",
        lu.annuaire, lu.membre, lu.etat, inscription.racine,
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
