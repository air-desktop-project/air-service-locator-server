//! Le tireur : la connexion SORTANTE vers l'autre racine, et l'application de
//! ce qu'elle a écrit (`docs/replication.md` §2.1, §2.3, §3).
//!
//! # CHAQUE RACINE OUVRE, ET LIT SANS FIN CE QUE L'AUTRE A ÉCRIT
//!
//! Le côté SERVI est dans [`crate::h3`] depuis la tranche 2 : les deux preuves,
//! les deux flux, l'exigence qui les garde. Ici est le côté qui TIRE. Quand
//! `--peer` est réglé, une tâche ouvre une connexion QUIC vers le pair, prouve
//! son identité de racine, vérifie celle du pair, puis lit
//! `GET /v1/pair/operations?apres=<curseur>` sans fin et applique chaque
//! opération. Sur `410`, elle s'amorce par `GET /v1/pair/instantane`.
//!
//! # POURQUOI CETTE CONNEXION EST RÉÉCRITE, ET NON TIRÉE D'`asl-client`
//!
//! `asl-client-tokio` ouvre une connexion QUIC cliente, et fait presque cela.
//! Mais le RÉEMPLOYER demanderait de tirer ce dépôt-là par une dépendance
//! `git` — or le dépôt client tire DÉJÀ `asl-id`, `asl-proto`, `asl-cle` et
//! `asl-api` d'ICI (voir son `Cargo.toml`). Se tirer l'un l'autre nouerait deux
//! dépôts qui se pointent, pour une politique de reprise qui tient en trente
//! lignes ([`Reprise`]) et une voie qui, elle, ne parle qu'aux racines : ni
//! annonce, ni poussée, ni enrôlement. On écrit donc NOTRE tireur, focalisé sur
//! les quatre verbes de `docs/protocole.md` §3 bis.
//!
//! # LA REPRISE EST CELLE D'`asl-client`, ET ON N'ABANDONNE JAMAIS
//!
//! `docs/replication.md` §2.3 : recul exponentiel, plafonné, bruit de ±20 %, et
//! **on n'abandonne jamais**. Une racine qui a perdu l'autre la rappelle jusqu'à
//! ce qu'elle revienne, et reprend là où son curseur s'était arrêté. La voie
//! coupée se voit dans le journal d'exploitation ; elle n'empêche rien de servir.

use std::net::SocketAddr;
use std::sync::Arc;

use ams_h3::{Http3Client, Transport};
use ams_proto_quic::{ConnectionId, Directional, StreamId};
use ams_quic::RecvState;
use ams_quic_tls::Connection;
use asl_cle::{ClePublique, CleSecrete, Defi, LiaisonDeCanal, Signature, identifiant_de_racine};
use asl_id::{Genre, Identifiant};
use asl_registre::Cadre;
use asl_store::{Applique, Entrepot, MotifDeRefus};
use tokio::net::UdpSocket;

use crate::quic::maintenant;

/// Ce qu'un datagramme peut faire — le tireur n'émet jamais plus grand (§14).
const DATAGRAMME_MAX: usize = 1_500;

/// Combien de temps on attend une poignée de main, en millisecondes.
///
/// **C'EST UNE BORNE DE REPRISE, PAS DE RÉSEAU** : un pair qui ne répond pas en
/// cinq secondes ne répondra pas mieux en trente ; ce qu'on veut est reculer et
/// réessayer. [`Reprise`] fait le reste, et n'abandonne jamais.
const POIGNEE_MS: u64 = 5_000;

/// Combien de temps on attend une réponse courte (défi, preuve), en
/// millisecondes.
const REPONSE_MS: u64 = 10_000;

/// Le délai avant le premier réessai, en millisecondes.
const RECUL_INITIAL_MS: u64 = 1_000;

/// Le bruit appliqué au délai, en centièmes : ±20 %.
const BRUIT_CENTIEMES: u64 = 20;

/// Ce que la voie entre racines a besoin de savoir pour tirer chez l'autre.
///
/// **Elle possède ce qu'elle tient** : la tâche vit aussi longtemps que le
/// serveur, et des références y traverseraient chaque `await`. L'entrepôt est
/// partagé (`Arc`), le reste est à elle.
pub struct Tireur {
    /// Ce qui se souvient, partagé avec la boucle qui sert.
    pub entrepot: Arc<Entrepot>,
    /// L'adresse du pair, telle que l'exploitant l'a réglée — `hôte:port`.
    pub adresse: String,
    /// Les certificats d'autorité, en PEM, qui valident le certificat TLS du
    /// pair.
    pub racines_pem: Vec<u8>,
    /// Notre clé d'identité : c'est elle qui signe la preuve de genre `n`.
    pub identite: CleSecrete,
    /// La clé d'identité du pair (`--peer-key`) : la preuve qu'il rend se
    /// vérifie contre elle, et rien d'autre (§2.2).
    pub cle_du_pair: ClePublique,
    /// La cadence de maintien, en microsecondes — celle du daemon (§2.3).
    pub keepalive_us: u64,
    /// L'inactivité annoncée, en microsecondes — celle du daemon (§2.3).
    pub idle_us: u64,
    /// De quoi tirer un défi de trente-deux octets, pour poser au pair la
    /// preuve qu'il doit signer. `None` si le noyau refuse.
    pub tirer_un_defi: Box<dyn Fn() -> Option<Defi> + Send + Sync>,
    /// De quoi tirer un aléa pour le bruit de la reprise — n'importe quelle
    /// valeur convient, seule sa répartition compte.
    pub alea: Box<dyn Fn() -> u16 + Send + Sync>,
    /// Où l'on dit l'ouverture et la fermeture de la voie, un rattrapage, un
    /// amorçage, un refus — le journal d'exploitation (§8). Jamais une
    /// opération par ligne.
    pub journal: Box<dyn Fn(String) + Send + Sync>,
    /// Ce que l'application ferme ici : la boucle qui sert les compare au pair
    /// de chaque connexion, comme pour une révocation locale (§3.3).
    pub fermetures: tokio::sync::mpsc::UnboundedSender<Identifiant>,
    /// Le plafond du recul, en millisecondes — la cadence de maintien.
    pub plafond_recul_ms: u64,
}

impl Tireur {
    /// Tire chez l'autre racine, sans fin : à chaque rupture, on recule et l'on
    /// rappelle, en reprenant depuis le curseur.
    ///
    /// **CETTE FONCTION NE REND JAMAIS** tant que la tâche vit. Une session qui
    /// aboutit lit jusqu'à ce que la connexion tombe ; une session qui échoue
    /// est journalisée, et la reprise réessaie.
    pub async fn tirer_sans_fin(self) {
        let pair = identifiant_de_racine(&self.cle_du_pair);
        let mut reprise = Reprise::nouvelle(self.plafond_recul_ms.max(1));
        loop {
            match self.une_session(pair).await {
                Ok(()) => {
                    // La connexion s'est fermée proprement (le pair est parti,
                    // ou le flux s'est tari). On repart doucement.
                    reprise.reussite();
                }
                Err(quoi) => {
                    (self.journal)(format!(
                        "voie vers {} ({pair}) rompue : {quoi} — reprise n° {}",
                        self.adresse,
                        reprise.essais().saturating_add(1),
                    ));
                }
            }
            let delai = reprise.prochain_delai((self.alea)());
            tokio::time::sleep(core::time::Duration::from_millis(delai)).await;
        }
    }

    /// Une session complète : ouvrir, prouver, vérifier, tirer.
    async fn une_session(&self, pair: Identifiant) -> Result<(), Faute> {
        let cible = self.resoudre().await?;
        let mut connexion =
            Connexion::ouvrir(cible, &self.nom_tls(), &self.racines_pem, self.idle_us).await?;
        connexion.maintenir(self.keepalive_us);

        // Premier temps : nous prouvons NOTRE identité de racine, comme une
        // machine prouve la sienne — un genre `n` de plus (§2.2).
        connexion.prouver_notre_racine(&self.identite).await?;

        // Second temps : le pair prouve la sienne, et on la vérifie contre la
        // seule clé qu'on tient de lui. Un pair qui ne prouve pas est refusé,
        // journalisé, et la connexion fermée.
        let defi = (self.tirer_un_defi)().ok_or(Faute::SansDefi)?;
        connexion
            .verifier_le_pair(&self.cle_du_pair, pair, &defi)
            .await?;
        (self.journal)(format!("voie vers {} ({pair}) ouverte", self.adresse));

        self.tirer(&mut connexion, pair).await
    }

    /// Le nom du certificat qu'on exige du pair : la part `hôte` de l'adresse.
    fn nom_tls(&self) -> String {
        let sans_port = self
            .adresse
            .rsplit_once(':')
            .map_or(self.adresse.as_str(), |(hote, _)| hote);
        // Une adresse IPv6 se donne entre crochets ; le certificat, lui, porte
        // l'adresse nue.
        sans_port
            .strip_prefix('[')
            .and_then(|reste| reste.strip_suffix(']'))
            .unwrap_or(sans_port)
            .to_owned()
    }

    /// Résout l'adresse du pair — à chaque session, car le DNS peut bouger.
    async fn resoudre(&self) -> Result<SocketAddr, Faute> {
        tokio::net::lookup_host(&self.adresse)
            .await
            .map_err(Faute::Socket)?
            // IPv6 d'abord, comme partout dans ce produit — mais on prend la
            // première qui vienne si c'est tout ce qu'il y a.
            .max_by_key(|adresse| u8::from(adresse.is_ipv6()))
            .ok_or(Faute::SansAdresse)
    }

    /// Le rattrapage, puis le flux sans fin — et l'amorçage sur `410`.
    async fn tirer(&self, connexion: &mut Connexion, pair: Identifiant) -> Result<(), Faute> {
        loop {
            let curseur = self.entrepot.curseur(pair).map_err(Faute::Entrepot)?;
            let flux = connexion
                .ouvrir_flux(format!("/v1/pair/operations?apres={curseur}").as_bytes())
                .await?;

            match connexion.statut_du_flux(flux).await? {
                200 => {
                    (self.journal)(format!(
                        "voie vers {pair} : lecture des opérations après {curseur}"
                    ));
                    self.lire_le_flux(connexion, pair, flux, false).await?;
                    // Le flux des opérations ne se termine jamais ; s'il rend la
                    // main, c'est que la connexion est tombée.
                    return Ok(());
                }
                410 => {
                    (self.journal)(format!(
                        "voie vers {pair} : 410 après {curseur}, amorçage par instantané"
                    ));
                    self.amorcer(connexion, pair).await?;
                    // On boucle : `GET /v1/pair/operations` reprend au compteur
                    // de coupe que l'instantané a posé.
                }
                autre => return Err(Faute::Statut(autre)),
            }
        }
    }

    /// L'amorçage : lire l'instantané jusqu'au cadre de fin, tout appliquer.
    async fn amorcer(&self, connexion: &mut Connexion, pair: Identifiant) -> Result<(), Faute> {
        let flux = connexion.ouvrir_flux(b"/v1/pair/instantane").await?;
        match connexion.statut_du_flux(flux).await? {
            200 => self.lire_le_flux(connexion, pair, flux, true).await,
            autre => Err(Faute::Statut(autre)),
        }
    }

    /// Lit les cadres d'un flux tenu, et les applique à mesure.
    ///
    /// En mode instantané, le cadre de fin arrête la lecture et pose le curseur.
    /// En mode flux, la lecture ne s'arrête que si la connexion tombe.
    async fn lire_le_flux(
        &self,
        connexion: &mut Connexion,
        pair: Identifiant,
        flux: StreamId,
        instantane: bool,
    ) -> Result<(), Faute> {
        let mut reste: Vec<u8> = Vec::new();
        loop {
            reste.extend_from_slice(&connexion.prendre_le_corps(flux));
            loop {
                // **RIEN À DÉCODER N'EST PAS UN CADRE ILLISIBLE.** `Cadre::lire`
                // sur zéro octet lit un genre nul et rend une étiquette
                // inconnue ; ce n'est pas une corruption, c'est un flux qui se
                // tait. On attend d'autres octets.
                if reste.is_empty() {
                    break;
                }
                match Cadre::lire(&reste) {
                    Ok((cadre, combien)) => {
                        reste.drain(..combien.min(reste.len()));
                        let fini = matches!(cadre, Cadre::Fin { .. });
                        self.appliquer_un_cadre(pair, &cadre, instantane)?;
                        if fini {
                            // L'instantané est fini : le flux se ferme derrière.
                            return Ok(());
                        }
                    }
                    // Il manque des octets : on en attend d'autres.
                    Err(asl_registre::Faute::Tronquee { .. }) => break,
                    // Un cadre illisible ferme la voie ; il ne se saute pas
                    // (§5.2). Le curseur n'a pas bougé, l'exploitant le lit, et
                    // la reprise réessaiera la même opération.
                    Err(quoi) => return Err(Faute::CadreIllisible(quoi)),
                }
            }
            // Le pair a-t-il fini d'écrire ce flux sans qu'on ait vu de fin ?
            if connexion.flux_fini(flux) && reste.is_empty() {
                return if instantane {
                    Err(Faute::InstantaneTronque)
                } else {
                    Ok(())
                };
            }
            connexion.entretenir(REPONSE_MS.min(500)).await?;
            if !connexion.vivante() {
                return Ok(());
            }
        }
    }

    /// Applique ce cadre, journalise un refus, et transmet ce qu'il faut fermer.
    fn appliquer_un_cadre(
        &self,
        pair: Identifiant,
        cadre: &Cadre,
        instantane: bool,
    ) -> Result<(), Faute> {
        match self
            .entrepot
            .appliquer(pair, cadre, instantane)
            .map_err(Faute::Entrepot)?
        {
            Applique::Faite { effets, .. } => {
                for quoi in effets.a_fermer {
                    // Le récepteur est fermé quand le serveur s'éteint : il n'y
                    // a alors plus personne pour fermer, et ce n'est pas une
                    // faute.
                    let _ = self.fermetures.send(quoi);
                }
            }
            Applique::Fin { .. } => {}
            // **UN REFUS NE FERME PAS LA VOIE** : un recul est une relivraison
            // idempotente, un rejeu et une provenance hors périmètre sont des
            // anomalies qu'on journalise sans rompre — l'exploitant regarde.
            Applique::Refusee(MotifDeRefus::Recule) => {}
            Applique::Refusee(motif) => {
                (self.journal)(format!("voie vers {pair} : opération refusée ({motif:?})"));
            }
        }
        Ok(())
    }
}

/// Ce qui peut rompre une session de la voie.
#[derive(Debug)]
pub enum Faute {
    /// La socket ou le noyau ont refusé.
    Socket(std::io::Error),
    /// L'adresse du pair ne se résout en rien.
    SansAdresse,
    /// La configuration TLS ne se monte pas.
    Tls(String),
    /// Le transport QUIC a refusé.
    Quic(ams_quic_tls::Error),
    /// Le conducteur HTTP/3 a refusé.
    Http3(ams_h3::Error),
    /// La poignée de main n'a pas abouti à temps.
    Delai,
    /// La liaison de canal ne s'exporte pas de cette connexion.
    SansLiaison,
    /// Le noyau n'a pas donné de défi pour la preuve du pair.
    SansDefi,
    /// La preuve de notre identité a été refusée par le pair.
    NotrePreuveRefusee(u16),
    /// Le pair n'a pas prouvé la clé qu'on tient de lui.
    PairNonProuve,
    /// Le pair a répondu autre chose que ce qu'on attendait.
    Statut(u16),
    /// Ce que le pair a rendu ne se lit pas.
    Illisible,
    /// Un cadre du flux ne se décode pas : la voie se ferme, il ne se saute pas.
    CadreIllisible(asl_registre::Faute),
    /// Un instantané s'est terminé sans cadre de fin.
    InstantaneTronque,
    /// L'entrepôt a refusé.
    Entrepot(asl_store::Faute),
}

impl core::fmt::Display for Faute {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Socket(quoi) => write!(f, "la socket a refusé : {quoi}"),
            Self::SansAdresse => f.write_str("l'adresse du pair ne se résout en rien"),
            Self::Tls(quoi) => write!(f, "la configuration TLS : {quoi}"),
            Self::Quic(quoi) => write!(f, "le transport a refusé : {quoi}"),
            Self::Http3(quoi) => write!(f, "HTTP/3 a refusé : {quoi}"),
            Self::Delai => f.write_str("la poignée de main n'a pas abouti à temps"),
            Self::SansLiaison => f.write_str("la liaison de canal ne s'exporte pas"),
            Self::SansDefi => f.write_str("le noyau n'a pas donné de défi"),
            Self::NotrePreuveRefusee(code) => {
                write!(f, "le pair a refusé notre preuve de racine ({code})")
            }
            Self::PairNonProuve => f.write_str("le pair n'a pas prouvé son identité"),
            Self::Statut(code) => write!(f, "le pair a répondu {code}"),
            Self::Illisible => f.write_str("la réponse du pair ne se lit pas"),
            Self::CadreIllisible(quoi) => write!(f, "un cadre ne se décode pas : {quoi:?}"),
            Self::InstantaneTronque => f.write_str("l'instantané s'est terminé sans cadre de fin"),
            Self::Entrepot(quoi) => write!(f, "l'entrepôt a refusé : {quoi}"),
        }
    }
}

impl std::error::Error for Faute {}

/// La politique de reprise (`docs/replication.md` §2.3, `protocole.md` §1.5) :
/// recul exponentiel, plafonné, bruit de ±20 %, et **on n'abandonne jamais**.
///
/// C'est celle d'`asl-client`, réécrite ici plutôt que tirée — voir l'en-tête
/// du module. Le compteur d'essais SATURE : après soixante-quatre échecs, un
/// décalage non saturé rendrait un délai nul, et la reprise deviendrait la
/// boucle serrée qu'elle existe pour éviter.
struct Reprise {
    plafond_ms: u64,
    essais: u32,
}

impl Reprise {
    /// Une reprise plafonnée à cette cadence.
    const fn nouvelle(plafond_ms: u64) -> Self {
        Self {
            plafond_ms,
            essais: 0,
        }
    }

    /// Le délai avant le prochain essai, en millisecondes — jamais nul.
    fn prochain_delai(&mut self, alea: u16) -> u64 {
        let brut = RECUL_INITIAL_MS
            .checked_shl(self.essais)
            .unwrap_or(u64::MAX)
            .min(self.plafond_ms);
        self.essais = self.essais.saturating_add(1);
        // Le bruit, en arithmétique entière : de 80 % à 120 %. Multiplier avant
        // de diviser garde la précision.
        let centiemes = 100_u64.saturating_sub(BRUIT_CENTIEMES).saturating_add(
            u64::from(alea)
                .saturating_mul(BRUIT_CENTIEMES.saturating_mul(2))
                .checked_div(u64::from(u16::MAX))
                .unwrap_or(0),
        );
        brut.saturating_mul(centiemes)
            .checked_div(100)
            .unwrap_or(brut)
            .max(1)
    }

    /// La session a abouti : le recul repart de zéro.
    const fn reussite(&mut self) {
        self.essais = 0;
    }

    /// Le nombre d'échecs consécutifs.
    const fn essais(&self) -> u32 {
        self.essais
    }
}

// ── La connexion QUIC sortante ──────────────────────────────────────────────

/// Une connexion cliente vers l'autre racine.
struct Connexion {
    socket: UdpSocket,
    quic: Box<Connection>,
    h3: Http3Client,
    liaison: LiaisonDeCanal,
    autorite: String,
}

impl Connexion {
    /// Ouvre une connexion et mène la poignée de main au bout.
    async fn ouvrir(
        cible: SocketAddr,
        nom: &str,
        racines: &[u8],
        idle_us: u64,
    ) -> Result<Self, Faute> {
        let config = configuration_tls(racines)?;
        let serveur = rustls::pki_types::ServerName::try_from(nom.to_owned())
            .map_err(|_| Faute::Tls(format!("`{nom}` n'est pas un nom de serveur")))?;

        // Une socket de la même famille que la cible : se lier en IPv4 pour
        // joindre de l'IPv6 échoue au premier envoi.
        let local = if cible.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(local).await.map_err(Faute::Socket)?;
        socket.connect(cible).await.map_err(Faute::Socket)?;

        // §7.2 : l'identifiant de destination doit être imprévisible — §5.2 en
        // dérive les clés `Initial`. On le tire de l'horloge et de l'adresse de
        // la pile, comme la boucle qui sert tire les siens.
        let graine = graine();
        let notre = ConnectionId::new(&graine[..8])
            .map_err(|_| Faute::Tls("l'identifiant local ne se construit pas".to_owned()))?;
        let origine = ConnectionId::new(&graine[8..])
            .map_err(|_| Faute::Tls("l'identifiant d'origine ne se construit pas".to_owned()))?;

        let quic = Box::new(
            Connection::connect(config, serveur, notre, origine, idle_us, maintenant())
                .map_err(Faute::Quic)?,
        );
        let mut connexion = Self {
            socket,
            quic,
            h3: Http3Client::new(),
            liaison: LiaisonDeCanal::depuis_octets([0; asl_cle::LIAISON_OCTETS]),
            autorite: nom.to_owned(),
        };
        connexion.poignee_de_main().await?;
        Ok(connexion)
    }

    /// La cadence de maintien : c'est elle qui tient le mapping ouvert (§2.3).
    fn maintenir(&mut self, keepalive_us: u64) {
        self.quic.set_keepalive(keepalive_us, maintenant());
    }

    /// La connexion est-elle encore là ?
    fn vivante(&self) -> bool {
        !self.quic.is_closed()
    }

    /// Mène la poignée de main, exporte la liaison, ouvre les flux HTTP/3.
    async fn poignee_de_main(&mut self) -> Result<(), Faute> {
        let echeance = maintenant().saturating_add(POIGNEE_MS.saturating_mul(1_000));
        while !self.quic.is_established() {
            if maintenant() >= echeance {
                return Err(Faute::Delai);
            }
            self.emettre().await?;
            self.recevoir(POIGNEE_MS.min(500)).await?;
        }
        self.liaison = self
            .quic
            .export(asl_cle::ETIQUETTE_LIAISON, None)
            .map(LiaisonDeCanal::depuis_octets)
            .map_err(|_| Faute::SansLiaison)?;
        {
            let mut pont = PontTireur(&mut self.quic);
            self.h3.on_established(&mut pont).map_err(Faute::Http3)?;
        }
        self.emettre().await
    }

    /// Émet tout ce que la connexion a à dire.
    async fn emettre(&mut self) -> Result<(), Faute> {
        let mut place = [0_u8; DATAGRAMME_MAX];
        loop {
            let ecrit = self
                .quic
                .poll_transmit(&mut place, maintenant())
                .map_err(Faute::Quic)?;
            if ecrit == 0 {
                return Ok(());
            }
            self.socket
                .send(place.get(..ecrit).unwrap_or_default())
                .await
                .map_err(Faute::Socket)?;
        }
    }

    /// Attend un datagramme, au plus ce nombre de millisecondes.
    async fn recevoir(&mut self, attente_ms: u64) -> Result<(), Faute> {
        let mut recu = [0_u8; DATAGRAMME_MAX];
        let attente = tokio::time::Duration::from_millis(attente_ms);
        match tokio::time::timeout(attente, self.socket.recv(&mut recu)).await {
            Ok(Ok(lus)) => {
                let mut datagramme = recu.get_mut(..lus).unwrap_or_default().to_vec();
                self.quic
                    .on_datagram(&mut datagramme, maintenant())
                    .map_err(Faute::Quic)?;
            }
            Ok(Err(quoi)) => return Err(Faute::Socket(quoi)),
            // Rien n'est arrivé : les délais de la connexion échoient quand même.
            Err(_) => {
                self.quic.on_timeout(maintenant());
            }
        }
        Ok(())
    }

    /// Reçoit, fait lire les flux, réémet — un tour de maintien.
    async fn entretenir(&mut self, attente_ms: u64) -> Result<(), Faute> {
        self.recevoir(attente_ms).await?;
        self.lire_les_flux()?;
        self.emettre().await
    }

    /// Fait lire au conducteur tout ce qui est lisible.
    fn lire_les_flux(&mut self) -> Result<(), Faute> {
        let vivants: Vec<StreamId> = self.quic.streams_alive().collect();
        let mut pont = PontTireur(&mut self.quic);
        for flux in vivants {
            self.h3.on_readable(&mut pont, flux).map_err(Faute::Http3)?;
        }
        Ok(())
    }

    /// Envoie une requête courte et attend sa réponse entière.
    async fn requete(
        &mut self,
        methode: &[u8],
        chemin: &[u8],
        champs: &[(&[u8], &[u8])],
        corps: &[u8],
    ) -> Result<ams_h3::ReponseRecue, Faute> {
        let flux = {
            let mut pont = PontTireur(&mut self.quic);
            self.h3
                .request(
                    &mut pont,
                    methode,
                    chemin,
                    self.autorite.as_bytes(),
                    champs,
                    corps,
                )
                .map_err(Faute::Http3)?
        };
        self.emettre().await?;
        let echeance = maintenant().saturating_add(REPONSE_MS.saturating_mul(1_000));
        loop {
            if let Some(reponse) = self.h3.take_response(flux) {
                return Ok(reponse);
            }
            if maintenant() >= echeance {
                return Err(Faute::Delai);
            }
            self.entretenir(REPONSE_MS.min(500)).await?;
        }
    }

    /// Ouvre un flux tenu (opérations, instantané) — sans en attendre la fin.
    async fn ouvrir_flux(&mut self, chemin: &[u8]) -> Result<StreamId, Faute> {
        let flux = {
            let mut pont = PontTireur(&mut self.quic);
            self.h3
                .request(
                    &mut pont,
                    b"GET",
                    chemin,
                    self.autorite.as_bytes(),
                    &[],
                    b"",
                )
                .map_err(Faute::Http3)?
        };
        self.emettre().await?;
        Ok(flux)
    }

    /// Attend le statut d'un flux tenu — il arrive avant le corps.
    async fn statut_du_flux(&mut self, flux: StreamId) -> Result<u16, Faute> {
        let echeance = maintenant().saturating_add(REPONSE_MS.saturating_mul(1_000));
        loop {
            if let Some(statut) = self.h3.statut(flux) {
                return Ok(statut.value());
            }
            if maintenant() >= echeance {
                return Err(Faute::Delai);
            }
            self.entretenir(REPONSE_MS.min(500)).await?;
            if !self.vivante() {
                return Err(Faute::Illisible);
            }
        }
    }

    /// Le corps arrivé sur ce flux depuis le dernier appel.
    fn prendre_le_corps(&mut self, flux: StreamId) -> Vec<u8> {
        self.h3.prendre_ce_qui_est_arrive(flux).unwrap_or_default()
    }

    /// Le pair a-t-il fini d'écrire ce flux ?
    fn flux_fini(&self, flux: StreamId) -> bool {
        self.h3.est_fini(flux)
    }

    /// Prouve NOTRE identité de racine — comme une machine, un genre `n` (§2.2).
    async fn prouver_notre_racine(&mut self, identite: &CleSecrete) -> Result<(), Faute> {
        let defi = self.defi().await?;
        let racine = identifiant_de_racine(&identite.publique());
        let signature = identite
            .signer(racine, &defi, &self.liaison)
            .map_err(|_| Faute::Illisible)?;
        let mut preuve = Vec::with_capacity(81);
        preuve.push(Genre::Annuaire.prefixe());
        preuve.extend_from_slice(racine.octets());
        preuve.extend_from_slice(signature.octets());
        let reponse = self
            .requete(
                b"POST",
                b"/v1/defi",
                &[(b"content-type", b"application/octet-stream")],
                &preuve,
            )
            .await?;
        let code = reponse.statut.value();
        if code == 204 {
            Ok(())
        } else {
            Err(Faute::NotrePreuveRefusee(code))
        }
    }

    /// Tire un défi du pair.
    async fn defi(&mut self) -> Result<Defi, Faute> {
        let reponse = self.requete(b"GET", b"/v1/defi", &[], b"").await?;
        if reponse.statut.value() != 200 || reponse.corps.len() != asl_cle::DEFI_OCTETS {
            return Err(Faute::Illisible);
        }
        let mut octets = [0_u8; asl_cle::DEFI_OCTETS];
        octets.copy_from_slice(&reponse.corps);
        Ok(Defi::depuis_octets(octets))
    }

    /// Pose au pair un défi, et vérifie la preuve qu'il rend contre la clé qu'on
    /// tient de lui (`prouve_la_racine`, §2.2).
    async fn verifier_le_pair(
        &mut self,
        cle_du_pair: &ClePublique,
        pair: Identifiant,
        defi: &Defi,
    ) -> Result<(), Faute> {
        let reponse = self
            .requete(
                b"POST",
                b"/v1/pair/preuve",
                &[(b"content-type", b"application/octet-stream")],
                defi.octets(),
            )
            .await?;
        if reponse.statut.value() != 200 || reponse.corps.len() != 81 {
            return Err(Faute::PairNonProuve);
        }
        let racine = Identifiant::depuis_entropie(
            Genre::Annuaire,
            reponse
                .corps
                .get(1..17)
                .unwrap_or_default()
                .try_into()
                .unwrap_or([0; 16]),
        );
        let mut brute = [0_u8; 64];
        brute.copy_from_slice(reponse.corps.get(17..81).unwrap_or_default());
        let signature = Signature::depuis_octets(brute);
        // L'identifiant rendu doit être celui de la clé épinglée, et la
        // signature doit vérifier contre elle.
        if racine != pair || !cle_du_pair.prouve_la_racine(racine, defi, &self.liaison, &signature)
        {
            return Err(Faute::PairNonProuve);
        }
        Ok(())
    }
}

/// Le pont côté CLIENT : il ouvre des flux bidirectionnels, ce que le pont du
/// serveur refuse ([`crate::pont::Pont`]).
///
/// **Deux ponts, et c'est la règle de l'orphelin** : `ams_h3::Transport` et
/// `ams_quic_tls::Connection` sont à d'autres, et se marient chez nous. Le
/// serveur n'ouvre jamais de bidirectionnel ; le tireur ne fait que cela.
struct PontTireur<'a>(&'a mut Connection);

impl Transport for PontTireur<'_> {
    fn open_bi(&mut self) -> Result<StreamId, ams_h3::Error> {
        self.0
            .open_stream(Directional::Bidirectional)
            .map_err(|_| ams_h3::Error::transport())
    }

    fn open_uni(&mut self) -> Result<StreamId, ams_h3::Error> {
        self.0
            .open_stream(Directional::Unidirectional)
            .map_err(|_| ams_h3::Error::transport())
    }

    fn read(&mut self, flux: StreamId, vers: &mut [u8]) -> usize {
        self.0.read(flux, vers)
    }

    fn write(&mut self, flux: StreamId, octets: &[u8]) -> Result<usize, ams_h3::Error> {
        self.0
            .write(flux, octets)
            .map_err(|_| ams_h3::Error::transport())
    }

    fn reset(&mut self, flux: StreamId, code: u64) -> Result<(), ams_h3::Error> {
        self.0
            .reset(flux, code)
            .map_err(|_| ams_h3::Error::transport())
    }

    fn finish(&mut self, flux: StreamId) -> Result<(), ams_h3::Error> {
        self.0.finish(flux).map_err(|_| ams_h3::Error::transport())
    }

    fn recv_state(&self, flux: StreamId) -> Option<RecvState> {
        self.0.recv_state(flux)
    }
}

/// Monte la configuration TLS cliente : les racines qui valident le pair, et
/// l'ALPN `h3` posée ici pour qu'on ne puisse pas l'oublier (§3.1 de RFC 9114).
fn configuration_tls(racines: &[u8]) -> Result<Arc<rustls::ClientConfig>, Faute> {
    use rustls::pki_types::pem::PemObject as _;

    let mut magasin = rustls::RootCertStore::empty();
    for der in rustls::pki_types::CertificateDer::pem_slice_iter(racines) {
        let der = der.map_err(|quoi| Faute::Tls(format!("certificat illisible : {quoi}")))?;
        magasin
            .add(der)
            .map_err(|quoi| Faute::Tls(format!("racine refusée : {quoi}")))?;
    }
    if magasin.is_empty() {
        return Err(Faute::Tls("aucune racine à qui faire confiance".to_owned()));
    }
    let mut config =
        rustls::ClientConfig::builder_with_provider(Arc::new(ams_tls::provider_quic()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|quoi| Faute::Tls(format!("TLS 1.3 : {quoi}")))?
            .with_root_certificates(magasin)
            .with_no_client_auth();
    config.alpn_protocols = ams_tls::alpn_h3();
    Ok(Arc::new(config))
}

/// Seize octets d'amorce pour les identifiants de connexion.
///
/// §5.1 ne demande pas d'imprévisibilité cryptographique — elle demande qu'on ne
/// puisse pas CORRÉLER. L'horloge et l'adresse d'une variable de pile (que
/// l'ASLR déplace) n'ont pas de motif ; c'est ce que fait aussi la boucle qui
/// sert (`crate::quic::amorce`).
fn graine() -> [u8; 16] {
    let pile = 0_u8;
    let adresse = core::ptr::from_ref(&pile) as u64;
    let a = maintenant().wrapping_mul(6_364_136_223_846_793_005) ^ adresse;
    let b = a
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    let mut graine = [0_u8; 16];
    graine[..8].copy_from_slice(&a.to_be_bytes());
    graine[8..].copy_from_slice(&b.to_be_bytes());
    graine
}
