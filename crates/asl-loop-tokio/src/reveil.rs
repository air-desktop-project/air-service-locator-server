//! Le réveilleur : l'appel sortant qui réveille les appareils d'un compte
//! (`protocole.md` §2.2, « Les notifications », 2026-09-25).
//!
//! # UNE TÂCHE À ELLE, HORS DE LA BOUCLE
//!
//! La boucle QUIC sert toutes les connexions dans une seule tâche, et rien de
//! long ne doit s'y passer (la leçon de la 0.18.0). Une autorisation écrite
//! pose le compte bénéficiaire dans un canal (`Annuaire::reveiller_par`) ;
//! c'est ici qu'on lit ses points, qu'on résout, qu'on se connecte et qu'on
//! attend — jusqu'à cinq secondes par envoi, chacun dans sa propre tâche. La
//! réponse à `POST /v1/autorisations` est partie depuis longtemps.
//!
//! # CE QUI SE DÉCIDE N'EST PAS ICI
//!
//! Quelle adresse est permise, quelle requête part, ce qu'on lit de la
//! réponse, combien d'envois on s'autorise : `asl-reveil`, à l'étage 2,
//! couvert et fuzzé. Ce module résout, se connecte, chiffre — et rapporte.
//!
//! # LE CLIENT HTTPS, ET CE QU'IL REPREND
//!
//! Le TLS est celui d'`ams-tls` — le client du relais de courrier sortant
//! d'`air-mail-server` : `rustls` sur `rustls-rustcrypto`, pas une ligne de
//! C, **TLS 1.3 seulement**, et la vérification ordinaire de la WebPKI contre
//! les racines que l'exploitant désigne (`--push-roots`, `ams_tls::anchors`
//! puis `ams_tls::webpki_config`). Aucune racine n'est embarquée ni lue sans
//! qu'on l'ait dit. Au-dessus, **HTTP/1.1 réduit à une requête constante** et
//! une ligne de statut : un `rustls::StreamOwned` sur une `std::net::TcpStream`,
//! dans `spawn_blocking`, chaque attente bornée par l'échéance commune — pas
//! de `tokio-rustls` à ajouter au graphe pour une requête par minute.
//!
//! # LA CONNEXION SE FAIT À L'ADRESSE VÉRIFIÉE
//!
//! Le nom est résolu à chaque envoi, TOUTES les adresses rendues sont jugées
//! (`asl_reveil::juger_toutes`), et la connexion va à la première — **sans
//! nouvelle résolution**. C'est ce qui défait le rebinding DNS : la seconde
//! résolution n'est jamais faite. Le nom ne sert plus qu'au SNI et à la
//! vérification du certificat.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use asl_api::point::UrlDePoussee;
use asl_id::Identifiant;
use asl_reveil::{Freins, Issue, Regle, Statut};
use asl_store::Entrepot;
use rustls::pki_types::ServerName;

/// Ce qu'un envoi a, au plus, pour tout : résolution, TCP, TLS, requête,
/// ligne de statut (§2.2, « La sécurité », 3).
pub const DELAI: Duration = Duration::from_secs(5);

/// Le port d'un point : 443, que la forme a exigé.
const PORT: u16 = 443;

/// Ce qui empêche un envoi d'aboutir.
#[derive(Debug)]
enum Echec {
    /// Le point rangé ne passe plus la forme — une base corrompue, ou une
    /// règle resserrée depuis sa dépose.
    Illisible,
    /// Le nom ne se résout pas, ou en rien.
    Resolution,
    /// Une adresse rendue n'est pas unicast globale : le nom est hostile.
    Regle(IpAddr, Regle),
    /// TCP, TLS, ou une ligne de statut qui n'en est pas une — ou le délai.
    Transport,
}

/// Le réveilleur, tel que le binaire le monte.
pub struct Reveilleur {
    /// Où lire les points des appareils à réveiller.
    entrepot: Arc<Entrepot>,
    /// Le client TLS : TLS 1.3, WebPKI, contre `--push-roots`.
    tls: Arc<rustls::ClientConfig>,
    /// Combien de racines ont été épinglées — ce que le démarrage dit.
    racines: usize,
    /// Le journal d'exploitation : les points morts, et chaque refus des
    /// règles d'adresse (§2.2, « Échec »).
    journal: Box<dyn Fn(&str) + Send + Sync>,
    /// L'origine de l'horloge des freins : une horloge monotone, qu'un
    /// réglage de l'heure murale ne fait pas reculer.
    debut: Instant,
    /// La porte d'essai — voir [`Reveilleur::resoudre_pour_un_essai`].
    #[cfg(feature = "porte-d-essai")]
    porte_d_essai: Option<SocketAddr>,
}

impl Reveilleur {
    /// Un réveilleur qui vérifie les serveurs de poussée contre ces racines,
    /// en PEM — le contenu de `--push-roots`.
    ///
    /// # Errors
    ///
    /// [`ams_tls::AnchorError`] si le fichier ne porte aucune autorité
    /// lisible : un magasin vide ferait échouer chaque envoi sans dire
    /// pourquoi, et mieux vaut refuser de démarrer.
    pub fn nouveau(
        entrepot: Arc<Entrepot>,
        racines_pem: &[u8],
        journal: Box<dyn Fn(&str) + Send + Sync>,
    ) -> Result<Self, ams_tls::AnchorError> {
        let racines = ams_tls::anchors(racines_pem)?;
        Ok(Self {
            entrepot,
            racines: racines.len(),
            tls: Arc::new(ams_tls::webpki_config(Arc::new(racines))),
            journal,
            debut: Instant::now(),
            #[cfg(feature = "porte-d-essai")]
            porte_d_essai: None,
        })
    }

    /// Combien de racines ont été épinglées.
    #[must_use]
    pub const fn racines(&self) -> usize {
        self.racines
    }

    /// **LA PORTE D'ESSAI** : tout nom se résout en cette adresse, et elle
    /// seule échappe au jugement des adresses.
    ///
    /// # ÉTROITE, EXPLICITE, ET ABSENTE DU BINAIRE
    ///
    /// Un essai de bout en bout doit joindre un faux serveur de poussée sur
    /// la boucle locale — exactement ce que les règles d'adresse refusent.
    /// Cette méthode n'existe que sous la fonctionnalité `porte-d-essai`, que
    /// seuls les essais de cette crate activent (sa propre
    /// `[dev-dependencies]`) ; `asl-server` ne l'active pas, et aucun réglage
    /// de la ligne de commande n'y mène. Le TLS, lui, n'est PAS contourné : le
    /// faux serveur présente un certificat pour le nom du point, sous une
    /// racine que l'essai donne comme `--push-roots`.
    #[cfg(feature = "porte-d-essai")]
    #[must_use]
    pub const fn resoudre_pour_un_essai(mut self, adresse: SocketAddr) -> Self {
        self.porte_d_essai = Some(adresse);
        self
    }

    /// Réveille, sans fin, les comptes que la boucle pose dans ce canal.
    ///
    /// Rend quand le canal se ferme — c'est-à-dire quand l'annuaire s'arrête.
    pub async fn reveiller_sans_fin(
        self,
        mut comptes: tokio::sync::mpsc::UnboundedReceiver<Identifiant>,
    ) {
        let moi = Arc::new(self);
        let freins = Arc::new(Mutex::new(Freins::neufs()));
        while let Some(compte) = comptes.recv().await {
            Self::reveiller_le_compte(&moi, &freins, compte);
        }
    }

    /// Lit les points des appareils vivants de ce compte, et lance un envoi
    /// par point que les freins admettent.
    fn reveiller_le_compte(moi: &Arc<Self>, freins: &Arc<Mutex<Freins>>, compte: Identifiant) {
        let points = match moi.entrepot.points_du_compte(compte) {
            Ok(points) => points,
            Err(faute) => {
                (moi.journal)(&format!(
                    "réveil : les points de {compte} ne se lisent pas ({faute:?}) — rien ne part"
                ));
                return;
            }
        };
        for (appareil, rangee) in points {
            let texte = String::from_utf8_lossy(rangee.point.octets()).into_owned();
            let Ok(point) = UrlDePoussee::analyser(&texte) else {
                (moi.journal)(&format!(
                    "réveil : le point de {appareil} ne passe plus la forme — rien ne part"
                ));
                continue;
            };
            let identite = (rangee.estampille.compteur, rangee.estampille.racine);
            let admis = freins
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .admettre(appareil, identite, point.hote(), depuis(moi.debut));
            // Un envoi freiné ne se dit pas : dix autorisations dans la minute
            // font un réveil, et neuf lignes de journal n'apprendraient rien.
            if admis.is_err() {
                continue;
            }
            let moi = Arc::clone(moi);
            let freins = Arc::clone(freins);
            tokio::spawn(async move {
                let hote = UrlDePoussee::analyser(&texte)
                    .map(|point| point.hote().to_owned())
                    .unwrap_or_default();
                match tokio::time::timeout(DELAI, moi.envoyer(&texte)).await {
                    Ok(Ok(code)) if asl_reveil::issue(code) == Issue::Mort => {
                        freins
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .marquer_mort(appareil, identite);
                        (moi.journal)(&format!(
                            "réveil : point mort — appareil {appareil}, statut {code} ; plus \
                             rien n'y part avant qu'il en dépose un neuf"
                        ));
                    }
                    Ok(Err(Echec::Regle(adresse, regle))) => {
                        (moi.journal)(&format!(
                            "réveil refusé par les règles d'adresse — appareil {appareil}, \
                             hôte {hote}, règle « {} » ({adresse})",
                            regle.nom()
                        ));
                    }
                    // `2xx`, `429`, `5xx`, un délai, un nom qui ne se résout
                    // pas : une tentative, pas de file (§2.2, « Échec »).
                    _ => {}
                }
                freins
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .rendre();
            });
        }
    }

    /// Un envoi : résoudre, juger, se connecter, écrire, lire le statut.
    async fn envoyer(&self, texte: &str) -> Result<u16, Echec> {
        let echeance = Instant::now().checked_add(DELAI).ok_or(Echec::Transport)?;
        let point = UrlDePoussee::analyser(texte).map_err(|_| Echec::Illisible)?;
        let adresse = self.resoudre(point.hote()).await?;
        let requete = asl_reveil::requete(&point);
        let nom = ServerName::try_from(point.hote().to_owned()).map_err(|_| Echec::Illisible)?;
        let tls = Arc::clone(&self.tls);
        tokio::task::spawn_blocking(move || appeler(adresse, nom, tls, &requete, echeance))
            .await
            .map_err(|_| Echec::Transport)?
    }

    /// Le nom résolu, toutes ses adresses jugées, et la première rendue.
    async fn resoudre(&self, hote: &str) -> Result<SocketAddr, Echec> {
        #[cfg(feature = "porte-d-essai")]
        if let Some(adresse) = self.porte_d_essai {
            return Ok(adresse);
        }
        let adresses: Vec<SocketAddr> = tokio::net::lookup_host((hote, PORT))
            .await
            .map_err(|_| Echec::Resolution)?
            .collect();
        let ips: Vec<IpAddr> = adresses.iter().map(SocketAddr::ip).collect();
        asl_reveil::juger_toutes(&ips).map_err(|(adresse, regle)| Echec::Regle(adresse, regle))?;
        adresses.first().copied().ok_or(Echec::Resolution)
    }
}

/// Ce qui reste avant l'échéance, jamais zéro — `set_read_timeout` refuse
/// une durée nulle, et une échéance passée se voit à la lecture suivante.
fn reste(echeance: Instant) -> Duration {
    echeance
        .saturating_duration_since(Instant::now())
        .max(Duration::from_millis(1))
}

/// L'appel lui-même, bloquant, chaque attente bornée par l'échéance.
///
/// **Seule la ligne de statut est lue** : dès qu'elle est entière, on s'en
/// va, sans lire les en-têtes ni le corps (§2.2, « La sécurité », 3). Une
/// redirection est un code comme un autre, et rien ne la suit.
fn appeler(
    adresse: SocketAddr,
    nom: ServerName<'static>,
    tls: Arc<rustls::ClientConfig>,
    requete: &[u8],
    echeance: Instant,
) -> Result<u16, Echec> {
    let transport = |_| Echec::Transport;
    let tcp = TcpStream::connect_timeout(&adresse, reste(echeance)).map_err(transport)?;
    tcp.set_write_timeout(Some(reste(echeance)))
        .map_err(transport)?;
    let _ = tcp.set_nodelay(true);
    let connexion = rustls::ClientConnection::new(tls, nom).map_err(|_| Echec::Transport)?;
    let mut flux = rustls::StreamOwned::new(connexion, tcp);
    flux.sock
        .set_read_timeout(Some(reste(echeance)))
        .map_err(transport)?;
    flux.write_all(requete).map_err(transport)?;
    flux.flush().map_err(transport)?;
    let mut recu = Vec::new();
    let mut tampon = [0_u8; 512];
    loop {
        if Instant::now() >= echeance {
            return Err(Echec::Transport);
        }
        flux.sock
            .set_read_timeout(Some(reste(echeance)))
            .map_err(transport)?;
        let lus = flux.read(&mut tampon).map_err(transport)?;
        if lus == 0 {
            return Err(Echec::Transport);
        }
        recu.extend_from_slice(tampon.get(..lus).unwrap_or_default());
        match asl_reveil::lire_le_statut(&recu) {
            Statut::Code(code) => return Ok(code),
            Statut::Illisible => return Err(Echec::Transport),
            Statut::Incomplet => {}
        }
    }
}

/// Les millisecondes écoulées depuis cette origine : ce que les freins
/// comptent.
fn depuis(debut: Instant) -> u64 {
    u64::try_from(debut.elapsed().as_millis()).unwrap_or(u64::MAX)
}
