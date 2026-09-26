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
//!
//! # UN FLUX PORTE UNE PART, ET LE TIREUR LE ROUVRE — SUR LA MÊME CONNEXION
//!
//! La pile QUIC greffée d'`air-mail-server` annonce seize kibioctets par flux
//! (`ams_quic_tls::FLUX_OCTETS`) **et ne relève jamais cette fenêtre** : elle
//! n'émet aucun `MAX_STREAM_DATA`. Un flux ne peut donc porter que seize
//! kibioctets dans un sens, sur toute sa vie — au-delà, l'émetteur attend un
//! crédit qui ne vient jamais, et rien ne le dit. Un flux d'opérations « sans
//! fin » s'y serait tu au bout de quelques dizaines d'écritures, et un
//! instantané de quelques centaines d'enregistrements n'y serait jamais passé.
//!
//! La racine tirée coupe donc chaque flux quand il a porté sa part
//! (`crate::h3::PART_OCTETS_MAX`), à une frontière de cadre, et le tireur le
//! rouvre — `operations` depuis son curseur, `instantane` là où la connexion
//! tient le reste — sans rompre la connexion ni refaire les preuves. **La fin
//! d'un flux n'est pas une rupture** ; la fin de la connexion l'est, et c'est
//! alors la reprise qui joue.
//!
//! # CE QU'UN TOUR REÇOIT S'APPLIQUE EN UNE TRANSACTION
//!
//! Les cadres entiers arrivés depuis le dernier tour forment un LOT, que
//! [`Entrepot::appliquer_la_suite`] applique en une transaction — un `fsync`
//! par tour et non par opération. C'est ce qui fait d'un amorçage de plusieurs
//! milliers d'enregistrements une affaire de secondes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ams_h3::{Http3Client, Transport};
use ams_proto_quic::{ConnectionId, Directional, StreamId};
use ams_quic::RecvState;
use ams_quic_tls::Connection;
use asl_cle::{ClePublique, CleSecrete, Defi, LiaisonDeCanal, Signature, identifiant_de_racine};
use asl_id::{Genre, Identifiant};
use asl_registre::{Cadre, Operation};
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

/// L'état VIVANT de la voie sortante, publié par le tireur et lu par
/// `GET /v1/replication` (`docs/replication.md` §8).
///
/// # UN BOOLÉEN, ET RIEN D'AUTRE, PARCE QUE LE RESTE EST DANS L'ENTREPÔT
///
/// Ce que la ressource rend — le pair, notre compteur, le curseur appliqué —
/// se lit de l'entrepôt au moment de la requête, et il n'y a pas à le
/// recopier ici : une copie vieillirait. Ce que l'entrepôt ne sait PAS est si
/// la connexion sortante est ouverte et prouvée dans les deux sens en ce
/// moment — c'est ce que le tireur seul voit, et c'est ce qu'il publie.
///
/// `ouverte` passe à vrai après les deux preuves, et à faux dès que la
/// session se rompt ; entre deux sessions, la voie est coupée, et la ressource
/// le dit.
#[derive(Debug, Default)]
pub struct EtatDeLaVoie {
    /// La connexion sortante est-elle ouverte et prouvée ?
    ouverte: AtomicBool,
}

impl EtatDeLaVoie {
    /// Une voie qu'on n'a pas encore ouverte.
    #[must_use]
    pub const fn nouvelle() -> Self {
        Self {
            ouverte: AtomicBool::new(false),
        }
    }

    /// La connexion sortante est-elle ouverte et prouvée en ce moment ?
    #[must_use]
    pub fn ouverte(&self) -> bool {
        self.ouverte.load(Ordering::Acquire)
    }

    /// Le tireur dit où il en est.
    fn poser(&self, ouverte: bool) {
        self.ouverte.store(ouverte, Ordering::Release);
    }
}

/// Comment un flux tenu s'est terminé.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum FinDeFlux {
    /// Le pair a fermé le flux : il a porté sa part, on le rouvre.
    Coupe,
    /// Le cadre de fin d'un instantané est passé.
    Fin,
    /// La connexion est tombée. **Le défaut** : une lecture qu'on n'a pas su
    /// mener au bout est traitée comme une connexion perdue, et la reprise joue.
    #[default]
    Morte,
}

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
    /// ([`crate::h3::Fermetures`] : le dépôt réveille la boucle.)
    pub fermetures: crate::h3::Fermetures,
    /// Le plafond du recul, en millisecondes — la cadence de maintien.
    pub plafond_recul_ms: u64,
    /// Où le tireur publie l'état de la voie, pour `GET /v1/replication`.
    pub etat: Arc<EtatDeLaVoie>,
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
            let resultat = self.une_session(pair).await;
            // **L'ÉTAT CHANGE, ET LE JOURNAL LE DIT** (§8) : la voie sortante
            // vers ce pair est coupée, quelle qu'en soit la raison.
            let etait_ouverte = self.etat.ouverte();
            self.etat.poser(false);
            match resultat {
                Ok(()) => {
                    // La connexion s'est fermée proprement (le pair est parti,
                    // ou le flux s'est tari). On repart doucement.
                    (self.journal)(format!(
                        "voie vers {pair} fermée : la connexion s'est terminée — état : coupée"
                    ));
                    reprise.reussite();
                }
                Err(quoi) => {
                    (self.journal)(format!(
                        "voie vers {} ({pair}) {} : {quoi} — état : coupée, reprise n° {}",
                        self.adresse,
                        if etait_ouverte {
                            "rompue"
                        } else {
                            "pas ouverte"
                        },
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
        self.etat.poser(true);
        (self.journal)(format!(
            "voie vers {} ({pair}) ouverte, prouvée dans les deux sens — état : ouverte",
            self.adresse
        ));

        self.tirer(&mut connexion, pair).await
    }

    /// Le nom du certificat qu'on exige du pair : la part `hôte` de l'adresse.
    fn nom_tls(&self) -> String {
        nom_tls(&self.adresse)
    }

    /// Résout l'adresse du pair — à chaque session, car le DNS peut bouger.
    async fn resoudre(&self) -> Result<SocketAddr, Faute> {
        resoudre(&self.adresse).await
    }

    /// Le rattrapage, puis le flux vivant, part après part — et l'amorçage
    /// sur `410`.
    ///
    /// **La fin d'un flux n'est pas une rupture** (voir l'en-tête) : le pair
    /// ferme un flux qui a porté sa part, et l'on en rouvre un depuis le
    /// curseur, sur la même connexion. Seule la connexion tombée rend la main.
    async fn tirer(&self, connexion: &mut Connexion, pair: Identifiant) -> Result<(), Faute> {
        loop {
            let curseur = self.entrepot.curseur(pair).map_err(Faute::Entrepot)?;
            let flux = connexion
                .ouvrir_flux(format!("/v1/pair/operations?apres={curseur}").as_bytes())
                .await?;

            match connexion.statut_du_flux(flux).await? {
                200 => {
                    let lu = self.lire_le_flux(connexion, pair, flux, false).await?;
                    match lu.fin {
                        // Le rattrapage se dit avec son nombre (§8) — une fois,
                        // quand il y a eu quelque chose à rattraper.
                        FinDeFlux::Coupe => {
                            if lu.cadres == 0 {
                                // Un pair qui coupe sans rien porter ne dit
                                // rien : ne pas tourner en rond sur lui.
                                return Err(Faute::FluxVide);
                            }
                            if lu.cadres > 0 && curseur > 0 && lu.rattrapes > 0 {
                                (self.journal)(format!(
                                    "voie vers {pair} : rattrapage de {} opérations après                                      {curseur}, la suite dans le flux suivant",
                                    lu.rattrapes
                                ));
                            }
                        }
                        FinDeFlux::Morte => return Ok(()),
                        // Un cadre de fin n'a rien à faire dans le flux des
                        // opérations : le pair a fait quelque chose de
                        // travers, et l'on rompt plutôt que de deviner.
                        FinDeFlux::Fin => return Err(Faute::FinHorsInstantane),
                    }
                }
                410 => {
                    (self.journal)(format!(
                        "voie vers {pair} : le journal ne remonte plus jusqu'à {curseur} (410),                          amorçage par instantané"
                    ));
                    self.amorcer(connexion, pair).await?;
                    // On boucle : `GET /v1/pair/operations` reprend au compteur
                    // de coupe que l'instantané a posé.
                }
                autre => return Err(Faute::Statut(autre)),
            }
        }
    }

    /// L'amorçage : lire l'instantané jusqu'au cadre de fin, part après part,
    /// et tout appliquer.
    ///
    /// Un flux qui se ferme SANS cadre de fin a porté sa part : la connexion
    /// tient le reste, et `GET /v1/pair/instantane` sur elle continue là où
    /// le flux s'est arrêté (`crate::h3`). Le cadre de fin pose le curseur.
    async fn amorcer(&self, connexion: &mut Connexion, pair: Identifiant) -> Result<(), Faute> {
        let mut cadres = 0_usize;
        let mut octets = 0_usize;
        let mut parts = 0_usize;
        loop {
            let flux = connexion.ouvrir_flux(b"/v1/pair/instantane").await?;
            match connexion.statut_du_flux(flux).await? {
                200 => {}
                autre => return Err(Faute::Statut(autre)),
            }
            let lu = self.lire_le_flux(connexion, pair, flux, true).await?;
            cadres = cadres.saturating_add(lu.cadres);
            octets = octets.saturating_add(lu.octets);
            parts = parts.saturating_add(1);
            match lu.fin {
                FinDeFlux::Fin => {
                    // L'amorçage se dit avec sa taille (§8).
                    (self.journal)(format!(
                        "voie vers {pair} : amorcé par instantané — {cadres} cadres,                          {octets} octets, {parts} parts"
                    ));
                    return Ok(());
                }
                // Une part vide et sans fin : le pair n'a rien à continuer, et
                // n'en dit pas la fin. On ne tourne pas en rond.
                FinDeFlux::Coupe if lu.cadres == 0 => return Err(Faute::InstantaneTronque),
                FinDeFlux::Coupe => {}
                FinDeFlux::Morte => return Err(Faute::InstantaneTronque),
            }
        }
    }

    /// Lit les cadres d'un flux tenu, et les applique par lots, à mesure.
    ///
    /// En mode instantané, le cadre de fin termine la lecture. Dans les deux
    /// modes, un flux que le pair ferme rend [`FinDeFlux::Coupe`], et une
    /// connexion qui tombe [`FinDeFlux::Morte`].
    async fn lire_le_flux(
        &self,
        connexion: &mut Connexion,
        pair: Identifiant,
        flux: StreamId,
        instantane: bool,
    ) -> Result<Lecture, Faute> {
        let mut reste: Vec<u8> = Vec::new();
        let mut lecture = Lecture::default();
        loop {
            let arrive = connexion.prendre_le_corps(flux);
            lecture.octets = lecture.octets.saturating_add(arrive.len());
            reste.extend_from_slice(&arrive);
            // **CE QUI EST ENTIER FORME UN LOT.** On découpe tout ce qu'on
            // peut, puis on applique en une transaction.
            let mut lot: Vec<Cadre> = Vec::new();
            let mut fin_vue = false;
            loop {
                // **RIEN À DÉCODER N'EST PAS UN CADRE ILLISIBLE.** `Cadre::lire`
                // sur zéro octet lit un genre nul et rend une étiquette
                // inconnue ; ce n'est pas une corruption, c'est un flux qui se
                // tait. On attend d'autres octets.
                if reste.is_empty() || fin_vue {
                    break;
                }
                match Cadre::lire(&reste) {
                    Ok((cadre, combien)) => {
                        reste.drain(..combien.min(reste.len()));
                        fin_vue = matches!(cadre, Cadre::Fin { .. });
                        lot.push(cadre);
                    }
                    // Il manque des octets : on en attend d'autres.
                    Err(asl_registre::Faute::Tronquee { .. }) => break,
                    // Un cadre illisible ferme la voie ; il ne se saute pas
                    // (§5.2). Le curseur n'a pas bougé, l'exploitant le lit, et
                    // la reprise réessaiera la même opération.
                    Err(quoi) => {
                        (self.journal)(format!(
                            "voie vers {pair} : un cadre ne se décode pas ({quoi:?}) — la voie                              se ferme, rien n'est sauté"
                        ));
                        return Err(Faute::CadreIllisible(quoi));
                    }
                }
            }
            if !lot.is_empty() {
                lecture.cadres = lecture.cadres.saturating_add(lot.len());
                let appliques = self.appliquer_un_lot(pair, lot, instantane).await?;
                lecture.rattrapes = lecture.rattrapes.saturating_add(appliques);
            }
            if fin_vue {
                // L'instantané est fini : le flux se ferme derrière.
                lecture.fin = FinDeFlux::Fin;
                return Ok(lecture);
            }
            // Le pair a-t-il fini d'écrire ce flux sans qu'on ait vu de fin ?
            // Il a porté sa part ; le reste attend le flux suivant.
            if connexion.flux_fini(flux) && reste.is_empty() {
                lecture.fin = FinDeFlux::Coupe;
                return Ok(lecture);
            }
            connexion.entretenir(REPONSE_MS.min(500)).await?;
            if !connexion.vivante() {
                lecture.fin = FinDeFlux::Morte;
                return Ok(lecture);
            }
        }
    }

    /// Applique ce lot en une transaction, journalise chaque refus avec son
    /// genre et son compteur (§8), transmet ce qu'il faut fermer, et rend
    /// combien d'opérations ont été appliquées.
    ///
    /// # L'ÉCRITURE SE FAIT HORS DE LA BOUCLE
    ///
    /// `appliquer_la_suite` est synchrone : une transaction `redb`, et un
    /// `fsync`. Appelée ici même, elle tenait un fil du runtime le temps de
    /// l'écriture — et la boucle QUIC de cette racine, UNE tâche qui sert
    /// toutes ses connexions, pouvait rester à l'arrêt tout un amorçage :
    /// plus de réponse à personne, keepalives compris. Mesuré le 2026-09-25
    /// (deux binaires en alternance, même charge) : l'essai qui amorce
    /// plusieurs milliers d'enregistrements tombait six fois sur dix, zéro
    /// une fois l'écriture déportée. `spawn_blocking` et non `block_in_place`,
    /// qui panique sous un runtime à un fil.
    async fn appliquer_un_lot(
        &self,
        pair: Identifiant,
        lot: Vec<Cadre>,
        instantane: bool,
    ) -> Result<usize, Faute> {
        let entrepot = Arc::clone(&self.entrepot);
        let (lot, verdicts) = tokio::task::spawn_blocking(move || {
            let verdicts = entrepot.appliquer_la_suite(pair, &lot, instantane);
            (lot, verdicts)
        })
        .await
        .map_err(|arret| match arret.try_into_panic() {
            // Une panique de l'entrepôt remonte comme avant, dans cette tâche.
            Ok(panique) => std::panic::resume_unwind(panique),
            Err(_) => Faute::Interrompue,
        })?;
        let verdicts = verdicts.map_err(Faute::Entrepot)?;
        let mut appliquees = 0_usize;
        for (cadre, verdict) in lot.iter().zip(verdicts) {
            match verdict {
                Applique::Faite { effets, .. } => {
                    appliquees = appliquees.saturating_add(1);
                    // **UN EFFACEMENT DE COMPTE SE DIT, « APPLIQUÉ » ET NON
                    // « EFFACÉ »** (`replication.md` §3.3, §8) : l'identifiant,
                    // la cause portée par l'opération, et rien d'autre. Qui a
                    // effacé est dit par l'estampille. **Une attestation
                    // aussi** (2026-09-21) : c'est ce qu'un appareil a prouvé
                    // chez l'autre racine, et l'exploitant qui lit « attesté »
                    // ici doit savoir que ce n'est pas ici qu'on l'a jugé. Ce
                    // sont les deux seules opérations qui aient leur ligne —
                    // jamais une ligne par opération.
                    if let Cadre::Operation { operation, .. } = cadre {
                        match operation {
                            Operation::CompteEfface { compte, cause, .. } => {
                                (self.journal)(format!(
                                    "compte {compte} appliqué : effacé chez {pair}, cause {cause}"
                                ));
                            }
                            Operation::AppareilAtteste { appareil, atteste } => {
                                (self.journal)(format!(
                                    "appareil {appareil} appliqué : attesté {} chez {pair}",
                                    match atteste {
                                        asl_registre::Attestation::Apple => "apple",
                                        asl_registre::Attestation::Android => "android",
                                        asl_registre::Attestation::Invitation => "invitation",
                                        asl_registre::Attestation::Aucune
                                        | asl_registre::Attestation::Attendue => "sans preuve",
                                    }
                                ));
                            }
                            _ => {}
                        }
                    }
                    for quoi in effets.a_fermer {
                        self.fermetures.fermer(quoi);
                    }
                }
                Applique::Fin { curseur } => {
                    (self.journal)(format!(
                        "voie vers {pair} : cadre de fin, curseur posé à {curseur}"
                    ));
                }
                // **UN REFUS NE FERME PAS LA VOIE** : un recul est une
                // relivraison, un rejeu et une provenance hors périmètre sont
                // des anomalies — on journalise avec le genre et le compteur
                // (§8), sans rompre, et l'exploitant regarde.
                Applique::Refusee(motif) => {
                    if let Cadre::Operation {
                        estampille,
                        operation,
                    } = cadre
                    {
                        (self.journal)(format!(
                            "voie vers {pair} : opération refusée — {}, genre {:?},                              compteur {}",
                            motif_en_mots(motif),
                            operation.genre(),
                            estampille.compteur
                        ));
                    }
                }
            }
        }
        Ok(appliquees)
    }
}

/// Ce qu'une lecture de flux a donné.
#[derive(Debug, Default)]
struct Lecture {
    /// Comment le flux s'est terminé.
    fin: FinDeFlux,
    /// Combien de cadres il a portés.
    cadres: usize,
    /// Combien d'octets il a portés.
    octets: usize,
    /// Combien d'opérations ont été appliquées — les refus en moins.
    rattrapes: usize,
}

/// Le motif d'un refus, en mots (§8).
const fn motif_en_mots(motif: MotifDeRefus) -> &'static str {
    match motif {
        MotifDeRefus::Recule => "elle recule sur le curseur",
        MotifDeRefus::Rejeu => "elle porte notre propre racine (rejeu)",
        MotifDeRefus::HorsProvenance => "sa provenance n'est pas locale (C11)",
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
    /// Un instantané s'est terminé sans cadre de fin, et le pair n'a rien à
    /// continuer.
    InstantaneTronque,
    /// Le pair a fermé un flux d'opérations sans y avoir rien porté.
    FluxVide,
    /// Un cadre de fin est arrivé sur le flux des opérations.
    FinHorsInstantane,
    /// L'entrepôt a refusé.
    Entrepot(asl_store::Faute),
    /// L'application d'un lot a été annulée avant de commencer : l'annuaire
    /// s'arrête, et rien n'a été écrit.
    Interrompue,
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
            Self::FluxVide => f.write_str("le pair a fermé un flux d'opérations vide"),
            Self::FinHorsInstantane => {
                f.write_str("un cadre de fin est arrivé sur le flux des opérations")
            }
            Self::Entrepot(quoi) => write!(f, "l'entrepôt a refusé : {quoi}"),
            Self::Interrompue => {
                f.write_str("l'application d'un lot a été annulée : l'annuaire s'arrête")
            }
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

/// Le nom du certificat qu'on exige d'en face : la part `hôte` de l'adresse.
///
/// Une adresse IPv6 se donne entre crochets (`[::1]:6630`) ; le certificat,
/// lui, porte l'adresse nue.
pub(crate) fn nom_tls(adresse: &str) -> String {
    let sans_port = adresse.rsplit_once(':').map_or(adresse, |(hote, _)| hote);
    sans_port
        .strip_prefix('[')
        .and_then(|reste| reste.strip_suffix(']'))
        .unwrap_or(sans_port)
        .to_owned()
}

/// Résout `hôte:port` — **à chaque fois**, car le DNS peut bouger sous nous.
///
/// IPv6 d'abord, comme partout dans ce produit ; mais on prend ce qu'il y a
/// quand il n'y a que de l'IPv4.
///
/// # Errors
///
/// [`Faute::Socket`] si le résolveur refuse, [`Faute::SansAdresse`] s'il ne
/// rend rien.
pub(crate) async fn resoudre(adresse: &str) -> Result<SocketAddr, Faute> {
    tokio::net::lookup_host(adresse)
        .await
        .map_err(Faute::Socket)?
        .max_by_key(|adresse| u8::from(adresse.is_ipv6()))
        .ok_or(Faute::SansAdresse)
}

// ── La connexion QUIC sortante ──────────────────────────────────────────────

/// Une connexion cliente vers l'autre racine.
///
/// **Visible dans la crate**, et non plus seulement ici : l'exploitant qui
/// émet une invitation ([`crate::exploitant`]) ouvre exactement la même
/// connexion — QUIC, HTTP/3, une racine épinglée, une liaison de canal. Deux
/// bootstraps QUIC dans un même binaire auraient divergé au premier réglage.
pub(crate) struct Connexion {
    socket: UdpSocket,
    quic: Box<Connection>,
    h3: Http3Client,
    pub(crate) liaison: LiaisonDeCanal,
    autorite: String,
}

impl Connexion {
    /// Ouvre une connexion et mène la poignée de main au bout.
    pub(crate) async fn ouvrir(
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
    pub(crate) fn maintenir(&mut self, keepalive_us: u64) {
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
    pub(crate) async fn requete(
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
    pub(crate) async fn defi(&mut self) -> Result<Defi, Faute> {
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
