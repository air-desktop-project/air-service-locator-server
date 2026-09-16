//! L'application HTTP/3 : elle relie la boucle QUIC à ce qui décide.
//!
//! # ELLE NE DÉCIDE RIEN, ET C'EST LA TROISIÈME FOIS QU'ON LE DIT
//!
//! `asl-session` décide de la réponse — statut, corps, champs — et le fait
//! **sans entrée-sortie**, sous le régime de couverture. `ams-h3` sait quel flux
//! ouvrir et dans quel ordre. Ce module ne fait que les présenter l'un à
//! l'autre, connexion par connexion.
//!
//! # C'EST ICI QUE LE BESOIN EST SATISFAIT, ET NULLE PART AILLEURS
//!
//! `asl-session` ne lit pas l'entrepôt : elle dit ce qu'il lui faut
//! (`besoin`), et répond quand on le lui apporte (`repondre`). **L'entre-deux
//! est ici**, parce que c'est le seul étage qui a le droit d'attendre.
//!
//! Ce n'est pas un détour : `ams_h3::Service::serve` doit rendre une réponse
//! SYNCHRONE, donc quelqu'un doit tenir les deux bouts. Que ce soit l'étage 3
//! est ce qui garde à l'étage 2 sa propriété — **il ne peut pas attendre, parce
//! qu'il n'a personne à appeler.**
//!
//! # UNE SESSION PAR CONNEXION, ET C'EST LE BAIL QUI L'EXIGE
//!
//! `asl_session::Session` portera la machine authentifiée : la connexion QUIC
//! **est** le bail, et ce qu'une requête a le droit de faire dépend de qui a
//! signé le défi au début de CETTE connexion-là. Une session partagée entre
//! connexions ferait hériter une requête des droits d'une autre — c'est la
//! faille qu'on ne peut pas se permettre.
//!
//! Elle est donc rangée avec le conducteur, sous l'identifiant local de la
//! connexion, et les deux disparaissent ensemble.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;

use ams_h3::{Http3, Reponse};
use ams_proto_http::RequestHead;
use ams_proto_quic::StreamId;
use ams_quic_tls::Connection;
use asl_api::corps::PlateformeAttestation;
use asl_cle::{CleAppareil, ClePublique, CleSecrete, Defi};
use asl_id::Identifiant;
use asl_session::{
    Besoin, CleTrouvee, EtatDeLaReplication, Resolution, Session, Trouvaille, VoieVersLePair,
};
use asl_store::{Entrepot, Rattrapage};
use sha2::{Digest, Sha256};

use crate::sonde::{self, Verdict};
use crate::tireur::EtatDeLaVoie;
use crate::vivier::Vivier;

use crate::pont::Pont;
use crate::quic::{Application, maintenant};

/// Ce qu'on tient pour une connexion vivante.
struct ParConnexion {
    /// Le conducteur HTTP/3 : flux de contrôle, QPACK, cadrage.
    conducteur: Http3,
    /// Ce qui décide des réponses de CETTE connexion.
    session: Session,
    /// Le flux que l'autre racine tient sur cette connexion, s'il y en a un.
    ///
    /// **UN SEUL**, et `asl-session` rend `409` au second : ce qui est poussé
    /// sur une connexion va à SON flux, et deux flux avec deux curseurs y
    /// liraient la même chose.
    flux_pair: Option<FluxPair>,
    /// Ce qu'il reste d'un instantané que cette connexion a commencé à
    /// tirer, part après part (voir [`PART_OCTETS_MAX`]).
    ///
    /// # L'INSTANTANÉ VIT AVEC LA CONNEXION QUI L'A DEMANDÉ
    ///
    /// Il est lu dans UNE transaction, et ses parts doivent venir de cette
    /// lecture-là : en recalculer une entre deux parts glisserait le compteur
    /// de coupe sous des écritures que la première part n'a pas vues. Le reste
    /// est donc tenu ici, et `GET /v1/pair/instantane` sur cette connexion le
    /// continue. La connexion tombe, le reste tombe avec elle, et le tireur
    /// redemande un instantané entier — qui fusionne, sans dommage.
    reste_d_instantane: Option<VecDeque<Vec<u8>>>,
}

/// Ce qu'un flux de la voie porte AU PLUS, en octets de charge `DATA`.
///
/// # LA PILE ANNONCE SEIZE KIBIOCTETS PAR FLUX, ET NE LES RELÈVE JAMAIS
///
/// `ams_quic_tls::FLUX_OCTETS` est la fenêtre de réception qu'un pair annonce
/// pour chaque flux, et la pile n'émet aucun `MAX_STREAM_DATA` : un flux ne
/// porte donc jamais plus de seize kibioctets dans un sens, sur toute sa vie.
/// Au-delà, `write` ne prend plus rien et rien ne le dit — un flux
/// d'opérations « sans fin » s'y taisait au bout de quelques dizaines
/// d'écritures.
///
/// **On coupe donc chaque flux à une PART**, à une frontière de cadre, et le
/// tireur en rouvre un sur la même connexion (`crate::tireur`). Douze
/// kibioctets de charge laissent quatre kibioctets à la section d'en-têtes et
/// aux en-têtes de trame, qui comptent dans la même fenêtre. C'est la borne
/// qui reste ; l'autre est l'instantané entier, tenu en mémoire par
/// connexion, dont la taille est celle de l'entrepôt.
pub const PART_OCTETS_MAX: usize = 12 * 1_024;

/// La fenêtre qu'un flux reçoit, telle que la pile l'annonce — la valeur de
/// `ams_quic_tls::connection::FLUX_OCTETS`, qui n'est pas exportée.
///
/// **Recopiée, donc à tenir d'accord** : le jour où la pile relèvera ses
/// fenêtres, cette constante et la part qu'elle borne deviendront un choix, et
/// non plus une contrainte. L'essai `un_grand_instantane_passe_par_parts…` de
/// `tests/bout_en_bout.rs` éprouve la part contre la vraie pile.
const FENETRE_D_UN_FLUX: usize = 16 * 1_024;

const _: () = assert!(
    PART_OCTETS_MAX + 4 * 1_024 <= FENETRE_D_UN_FLUX,
    "une part et ses en-têtes doivent tenir dans la fenêtre d'un flux"
);

/// Un flux de la voie entre racines, tenu sur une connexion : une part des
/// opérations, ou une part de l'instantané.
///
/// # CE QUI EST EN ATTENTE, ET POURQUOI IL Y A UNE ATTENTE
///
/// `ams_quic_tls::Connection::write` ne prend pas forcément tout : ce qui
/// attend d'être émis est borné (C3), et le reste se réécrit quand la place
/// se libère. `ams_h3::Http3::pousser` ignore ce reste — une poussée de
/// verdict tient dans la place —, mais un rattrapage ou un instantané ne
/// tiennent pas. On cadre donc les trames `DATA` nous-mêmes, une par lot de
/// cadres qui tient dans ce que la part peut encore porter, on écrit ce qui
/// entre, et on garde le reste ici pour le tour suivant. **Tant qu'il reste
/// quelque chose, on ne relit pas le journal** : c'est la contre-pression,
/// et c'est ce qui borne la mémoire à un instantané, jamais plus.
struct FluxPair {
    /// Le flux, tel que la réponse tenue l'a laissé ouvert.
    flux: StreamId,
    /// La trame `DATA` en cours, pas encore prise entière par le transport.
    en_attente: Vec<u8>,
    /// Les cadres pas encore cadrés pour ce flux, dans l'ordre.
    a_venir: VecDeque<Vec<u8>>,
    /// Ce que ce flux a déjà cadré, en octets de charge : la part.
    portes: usize,
    /// Le compteur de la dernière opération relue du journal — `None` pour un
    /// instantané, qui ne suit rien.
    curseur: Option<u64>,
    /// Jusqu'où le journal a été regardé (`Entrepot::derniere_operation`).
    ///
    /// C'est ce que chaque tour compare : tant que rien n'a été journalisé
    /// depuis, il n'y a rien à relire, et le tour ne coûte qu'une lecture
    /// d'entier.
    vu_jusqu_a: u64,
    /// Fermer le flux une fois l'attente vidée : la part est pleine,
    /// l'instantané est entièrement cadré, ou le journal s'est expiré sous le
    /// lecteur.
    a_clore: bool,
}

impl FluxPair {
    /// Cadre la prochaine trame `DATA` depuis ce qui est à venir, dans ce que
    /// la part peut encore porter — et dit s'il faut clore après elle.
    ///
    /// **À UNE FRONTIÈRE DE CADRE, TOUJOURS** : un cadre coupé entre deux flux
    /// serait illisible des deux côtés, et le tireur repart à neuf sur chaque
    /// flux.
    fn cadrer_une_trame(&mut self) {
        if !self.en_attente.is_empty() {
            return;
        }
        let budget = PART_OCTETS_MAX.saturating_sub(self.portes);
        let mut pris = Vec::new();
        let mut total = 0_usize;
        while let Some(cadre) = self.a_venir.front() {
            let apres = total.saturating_add(cadre.len());
            if apres > budget {
                break;
            }
            total = apres;
            if let Some(cadre) = self.a_venir.pop_front() {
                pris.push(cadre);
            }
        }
        if !pris.is_empty() {
            self.en_attente = trame_de_donnees(&pris);
            self.portes = self.portes.saturating_add(total);
        }
        // La part est pleine et il reste à porter : ce sera le flux suivant.
        // Ou l'instantané est entièrement cadré : il se ferme derrière sa fin.
        if (!self.a_venir.is_empty() && pris.is_empty())
            || (self.a_venir.is_empty() && self.curseur.is_none())
        {
            self.a_clore = true;
        }
    }

    /// Y a-t-il encore quelque chose à faire sur ce flux, ce tour-ci ?
    fn a_pousser(&self) -> bool {
        !self.en_attente.is_empty() || !self.a_venir.is_empty() || self.a_clore
    }
}

/// Ce qu'une requête de la voie a préparé, et que la boucle poussera sur le
/// flux de cette requête juste après la réponse.
///
/// `asl_session::Service::serve` ne connaît pas le flux qu'il sert ; la boucle,
/// elle, le connaît (`a_la_lecture`). Le service dépose donc ici, et la boucle
/// ramasse.
struct SuiteAuPair {
    /// Les cadres à écrire, chacun tel que le fil le porte.
    cadres: VecDeque<Vec<u8>>,
    /// Le curseur à partir duquel suivre le journal, ou `None` pour un
    /// instantané qui se ferme après ses cadres.
    curseur: Option<u64>,
    /// Ce que le journal portait quand les cadres ont été lus.
    vu_jusqu_a: u64,
}

/// La voie entre racines, telle que l'exploitant l'a réglée.
///
/// # DEUX CLÉS, CONNUES D'AVANCE, ET AUCUNE LISTE (`replication.md` §2.2)
///
/// Notre clé d'identité signe la preuve de racine que le tireur demande ; la
/// clé de l'autre racine est celle contre laquelle sa preuve se vérifie. L'une
/// sans l'autre a un sens : un annuaire peut avoir une identité et pas de
/// pair — il tourne seul —, et c'est `asl-server` qui refuse un pair sans
/// identité.
#[derive(Clone, Copy)]
pub struct Voie<'a> {
    /// Notre clé d'identité Ed25519, si l'exploitant en a donné une.
    pub identite: Option<&'a CleSecrete>,
    /// La clé d'identité de l'autre racine (`--peer-key`), si elle est réglée.
    pub pair: Option<ClePublique>,
    /// Où dire l'ouverture et la fermeture de chaque sens, un rattrapage avec
    /// son nombre d'opérations, un amorçage avec sa taille — le journal
    /// d'exploitation de `replication.md` §8. **Jamais une opération par
    /// ligne.**
    pub journal: &'a (dyn Fn(&str) + Send + Sync),
    /// L'état de la voie SORTANTE, que le tireur publie et que
    /// `GET /v1/replication` lit — `None` sans tireur.
    pub etat: Option<&'a EtatDeLaVoie>,
}

impl Voie<'static> {
    /// Aucune identité, aucun pair, et rien à dire : un annuaire seul.
    pub const AUCUNE: Self = Self {
        identite: None,
        pair: None,
        journal: &taire,
        etat: None,
    };
}

/// Ne dit rien.
fn taire(_: &str) {}

/// Une trame `DATA` qui porte ces cadres à la suite, sans enveloppe.
///
/// Vide si rien n'est à porter : une trame de zéro octet ne dit rien de plus
/// que son absence.
fn trame_de_donnees(cadres: &[Vec<u8>]) -> Vec<u8> {
    let combien: usize = cadres.iter().map(Vec::len).sum();
    if combien == 0 {
        return Vec::new();
    }
    let mut entete = [0_u8; 16];
    let pose = ams_proto_h3::write_header(
        ams_proto_h3::FrameKind::Data,
        u64::try_from(combien).unwrap_or(u64::MAX),
        &mut entete,
    )
    .unwrap_or(0);
    let mut trame = Vec::with_capacity(pose.saturating_add(combien));
    trame.extend_from_slice(entete.get(..pose).unwrap_or_default());
    for cadre in cadres {
        trame.extend_from_slice(cadre);
    }
    trame
}

/// Le compteur du dernier cadre, tel que son estampille le porte.
///
/// `None` si un cadre ne se relit pas — le journal est corrompu, et le flux se
/// ferme plutôt que de pousser ce qu'on ne sait pas lire.
fn dernier_compteur(cadres: &[Vec<u8>]) -> Option<u64> {
    let dernier = cadres.last()?;
    let (estampille, _, _) = asl_registre::Operation::lire(dernier).ok()?;
    Some(estampille.compteur)
}

/// Ce qui sert une requête : la session décide, l'entrepôt fournit.
///
/// # POURQUOI CE TYPE EXISTE
///
/// `ams_h3::Service` veut un seul objet ; le travail en demande deux. Celui-ci
/// les tient le temps d'une requête, et **c'est lui qui fait le voyage à
/// l'entrepôt** — entre `besoin` et `repondre`, là où l'étage 2 ne peut pas
/// aller.
/// De quoi vérifier une attestation Apple, tel que l'exploitant l'a fourni.
///
/// La racine d'Apple est la même pour tous (`asl_apple::RACINE_APPLE`) ; seuls
/// l'identifiant de l'app et l'environnement viennent du binaire. Absent, aucune
/// attestation Apple ne se vérifie — et un compte qui en déclare une est refusé.
#[derive(Debug, Clone, Copy)]
pub struct ConfigApple<'a> {
    /// L'identifiant de l'app, `<équipe>.<bundle>`.
    pub identifiant_app: &'a str,
    /// L'environnement attendu.
    pub environnement: asl_apple::Environnement,
}

/// De quoi vérifier une attestation de clé Android, tel que l'exploitant l'a
/// fourni (`protocole.md` §2.1, décidé le 2026-09-16 ; C19).
///
/// **Ici, même la racine vient de l'exploitant** : c'est un fichier PEM
/// (`--android-roots`), celle de Google, de GrapheneOS, ou la sienne — aucune
/// n'est dans le binaire. Absent, aucune attestation Android ne se vérifie, et
/// un compte qui en déclare une est refusé.
#[derive(Debug, Clone, Copy)]
pub struct ConfigAndroid<'a> {
    /// Les racines épinglées, en DER, au moins une.
    pub racines: &'a [Vec<u8>],
    /// Le nom de notre paquet, `org.airdesktop.servicelocator`.
    pub paquet: &'a str,
    /// L'empreinte SHA-256 du certificat qui signe notre build.
    pub signataire: [u8; 32],
}

/// De quoi vérifier les attestations, plate-forme par plate-forme — chacune
/// absente tant que l'exploitant ne l'a pas réglée.
#[derive(Debug, Clone, Copy)]
pub struct Attestations<'a> {
    /// Apple App Attest (`--apple-app`, `--apple-environment`).
    pub apple: Option<ConfigApple<'a>>,
    /// L'attestation de clé d'Android (`--android-roots`, `--android-app`,
    /// `--android-signer`).
    pub android: Option<ConfigAndroid<'a>>,
}

impl Attestations<'static> {
    /// Aucune plate-forme réglée : toute attestation déclarée est refusée.
    pub const AUCUNE: Self = Self {
        apple: None,
        android: None,
    };
}

struct Service<'a> {
    /// Ce qui décide.
    session: &'a mut Session,
    /// Ce que l'annuaire exige d'un appareil qui s'enrôle.
    politique: asl_auth::Politique,
    /// De quoi vérifier les attestations, si l'exploitant l'a fourni.
    attestations: Attestations<'a>,
    /// Le bail qu'on accorde à une annonce servie sur cette requête.
    bail: asl_proto::Bail,
    /// Les pairs qu'une révocation vient de condamner, sur CETTE requête.
    ///
    /// **Ce sont des pairs, pas des connexions** : la requête qui révoque ne
    /// sait pas quelles connexions ce pair tient — c'est `Annuaire` qui les
    /// connaît, et qui traduira. Voir `Annuaire::au_tour`.
    a_fermer: &'a mut Vec<Identifiant>,
    /// Ce qui se souvient.
    entrepot: &'a Entrepot,
    /// Ce qui vit.
    vivier: &'a mut Vivier,
    /// L'identifiant local de la connexion, pour attribuer les annonces.
    connexion: Vec<u8>,
    /// De quoi tirer un identifiant de service, si l'annonce en crée un.
    tirer_un_identifiant: &'a (dyn Fn() -> Option<[u8; 16]> + Send + Sync),
    /// Le corps de la requête, pour l'annonce qui doit le décoder.
    corps: Vec<u8>,
    /// Par où les sondes rapportent.
    rapports: tokio::sync::mpsc::UnboundedSender<Verdict>,
    /// Combien de sondes sont en vol, pour ne pas en lancer sans fin.
    en_vol: &'a mut usize,
    /// D'où l'on VOIT ce pair.
    ///
    /// **C'est le seul fait qu'on ait constaté plutôt qu'entendu**, et c'est ce
    /// qui permet le verdict de NAT : `asl-annuaire` compare cette adresse à
    /// celles que le daemon annonce.
    vu_depuis: asl_proto::VuDepuis,
    /// De quoi tirer un défi, si le noyau en a donné.
    ///
    /// **L'ENTROPIE EST UNE ENTRÉE-SORTIE**, donc elle est ici et pas à
    /// l'étage 2. Le défi est tiré à chaque requête, qu'il serve ou non : le
    /// tirer paresseusement demanderait de savoir d'avance si la session en
    /// aura besoin, ce qui est précisément ce qu'elle seule sait.
    ///
    /// **`None` QUAND LE NOYAU A REFUSÉ**, et surtout pas un défi de repli : un
    /// défi prévisible ne défie personne, et se replier en silence serait pire
    /// que de rendre l'erreur. `asl-session` répond alors `500`.
    defi: Option<Defi>,
    /// La voie entre racines : nos clés, et où dire ce qui s'y passe.
    voie: Voie<'a>,
    /// L'identifiant `n-…` que la clé du pair donne — `None` sans pair.
    pair_attendu: Option<Identifiant>,
    /// Cette connexion tient-elle déjà un flux de la voie ?
    flux_pair_tenu: bool,
    /// Ce que la requête a préparé pour son flux, que la boucle poussera.
    suite: &'a mut Option<SuiteAuPair>,
    /// Ce qu'il reste d'un instantané que cette connexion tire par parts.
    reste_d_instantane: &'a mut Option<VecDeque<Vec<u8>>>,
}

impl ams_h3::Service for Service<'_> {
    fn serve<'o>(
        &mut self,
        tete: &RequestHead<'_>,
        corps: &[u8],
        sortie: &'o mut [u8],
    ) -> Reponse<'o> {
        let besoin = asl_session::besoin(self.session, tete, corps);
        self.corps = corps.to_vec();
        let trouvaille = self.chercher(&besoin);
        asl_session::repondre(self.session, &besoin, &trouvaille, self.defi, sortie)
    }
}

impl Service<'_> {
    /// Va chercher ce que la session a demandé.
    ///
    /// # UNE FAUTE DE L'ENTREPÔT REND `Rien`, ET IL FAUT LE DIRE
    ///
    /// Une base qui refuse et un compte qui n'existe pas donnent la même
    /// réponse : `404`. **Ce n'est pas satisfaisant**, et c'est délibéré tant
    /// qu'il n'y a pas de journal d'exploitation : distinguer les deux dans la
    /// RÉPONSE dirait à un inconnu que notre base a un problème, et c'est
    /// précisément ce qu'on ne veut pas lui apprendre. La distinction ira au
    /// journal, quand il existera.
    fn chercher(&mut self, besoin: &Besoin<'_>) -> Trouvaille {
        match besoin {
            Besoin::Deja(_) | Besoin::DefiATirer => Trouvaille::Rien,

            // **C'EST ICI QUE L'ANNONCE VIT.** Voir `annoncer`.
            // **C'EST LE SEUL BESOIN QUE L'ÉTAGE 3 SATISFAIT SANS RIEN LIRE.**
            // Le fait demandé n'est ni dans l'entrepôt ni dans la requête : il
            // est dans la socket, et seul cet étage la tient.
            Besoin::OuSuisJeVu => Trouvaille::VuDepuis(self.vu_depuis),
            // **LA VERSION DU WORKSPACE, EN LOCKSTEP** : toutes les crates la
            // partagent (`Cargo.toml`), donc celle-ci est celle du binaire, et
            // `scripts/check-version.sh` tient l'égalité.
            Besoin::Version => Trouvaille::Version(env!("CARGO_PKG_VERSION")),

            Besoin::Annoncer => self
                .annoncer()
                .map_or(Trouvaille::Rien, Trouvaille::Annoncee),

            // **LA CLÉ VIENT DE L'ENREGISTREMENT DE LA MACHINE**, et rien
            // d'autre : une machine inconnue, une clé illisible et une
            // signature fausse donnent le même refus, et c'est `asl-session`
            // qui le compose.
            // **DEUX GENRES PROUVENT UNE CLÉ ICI** : une machine, ou un
            // appareil. Le genre de l'identifiant dit dans quelle table
            // chercher, et il vient de la SIGNATURE — `asl-session` l'a lu du
            // corps, mais c'est le message signé qui le rend contraignant.
            Besoin::ClePourPreuve { machine: qui, .. } => match qui.genre() {
                // **L'AUTRE RACINE NE VIENT PAS DE L'ENTREPÔT** : sa clé est
                // celle de `--peer-key`, une seule, et `asl_auth::decider_pair`
                // dit si le `n-…` présenté est le sien. Un autre rend le refus
                // d'une clé inconnue (`protocole.md` §3 bis).
                asl_id::Genre::Annuaire => match self.voie.pair {
                    Some(cle) if asl_auth::decider_pair(*qui, self.pair_attendu).permet() => {
                        Trouvaille::Cle(CleTrouvee::Racine(cle))
                    }
                    _ => Trouvaille::Rien,
                },
                // **UN APPAREIL SIGNE EN P-256**, et sa clé rangée fait 33
                // octets. La lire comme un Ed25519 échouerait, et une panne de
                // courbe se lirait comme une clé fausse.
                asl_id::Genre::Appareil => match self.entrepot.appareil(*qui).ok().flatten() {
                    Some(appareil) => match CleAppareil::depuis_octets(appareil.cle) {
                        Ok(cle) => Trouvaille::Cle(CleTrouvee::Appareil(cle)),
                        Err(_) => Trouvaille::Rien,
                    },
                    None => Trouvaille::Rien,
                },
                // **UNE MACHINE SANS CLÉ NE PROUVE RIEN.** Elle est déclarée et
                // pas encore enrôlée ; c'est `None`, et non trente-deux zéros
                // dont n'importe qui forgerait la signature.
                _ => match self
                    .entrepot
                    .machine(*qui)
                    .ok()
                    .flatten()
                    .and_then(|m| m.cle)
                {
                    Some(liee) => match ClePublique::depuis_octets(liee.cle) {
                        Ok(cle) => Trouvaille::Cle(CleTrouvee::Machine(cle)),
                        Err(_) => Trouvaille::Rien,
                    },
                    None => Trouvaille::Rien,
                },
            },
            Besoin::Compte(qui) => match self.entrepot.compte(*qui) {
                Ok(Some(compte)) => Trouvaille::Compte {
                    qui: *qui,
                    alias: compte.alias,
                },
                Ok(None) | Err(_) => Trouvaille::Rien,
            },
            // ── LA RÉSOLUTION : QUATRE LECTURES, ET TOUTES OU AUCUNE ──────
            //
            // Décider avec trois sur quatre n'aurait pas de sens : si l'une
            // manque, on rend `Rien`, et `asl-session` répond `404` — le même
            // `404` qu'un refus, pour que rien ne dise à qui essaie ce qui
            // existe.
            Besoin::Ou { machine, service } => self
                .rassembler(*machine, service)
                .map_or(Trouvaille::Rien, Trouvaille::Resolution),

            // ── LES VERBES DE LISTE ─────────────────────────────────────
            //
            // **ON RASSEMBLE TOUT, ET L'ÉTAGE 2 ÉCARTE.** Filtrer ici mettrait
            // « un service ne se rend qu'à qui y a droit » à deux endroits, et
            // c'est celle qu'on oublie de corriger qui laisse passer.
            Besoin::OuParNom { service } => {
                Trouvaille::Resolutions(self.rassembler_par_nom(service))
            }
            Besoin::ServicesDeMachine { machine } => self.rassembler_les_services(*machine),
            Besoin::MesMachines => self.rassembler_les_machines(),
            Besoin::MesAppareils => self.rassembler_les_appareils(),
            Besoin::MesAutorisations => self.rassembler_les_autorisations(),
            Besoin::MachinesDe { compte } => self.rassembler_les_machines_de(*compte),
            Besoin::Moi => self.qui_je_suis(),
            // **RIEN À CHERCHER** : ouvrir le flux ne dépend d'aucun état, et
            // ce qui s'y écrira ensuite n'est pas une réponse à une requête.
            Besoin::EcouterLesPoussees => Trouvaille::Rien,

            // ── CE QUI CRÉE ─────────────────────────────────────────────
            //
            // **TOUT SE PASSE ICI**, et rien à l'étage 2 : créer, c'est écrire,
            // et tirer un identifiant, c'est lire l'entropie du noyau. Ce que
            // `asl-session` a fait avant, elle, est ce qu'elle seule pouvait
            // faire : vérifier une preuve contre le défi de cette connexion.
            Besoin::PreuveRefusee => Trouvaille::Rien,
            Besoin::CreerCompte {
                cle,
                plateforme,
                attestation,
                defi_attestation,
            } => self.creer_un_compte(cle, *plateforme, attestation, defi_attestation),
            Besoin::CreerAppareil { cle } => self.creer_un_appareil(cle),
            Besoin::CreerMachine { nom, capacites } => self.creer_une_machine(nom, *capacites),
            Besoin::ModifierMachine {
                machine,
                nom,
                capacites,
            } => self.modifier_une_machine(*machine, *nom, *capacites),
            Besoin::NouveauCode { machine } => self.emettre_un_code(*machine),
            Besoin::Enroler { empreinte, cle } => self.enroler(empreinte, cle),
            Besoin::Autoriser {
                a,
                portee,
                etiquette,
            } => self.autoriser(*a, *portee, etiquette),

            // ── CE QUI RETIRE ───────────────────────────────────────────
            Besoin::PoserJetonDePoussee {
                appareil,
                plateforme,
                jeton,
            } => self.poser_un_jeton(*appareil, *plateforme, jeton),
            Besoin::PoserDescription {
                appareil,
                systeme,
                modele,
            } => self.poser_une_description(*appareil, *systeme, modele),
            Besoin::RevoquerAppareil { appareil } => self.revoquer_un_appareil(*appareil),
            Besoin::RevoquerCleMachine { machine } => self.revoquer_une_cle(*machine),
            Besoin::RevoquerAutorisation { autorisation } => {
                self.revoquer_une_autorisation(*autorisation)
            }
            Besoin::PoserAlias { alias } => self.poser_l_alias(Some(alias)),
            Besoin::RetirerAlias => self.poser_l_alias(None),

            // ── LA VOIE ENTRE RACINES ───────────────────────────────────
            //
            // **LA CLÉ D'IDENTITÉ VIT ICI, ET C'EST ICI QU'ON SIGNE.** Sous
            // le domaine propre de la preuve de racine, avec la liaison de
            // CETTE connexion — celle que le tireur a dérivée de son côté.
            Besoin::ProuverLaRacine { defi } => match self.voie.identite {
                Some(cle) => {
                    let (racine, signature) = cle.prouver_la_racine(defi, self.session.liaison());
                    Trouvaille::PreuveDeRacine { racine, signature }
                }
                None => Trouvaille::Rien,
            },
            Besoin::LireLesOperations { apres } => self.ouvrir_les_operations(*apres),
            Besoin::LireLInstantane => self.ouvrir_l_instantane(),
            // **L'ÉTAT SE LIT AU MOMENT DE LA REQUÊTE, ET NULLE PART N'EST
            // RECOPIÉ** : le compteur et le curseur viennent de l'entrepôt,
            // le seul fait qu'il ne tient pas — la connexion sortante est-elle
            // ouverte — vient du tireur (`EtatDeLaVoie`). Sans pair, « seule ».
            Besoin::EtatDeLaReplication => match self.entrepot.compteur() {
                Ok(compteur) => Trouvaille::Replication(EtatDeLaReplication {
                    compteur,
                    voie: self.pair_attendu.map(|pair| VoieVersLePair {
                        pair,
                        ouverte: self.voie.etat.is_some_and(EtatDeLaVoie::ouverte),
                        applique: self.entrepot.curseur(pair).unwrap_or(0),
                    }),
                }),
                Err(_) => Trouvaille::Rien,
            },

            Besoin::CompteParAlias(alias) => match self.entrepot.compte_par_alias(alias) {
                Ok(Some(qui)) => match self.entrepot.compte(qui) {
                    Ok(Some(compte)) => Trouvaille::Compte {
                        qui,
                        alias: compte.alias,
                    },
                    // **L'INDEX DÉSIGNE UN COMPTE QUI N'EXISTE PAS.** C'est une
                    // incohérence de la base, pas une requête fautive ; on rend
                    // `404` plutôt que d'inventer un compte vide.
                    Ok(None) | Err(_) => Trouvaille::Rien,
                },
                Ok(None) | Err(_) => Trouvaille::Rien,
            },
        }
    }
}

impl Service<'_> {
    /// Le compte au nom duquel cette connexion agit.
    ///
    /// **C'est l'APPAREIL qui a prouvé sa clé qui le désigne**, jamais ce
    /// qu'une requête a nommé. C10 tient par là : aucun verbe d'administration
    /// ne prend un compte en paramètre.
    fn compte_de_la_connexion(&self) -> Option<Identifiant> {
        let appareil = self.session.appareil()?;
        self.entrepot
            .appareil(appareil)
            .ok()
            .flatten()
            // **UN APPAREIL RÉVOQUÉ N'AGIT PLUS**, même sur une connexion qu'il
            // avait authentifiée avant. La connexion est fermée par ailleurs,
            // mais s'en remettre à cette fermeture seule ferait dépendre une
            // règle d'autorisation du bon déroulement d'un tour de boucle.
            .filter(|rangee| !rangee.revoque)
            .map(|rangee| rangee.proprietaire)
    }

    /// Tire un identifiant de ce genre.
    fn un_identifiant(&self, genre: asl_id::Genre) -> Option<Identifiant> {
        Some(Identifiant::depuis_entropie(
            genre,
            (self.tirer_un_identifiant)()?,
        ))
    }

    /// Crée un compte et enrôle l'appareil qui vient de prouver sa clé.
    fn creer_un_compte(
        &self,
        cle: &CleAppareil,
        plateforme: PlateformeAttestation,
        attestation: &[u8],
        defi_attestation: &[u8],
    ) -> Trouvaille {
        // **L'ATTESTATION, D'ABORD.** Elle est ce qui garde ce chemin : il
        // n'exige aucune signature de compte, puisqu'il n'y a pas encore de
        // compte. Un refus ici est `Refus` (403), pas `Rien` (500) : la règle a
        // tranché, ce n'est pas une panne.
        let atteste =
            match self.verifier_l_attestation(plateforme, attestation, defi_attestation, cle) {
                Some(atteste) => atteste,
                None => return Trouvaille::Refus,
            };
        let prouvee = atteste != asl_registre::Attestation::Aucune;
        if asl_auth::decider_attestation(prouvee, self.politique) == asl_auth::Decision::Refuser {
            return Trouvaille::Refus;
        }
        let (Some(compte), Some(appareil)) = (
            self.un_identifiant(asl_id::Genre::Utilisateur),
            self.un_identifiant(asl_id::Genre::Appareil),
        ) else {
            return Trouvaille::Rien;
        };

        if self
            .entrepot
            .creer_compte(compte, asl_registre::Provenance::Ici, None)
            .is_err()
        {
            return Trouvaille::Rien;
        }
        // **CE SOUS QUOI IL EST RÉELLEMENT ENTRÉ**, pour qu'on sache plus tard,
        // compte par compte, qui a été attesté et qui non — le jour où l'on
        // resserre la posture.
        if self
            .entrepot
            .creer_appareil(
                appareil,
                asl_registre::Provenance::Ici,
                compte,
                cle.octets(),
                atteste,
            )
            .is_err()
        {
            return Trouvaille::Rien;
        }
        Trouvaille::CompteCree { compte, appareil }
    }

    /// Vérifie l'attestation, et rend SOUS QUOI l'appareil est entré.
    ///
    /// `None` est un REFUS — la plate-forme est déclarée mais l'attestation ne
    /// prouve rien : elle ne vérifie pas, ou l'annuaire n'a pas de quoi la
    /// vérifier (pas de configuration pour cette plate-forme), ou c'est une
    /// plate-forme qu'on ne sert pas encore (l'invitation). `Some(Aucune)` est
    /// le cas franc où l'application n'a rien présenté ; c'est alors à
    /// `decider_attestation` de dire si l'annuaire l'accepte.
    ///
    /// **Chaque refus est dit au journal d'exploitation, avec sa cause** — et
    /// sans l'attestation elle-même : la cause suffit à l'exploitant, et une
    /// chaîne de certificats n'a rien à faire dans un journal.
    fn verifier_l_attestation(
        &self,
        plateforme: PlateformeAttestation,
        attestation: &[u8],
        defi_attestation: &[u8],
        cle: &CleAppareil,
    ) -> Option<asl_registre::Attestation> {
        let dire = |cause: &str| {
            (self.voie.journal)(&format!("attestation refusée : {cause}"));
        };
        match plateforme {
            PlateformeAttestation::Aucune => Some(asl_registre::Attestation::Aucune),
            PlateformeAttestation::Apple => {
                // La clé de l'appareil est SANS emploi dans la vérification
                // elle-même : le défi la porte déjà
                // (`asl_cle::message_d_attestation`), et c'est ce défi
                // qu'`asl_apple` recompose dans le nonce.
                let Some(config) = self.attestations.apple else {
                    dire("Apple, sans --apple-app ni --apple-environment");
                    return None;
                };
                // **`maintenant()` EST EN MICROSECONDES, ET LES VÉRIFICATEURS
                // VEULENT DES SECONDES.** Jusqu'en 0.8.2, la division était par
                // mille : l'instant tombait en l'an 58 000, et toute chaîne
                // d'Apple aurait été refusée « expirée » — ce que le premier
                // iPhone aurait découvert. Corrigé avec Android, qui prend le
                // même instant.
                let attendu = asl_apple::Attendu {
                    racine: asl_apple::RACINE_APPLE,
                    defi: defi_attestation,
                    identifiant_app: config.identifiant_app,
                    environnement: config.environnement,
                    maintenant: maintenant().saturating_div(1_000_000),
                };
                match asl_apple::verifier(attestation, &attendu) {
                    Ok(_) => Some(asl_registre::Attestation::Apple),
                    Err(refus) => {
                        dire(&format!("Apple, {refus}"));
                        None
                    }
                }
            }
            // **L'ATTESTATION DE CLÉ D'ANDROID** (`protocole.md` §2.1, C19) :
            // le défi posé à la génération de la clé est le SHA-256 du même
            // message que pour Apple, et la clé attestée est la clé enrôlée —
            // `asl_keystore` compare la feuille à `cle`.
            PlateformeAttestation::Android => {
                let Some(config) = self.attestations.android else {
                    dire("Android, sans --android-roots, --android-app ni --android-signer");
                    return None;
                };
                let racines: Vec<&[u8]> = config.racines.iter().map(Vec::as_slice).collect();
                let defi = Sha256::digest(defi_attestation);
                let attendu = asl_keystore::Attendu {
                    racines: &racines,
                    defi: &defi,
                    cle: &cle.octets(),
                    paquet: config.paquet,
                    empreinte: &config.signataire,
                    maintenant: maintenant().saturating_div(1_000_000),
                };
                match asl_keystore::verifier(attestation, &attendu) {
                    Ok(_) => Some(asl_registre::Attestation::Android),
                    Err(refus) => {
                        dire(&format!("Android, {refus}"));
                        None
                    }
                }
            }
            // **L'INVITATION N'EST PAS ENCORE SERVIE.** La posture
            // `--attestation invitation` et l'émission du code par l'exploitant
            // sont un chantier à part (`protocole.md` §2.1) ; en attendant, la
            // plate-forme `3` est refusée franchement, et le journal dit
            // pourquoi.
            PlateformeAttestation::Invitation => {
                dire("invitation, pas encore servie");
                None
            }
        }
    }

    /// Enrôle un appareil de plus sur le compte de cette connexion.
    fn creer_un_appareil(&self, cle: &CleAppareil) -> Trouvaille {
        if asl_auth::decider_attestation(false, self.politique) == asl_auth::Decision::Refuser {
            return Trouvaille::Refus;
        }
        let (Some(compte), Some(appareil)) = (
            self.compte_de_la_connexion(),
            self.un_identifiant(asl_id::Genre::Appareil),
        ) else {
            return Trouvaille::Rien;
        };
        match self.entrepot.creer_appareil(
            appareil,
            asl_registre::Provenance::Ici,
            compte,
            cle.octets(),
            asl_registre::Attestation::Aucune,
        ) {
            Ok(()) => Trouvaille::AppareilCree(appareil),
            Err(_) => Trouvaille::Rien,
        }
    }

    /// Déclare une machine, et émet son premier code d'enrôlement.
    fn creer_une_machine(&self, nom: &str, capacites: asl_api::corps::Capacites) -> Trouvaille {
        let (Some(compte), Some(machine)) = (
            self.compte_de_la_connexion(),
            self.un_identifiant(asl_id::Genre::Machine),
        ) else {
            return Trouvaille::Rien;
        };
        let Ok(nom) = asl_registre::NomRange::nouveau(nom) else {
            return Trouvaille::Rien;
        };

        // **SANS CLÉ**, et c'est l'état d'une machine déclarée : la clé
        // arrivera avec le code, générée sur place.
        if self
            .entrepot
            .creer_machine(
                machine,
                asl_registre::Provenance::Ici,
                compte,
                nom,
                asl_registre::Capacites {
                    annonce: capacites.annonce,
                    lecture: capacites.lecture,
                },
            )
            .is_err()
        {
            return Trouvaille::Rien;
        }
        match self.tirer_un_code(machine) {
            Some((code, expire_a)) => Trouvaille::MachineCreee {
                machine,
                code,
                expire_a,
            },
            None => Trouvaille::Rien,
        }
    }

    /// Change le nom ou les capacités d'une machine qu'on possède.
    ///
    /// # RETIRER LA CAPACITÉ D'ANNONCE FERME LES CONNEXIONS DE CETTE MACHINE
    ///
    /// Sans cette fermeture, le retrait ne retirerait rien : les baux posés
    /// avant vivraient tant que les connexions vivent, et l'annuaire
    /// continuerait de publier les adresses d'une machine à qui l'on vient
    /// d'interdire d'annoncer. **C'est le même geste que la révocation d'une
    /// clé**, pour la même raison, et il partage la même file.
    ///
    /// **Retirer la LECTURE ne ferme rien.** Une machine qui ne peut plus
    /// interroger l'annuaire n'a rien laissé derrière elle : la prochaine
    /// requête sera refusée, et il n'y a pas d'état à défaire.
    fn modifier_une_machine(
        &mut self,
        machine: Identifiant,
        nom: Option<&str>,
        capacites: Option<asl_api::corps::Capacites>,
    ) -> Trouvaille {
        let (Some(compte), Ok(Some(rangee))) = (
            self.compte_de_la_connexion(),
            self.entrepot.machine(machine),
        ) else {
            return Trouvaille::Rien;
        };
        // **UNE MACHINE QUI N'EST PAS À NOUS NE SE MODIFIE PAS**, et le refus se
        // cache derrière le `404` des autres : distinguer « elle n'existe pas »
        // de « elle n'est pas à vous » dirait à qui essaie des identifiants au
        // hasard lesquels existent.
        if asl_auth::decider_gestion(compte, rangee.proprietaire) == asl_auth::Decision::Refuser {
            return Trouvaille::Rien;
        }

        let nom = match nom {
            Some(texte) => match asl_registre::NomRange::nouveau(texte) {
                Ok(range) => Some(range),
                Err(_) => return Trouvaille::Rien,
            },
            None => None,
        };
        let capacites = capacites.map(|demandees| asl_registre::Capacites {
            annonce: demandees.annonce,
            lecture: demandees.lecture,
        });
        let perd_l_annonce = rangee.annonce && capacites.is_some_and(|quoi| !quoi.annonce);

        // **CHAMP PAR CHAMP** : l'entrepôt n'estampille que ce qui est donné,
        // et c'est ce que la règle de conflit compare (`replication.md` §3.2).
        match self.entrepot.modifier_machine(machine, nom, capacites) {
            Ok(Some(_)) => {
                if perd_l_annonce {
                    self.a_fermer.push(machine);
                }
                Trouvaille::Fait
            }
            Ok(None) | Err(_) => Trouvaille::Rien,
        }
    }

    /// Émet un nouveau code pour une machine déjà déclarée.
    fn emettre_un_code(&self, machine: Identifiant) -> Trouvaille {
        let (Some(compte), Ok(Some(rangee))) = (
            self.compte_de_la_connexion(),
            self.entrepot.machine(machine),
        ) else {
            return Trouvaille::Rien;
        };
        // **UNE MACHINE QUI N'EST PAS À NOUS NE SE RÉ-ENRÔLE PAS.** Sans ce
        // refus, quiconque a un compte pourrait émettre un code pour la machine
        // d'un autre, puis y lier sa propre clé.
        if asl_auth::decider_gestion(compte, rangee.proprietaire) == asl_auth::Decision::Refuser {
            return Trouvaille::Refus;
        }
        match self.tirer_un_code(machine) {
            Some((code, expire_a)) => Trouvaille::CodeEmis { code, expire_a },
            None => Trouvaille::Rien,
        }
    }

    /// Tire un code pour cette machine, et le range sous son empreinte.
    fn tirer_un_code(&self, machine: Identifiant) -> Option<(asl_cle::TexteCode, u64)> {
        // Huit octets suffisent : dix symboles n'en portent que cinquante bits.
        // On puise à la même source que les identifiants — c'est le même noyau,
        // et la même exigence.
        let graine = (self.tirer_un_identifiant)()?;
        let mut huit = [0_u8; 8];
        for (place, octet) in huit.iter_mut().zip(graine.iter()) {
            *place = *octet;
        }
        let code = asl_cle::CodeEnrolement::depuis_entropie(huit);
        let expire_a = maintenant()
            .saturating_div(1_000)
            .saturating_add(asl_auth::VALIDITE_CODE_SECONDES.saturating_mul(1_000));

        self.entrepot
            .emettre_enrolement(
                &code.empreinte(),
                asl_registre::Provenance::Ici,
                machine,
                expire_a,
            )
            .ok()?;
        Some((code.texte_groupe(), expire_a))
    }

    /// Lie cette clé à la machine que ce code désigne.
    fn enroler(
        &self,
        empreinte: &[u8; asl_registre::EMPREINTE_OCTETS],
        cle: &ClePublique,
    ) -> Trouvaille {
        // **LE CODE MEURT ICI, QU'IL SERVE OU NON.** Consommer d'abord et
        // décider ensuite est ce qui rend « à usage unique » vrai : un code
        // expiré qu'on laisserait en place resterait un secret vivant, et deux
        // enrôlements simultanés du même code en verraient tous deux un valide.
        let Ok(trouve) = self.entrepot.consommer_enrolement(empreinte) else {
            return Trouvaille::Rien;
        };
        let etat = match &trouve {
            None => asl_auth::EtatCode::Inconnu,
            Some(enrolement) if enrolement.expire_a < maintenant().saturating_div(1_000) => {
                asl_auth::EtatCode::Expire
            }
            Some(_) => asl_auth::EtatCode::Utilisable,
        };
        if asl_auth::decider_enrolement(etat) == asl_auth::Decision::Refuser {
            return Trouvaille::Refus;
        }
        let Some(enrolement) = trouve else {
            return Trouvaille::Refus;
        };
        // **L'EMPREINTE ET L'ESTAMPILLE D'ÉMISSION PARTENT AVEC LA LIAISON**
        // (`replication.md` §5.2) : l'autre racine retire le code, et sait
        // quel code a lié cette clé — c'est ce que sa règle de conflit compare.
        match self.entrepot.lier_cle(
            enrolement.machine,
            cle.octets(),
            *empreinte,
            enrolement.estampille,
        ) {
            Ok(Some(rangee)) => Trouvaille::Enrolee {
                machine: enrolement.machine,
                proprietaire: rangee.proprietaire,
            },
            Ok(None) | Err(_) => Trouvaille::Rien,
        }
    }

    /// Qui est la machine de cette connexion, et à qui elle appartient.
    fn qui_je_suis(&self) -> Trouvaille {
        let Some(machine) = self.session.machine() else {
            return Trouvaille::Rien;
        };
        match self.entrepot.machine(machine) {
            Ok(Some(rangee)) => Trouvaille::Moi {
                machine,
                proprietaire: rangee.proprietaire,
            },
            _ => Trouvaille::Rien,
        }
    }

    /// Les machines d'un utilisateur, TOUTES, avec de quoi décider pour chacune.
    ///
    /// # ON RASSEMBLE TOUT, ET L'ÉTAGE 2 ÉCARTE
    ///
    /// Le demandeur est le compte de l'appareil, ou le propriétaire de la
    /// machine qui a prouvé sa clé — jamais ce que la requête nomme (C10). Ses
    /// arêtes reçues, révoquées comprises, partent avec ; c'est
    /// `asl_auth::decider_machine_visible` qui les examine, machine par machine.
    ///
    /// # LE MÊME TRAVAIL, QU'IL Y AIT UNE ARÊTE OU NON (C9)
    ///
    /// Les machines de `u` et leurs services se lisent AVANT qu'on sache si le
    /// demandeur en verra une : un tiers sans arête coûte à l'annuaire ce que
    /// coûte un ami, et reçoit la même liste vide après le même délai.
    fn rassembler_les_machines_de(&self, proprietaire: Identifiant) -> Trouvaille {
        let (demandeur, lecture) = if let Some(appareil) = self.session.appareil() {
            let Ok(Some(rangee)) = self.entrepot.appareil(appareil) else {
                return Trouvaille::Rien;
            };
            if rangee.revoque {
                return Trouvaille::Rien;
            }
            (rangee.proprietaire, true)
        } else if let Some(machine) = self.session.machine() {
            let Ok(Some(rangee)) = self.entrepot.machine(machine) else {
                return Trouvaille::Rien;
            };
            (rangee.proprietaire, rangee.lecture)
        } else {
            return Trouvaille::Rien;
        };

        let Ok(rangees) = self.entrepot.machines_de_compte(proprietaire) else {
            return Trouvaille::Rien;
        };
        let machines = rangees
            .into_iter()
            .filter_map(|(quelle, machine)| {
                let nom = core::str::from_utf8(machine.nom.octets()).ok()?;
                let vue = asl_api::corps::MachineVue {
                    machine: quelle,
                    nom,
                };
                let mut encodee = alloc_reponse();
                let combien = vue.encoder(&mut encodee).ok()?;
                encodee.truncate(combien);
                let services = self
                    .entrepot
                    .services_de_machine(quelle)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(service, _)| service)
                    .collect();
                Some(asl_session::MachineRassemblee {
                    machine: quelle,
                    services,
                    encodee,
                })
            })
            .collect();

        let autorisations = self
            .entrepot
            .autorisations_recues(demandeur)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|quoi| {
                asl_auth::Autorisation::nouvelle(
                    quoi.par,
                    quoi.a,
                    match quoi.portee {
                        asl_registre::Portee::ToutLeCompte => asl_auth::Portee::ToutLeCompte,
                        asl_registre::Portee::UneMachine(quelle) => {
                            asl_auth::Portee::UneMachine(quelle)
                        }
                        asl_registre::Portee::UnService(quel) => asl_auth::Portee::UnService(quel),
                    },
                    quoi.revoquee,
                )
                .ok()
            })
            .collect();

        Trouvaille::MachinesDe {
            demandeur,
            lecture,
            proprietaire,
            machines,
            autorisations,
        }
    }

    /// Accorde une autorisation à un autre compte.
    fn autoriser(
        &self,
        a: Identifiant,
        portee: asl_api::corps::Portee,
        etiquette: &str,
    ) -> Trouvaille {
        let (Some(par), Some(quelle)) = (
            self.compte_de_la_connexion(),
            self.un_identifiant(asl_id::Genre::Autorisation),
        ) else {
            return Trouvaille::Rien;
        };

        // L'étiquette a déjà été bornée par `asl-api` (texte libre, 1 à 64
        // octets) ; `NomRange::nouveau` ne peut donc échouer que sur une
        // longueur, et un `Rien` (500) est le mot juste si l'invariant cassait.
        let Ok(etiquette) = asl_registre::NomRange::nouveau(etiquette) else {
            return Trouvaille::Rien;
        };

        // **LE BÉNÉFICIAIRE DOIT EXISTER.** Une autorisation vers un compte
        // inexistant est MUETTE : elle s'affiche comme accordée et n'ouvre rien.
        // `protocole.md` §2.2 donne `GET /v1/utilisateurs/{u}` pour qu'une faute
        // de frappe se voie ; le vérifier ici est ce qui la rend impossible.
        match self.entrepot.compte(a) {
            Ok(Some(_)) => {}
            Ok(None) => return Trouvaille::Refus,
            Err(_) => return Trouvaille::Rien,
        }

        // **ON N'ACCORDE QUE SUR CE QU'ON POSSÈDE.** Une portée qui nomme la
        // machine d'un autre n'ouvrirait rien — `Autorisation::couvre` vérifie
        // les deux bouts —, mais elle s'afficherait comme accordée. Un droit qui
        // ment sur ce qu'il donne est pire qu'un refus.
        let portee = match portee {
            asl_api::corps::Portee::ToutLeCompte => asl_registre::Portee::ToutLeCompte,
            asl_api::corps::Portee::UneMachine(machine) => {
                let Ok(Some(rangee)) = self.entrepot.machine(machine) else {
                    return Trouvaille::Refus;
                };
                if asl_auth::decider_gestion(par, rangee.proprietaire)
                    == asl_auth::Decision::Refuser
                {
                    return Trouvaille::Refus;
                }
                asl_registre::Portee::UneMachine(machine)
            }
            asl_api::corps::Portee::UnService(service) => {
                let Ok(Some(rangee)) = self.entrepot.service(service) else {
                    return Trouvaille::Refus;
                };
                let Ok(Some(machine)) = self.entrepot.machine(rangee.machine) else {
                    return Trouvaille::Refus;
                };
                if asl_auth::decider_gestion(par, machine.proprietaire)
                    == asl_auth::Decision::Refuser
                {
                    return Trouvaille::Refus;
                }
                asl_registre::Portee::UnService(service)
            }
        };

        // **`Autorisation::nouvelle` REFUSE QU'UN COMPTE S'AUTORISE LUI-MÊME**,
        // et c'est là que ce refus se prend. Le répéter ici en ferait une règle
        // à deux endroits.
        if asl_auth::Autorisation::nouvelle(
            par,
            a,
            match portee {
                asl_registre::Portee::ToutLeCompte => asl_auth::Portee::ToutLeCompte,
                asl_registre::Portee::UneMachine(quoi) => asl_auth::Portee::UneMachine(quoi),
                asl_registre::Portee::UnService(quoi) => asl_auth::Portee::UnService(quoi),
            },
            false,
        )
        .is_err()
        {
            return Trouvaille::Refus;
        }

        match self.entrepot.accorder_autorisation(
            quelle,
            asl_registre::Provenance::Ici,
            par,
            a,
            portee,
            etiquette,
        ) {
            Ok(()) => Trouvaille::AutorisationCreee(quelle),
            Err(_) => Trouvaille::Rien,
        }
    }

    /// Révoque un appareil du compte de cette connexion.
    fn revoquer_un_appareil(&mut self, vise: Identifiant) -> Trouvaille {
        let (Some(compte), Some(demandeur)) =
            (self.compte_de_la_connexion(), self.session.appareil())
        else {
            return Trouvaille::Rien;
        };
        // **LE REFUS DE SE RÉVOQUER SOI-MÊME SE PREND AVANT LA LECTURE**, parce
        // qu'il ne dépend pas de l'entrepôt — et parce qu'il ne se cache pas :
        // celui qui demande connaît déjà son propre identifiant.
        if asl_auth::decider_revocation_d_appareil(demandeur, vise) == asl_auth::Decision::Refuser {
            return Trouvaille::Refus;
        }
        let Ok(Some(rangee)) = self.entrepot.appareil(vise) else {
            return Trouvaille::Rien;
        };
        // **L'APPAREIL D'UN AUTRE COMPTE REND `Rien`, ET NON UN REFUS** : les
        // deux réponses doivent être la même, sinon un inconnu apprend quels
        // identifiants existent en essayant.
        if asl_auth::decider_gestion(compte, rangee.proprietaire) == asl_auth::Decision::Refuser {
            return Trouvaille::Rien;
        }
        match self.entrepot.revoquer_appareil(vise) {
            Ok(Some(_)) => {
                self.a_fermer.push(vise);
                Trouvaille::Fait
            }
            Ok(None) => Trouvaille::Rien,
            Err(_) => Trouvaille::Rien,
        }
    }

    /// Retire la clé d'une machine du compte de cette connexion.
    fn revoquer_une_cle(&mut self, machine: Identifiant) -> Trouvaille {
        let (Some(compte), Ok(Some(rangee))) = (
            self.compte_de_la_connexion(),
            self.entrepot.machine(machine),
        ) else {
            return Trouvaille::Rien;
        };
        if asl_auth::decider_gestion(compte, rangee.proprietaire) == asl_auth::Decision::Refuser {
            return Trouvaille::Rien;
        }
        // **LA CLÉ S'EFFACE, LA MACHINE RESTE.** Elle garde son nom, ses
        // capacités et ses services ; ce qu'elle perd est le moyen de prouver
        // qu'elle est elle. Un nouveau code la remettra en marche.
        match self.entrepot.revoquer_cle(machine) {
            Ok(Some(_)) => {
                self.a_fermer.push(machine);
                Trouvaille::Fait
            }
            Ok(None) | Err(_) => Trouvaille::Rien,
        }
    }

    /// Dépose ou renouvelle le jeton de poussée d'un appareil.
    ///
    /// # C'EST LA CONNEXION QUI DÉSIGNE L'APPAREIL, ET LE CHEMIN DOIT SUIVRE
    ///
    /// Le jeton vient du système du téléphone qui le porte, et personne d'autre
    /// ne l'a. Déposer pour un autre appareil détournerait ses notifications —
    /// c'est-à-dire celles d'un compte vers le téléphone de qui l'a volé.
    ///
    /// **Le refus rend `Rien`, donc `404`.** Dire « ce n'est pas vous » à qui
    /// vise l'identifiant d'un autre confirmerait que cet identifiant existe.
    fn poser_un_jeton(
        &self,
        vise: Identifiant,
        plateforme: asl_api::corps::Plateforme,
        jeton: &str,
    ) -> Trouvaille {
        let Some(moi) = self.session.appareil() else {
            return Trouvaille::Rien;
        };
        if moi != vise {
            return Trouvaille::Rien;
        }
        // **UN APPAREIL RÉVOQUÉ NE DÉPOSE PLUS.** `compte_de_la_connexion`
        // écarte déjà les révoqués, et c'est ce qui compte ici : sans elle, un
        // téléphone déclaré perdu pourrait redéposer son jeton et continuer de
        // recevoir les notifications du compte.
        let Some(_compte) = self.compte_de_la_connexion() else {
            return Trouvaille::Rien;
        };
        let Ok(jeton) = asl_registre::JetonRange::nouveau(jeton) else {
            return Trouvaille::Rien;
        };
        match self.entrepot.poser_jeton(
            vise,
            asl_registre::Provenance::Ici,
            match plateforme {
                asl_api::corps::Plateforme::Apns => asl_registre::Plateforme::Apns,
                asl_api::corps::Plateforme::Fcm => asl_registre::Plateforme::Fcm,
            },
            jeton,
        ) {
            Ok(()) => Trouvaille::Fait,
            Err(_) => Trouvaille::Rien,
        }
    }

    /// Pose ce qu'un appareil dit de lui-même — **pour lui-même seulement**.
    ///
    /// La même garde que [`Service::poser_un_jeton`], et pour la même forme :
    /// c'est l'appareil de CETTE connexion qui parle de lui, et viser un autre
    /// rend le `404` de ce qui n'existe pas. Un appareil révoqué ne se décrit
    /// plus non plus — `compte_de_la_connexion` l'écarte —, non qu'il y ait un
    /// droit à protéger, mais parce qu'un téléphone déclaré perdu n'a plus rien
    /// à dire sur ce compte.
    fn poser_une_description(
        &self,
        vise: Identifiant,
        systeme: asl_api::corps::Systeme,
        modele: &str,
    ) -> Trouvaille {
        let Some(moi) = self.session.appareil() else {
            return Trouvaille::Rien;
        };
        if moi != vise {
            return Trouvaille::Rien;
        }
        let Some(_compte) = self.compte_de_la_connexion() else {
            return Trouvaille::Rien;
        };
        let Ok(modele) = asl_registre::NomRange::nouveau(modele) else {
            return Trouvaille::Rien;
        };
        match self.entrepot.poser_description(
            vise,
            asl_registre::Provenance::Ici,
            match systeme {
                asl_api::corps::Systeme::Ios => asl_registre::Systeme::Ios,
                asl_api::corps::Systeme::Android => asl_registre::Systeme::Android,
                asl_api::corps::Systeme::Macos => asl_registre::Systeme::Macos,
            },
            modele,
        ) {
            Ok(()) => Trouvaille::Fait,
            Err(_) => Trouvaille::Rien,
        }
    }

    /// Retire une autorisation que ce compte a accordée.
    fn revoquer_une_autorisation(&self, quelle: Identifiant) -> Trouvaille {
        let (Some(compte), Ok(Some(rangee))) = (
            self.compte_de_la_connexion(),
            self.entrepot.autorisation(quelle),
        ) else {
            return Trouvaille::Rien;
        };
        // **C'EST CELUI QUI A ACCORDÉ QUI RETIRE**, jamais le bénéficiaire :
        // une arête qu'on pourrait retirer soi-même serait une arête qu'un
        // compromis effacerait pour brouiller les pistes.
        if asl_auth::decider_gestion(compte, rangee.par) == asl_auth::Decision::Refuser {
            return Trouvaille::Rien;
        }
        match self.entrepot.revoquer_autorisation(quelle) {
            Ok(Some(_)) => Trouvaille::Fait,
            Ok(None) | Err(_) => Trouvaille::Rien,
        }
    }

    /// Pose ou retire l'alias public du compte de cette connexion.
    ///
    /// # LES DEUX VERBES SONT LA MÊME ÉCRITURE
    ///
    /// `reclamer_alias` tient l'index des réclamations, et le met d'accord avec
    /// le compte qu'on écrit : l'ancienne réclamation part, la neuve entre, et
    /// un alias déjà pris est refusé. Écrire un chemin à part pour le retrait
    /// aurait dédoublé cette mise d'accord — et c'est la copie qu'on oublie qui
    /// laisse un index désignant un compte qui n'a plus cet alias.
    fn poser_l_alias(&self, alias: Option<&str>) -> Trouvaille {
        let (Some(compte),) = (self.compte_de_la_connexion(),) else {
            return Trouvaille::Rien;
        };
        let range = match alias {
            Some(texte) => match asl_registre::AliasRange::nouveau(texte) {
                Ok(range) => Some(range),
                Err(_) => return Trouvaille::Rien,
            },
            None => None,
        };
        match self.entrepot.reclamer_alias(compte, range) {
            Ok(true) => Trouvaille::Fait,
            Err(asl_store::Faute::AliasPris) => Trouvaille::Conflit,
            Ok(false) | Err(_) => Trouvaille::Rien,
        }
    }

    /// Ouvre le flux des opérations après ce compteur (`replication.md` §5.3).
    ///
    /// # LE RATTRAPAGE EST LU MAINTENANT, ET POUSSÉ JUSTE APRÈS LA RÉPONSE
    ///
    /// C'est la même lecture qui dit `410` : le journal remonte jusqu'à
    /// `apres`, ou non. Ce qu'il porte après est déposé dans `suite`, et la
    /// boucle l'écrit sur le flux de cette requête dès que la réponse tenue
    /// est partie — puis chaque opération nouvelle, à mesure (`au_tour`).
    fn ouvrir_les_operations(&mut self, apres: u64) -> Trouvaille {
        if self.flux_pair_tenu {
            return Trouvaille::Conflit;
        }
        // Le tireur passe aux opérations : ce qu'il restait d'un instantané
        // ne l'intéresse plus.
        *self.reste_d_instantane = None;
        // **LA BORNE EST LUE AVANT LE JOURNAL.** Une opération journalisée
        // entre les deux serait relue au tour suivant : le curseur avance
        // sur ce qu'on a poussé, et la borne ne dit que « regarde ».
        let vu_jusqu_a = self.entrepot.derniere_operation();
        match self.entrepot.operations_apres(apres) {
            Ok(Rattrapage::Operations(cadres)) => {
                (self.voie.journal)(&format!(
                    "{} tire les opérations après {apres} : {} en rattrapage",
                    self.session
                        .racine()
                        .map_or_else(String::new, |qui| qui.texte().as_str().to_owned()),
                    cadres.len()
                ));
                let curseur = if cadres.is_empty() {
                    Some(apres)
                } else {
                    dernier_compteur(&cadres)
                };
                // Un journal illisible ne se pousse pas : `500`, et
                // l'exploitant le lit.
                let Some(curseur) = curseur else {
                    (self.voie.journal)("une opération du journal ne se relit pas");
                    return Trouvaille::Rien;
                };
                *self.suite = Some(SuiteAuPair {
                    cadres: cadres.into(),
                    curseur: Some(curseur),
                    vu_jusqu_a,
                });
                Trouvaille::FluxOuvert
            }
            Ok(Rattrapage::HorsJournal { retirees_jusqu_a }) => {
                (self.voie.journal)(&format!(
                    "le journal ne remonte plus jusqu'à {apres} (retiré jusqu'à \
                     {retirees_jusqu_a}) : 410, l'autre racine s'amorce par instantané"
                ));
                Trouvaille::HorsJournal
            }
            Err(_) => Trouvaille::Rien,
        }
    }

    /// Ouvre le flux de l'instantané (`replication.md` §5.4) : tout l'état,
    /// lu dans une seule transaction, puis le cadre de fin — par parts, un
    /// flux par part, et le dernier se ferme derrière la fin.
    ///
    /// **Une connexion qui tient le reste d'un instantané le CONTINUE** : la
    /// demande suivante rend la part suivante de la même lecture, et non un
    /// instantané neuf (voir `ParConnexion::reste_d_instantane`).
    fn ouvrir_l_instantane(&mut self) -> Trouvaille {
        if self.flux_pair_tenu {
            return Trouvaille::Conflit;
        }
        if let Some(reste) = self.reste_d_instantane.take() {
            *self.suite = Some(SuiteAuPair {
                cadres: reste,
                curseur: None,
                vu_jusqu_a: 0,
            });
            return Trouvaille::FluxOuvert;
        }
        match self.entrepot.instantane() {
            Ok(cadres) => {
                let octets: usize = cadres.iter().map(Vec::len).sum();
                (self.voie.journal)(&format!(
                    "{} s'amorce par instantané : {} cadres, {octets} octets, par parts de \
                     {PART_OCTETS_MAX} au plus",
                    self.session
                        .racine()
                        .map_or_else(String::new, |qui| qui.texte().as_str().to_owned()),
                    cadres.len()
                ));
                *self.suite = Some(SuiteAuPair {
                    cadres: cadres.into(),
                    curseur: None,
                    vu_jusqu_a: 0,
                });
                Trouvaille::FluxOuvert
            }
            Err(_) => Trouvaille::Rien,
        }
    }

    /// Prend une annonce, ouvre sa session vivante, et compose la réponse.
    ///
    /// # POURQUOI TOUT CECI EST À L'ÉTAGE 3
    ///
    /// Une annonce OUVRE de l'état vivant, qui n'existe qu'en mémoire et
    /// n'appartient qu'à cette connexion. Ce qui DÉCIDE reste ailleurs et reste
    /// pur : `asl_auth::decider_annonce` pour la permission,
    /// `asl_annuaire::Session::ouvrir` pour tout le reste — le bail, le verdict
    /// de NAT, les candidats. Cette fonction ne fait que les appeler dans
    /// l'ordre, et ranger ce qu'ils rendent.
    ///
    /// Rend `None` sur un refus ou un message mal formé ; `asl-session` en fait
    /// un `403`.
    fn annoncer(&mut self) -> Option<Vec<u8>> {
        // ── LE DEMANDEUR, ET SA PERMISSION ──────────────────────────────────
        let qui = self.session.machine()?;
        let rangee = self.entrepot.machine(qui).ok().flatten()?;
        let demandeur = asl_auth::Machine::nouvelle(
            qui,
            rangee.proprietaire,
            asl_auth::Capacites {
                annonce: rangee.annonce,
                lecture: rangee.lecture,
            },
        )
        .ok()?;
        if asl_auth::decider_annonce(&demandeur) == asl_auth::Decision::Refuser {
            return None;
        }

        // ── LE MESSAGE ──────────────────────────────────────────────────────
        let mut tampons = asl_proto::cadrage::Tampons::nouveaux();
        let annonce = asl_proto::Annonce::decoder(&self.corps, &mut tampons).ok()?;

        // **UNE MACHINE N'ANNONCE QUE POUR ELLE-MÊME.** Le message porte un
        // identifiant de machine ; s'il n'est pas celui qui a prouvé sa clé sur
        // CETTE connexion, c'est une usurpation, et elle se refuse ici.
        if annonce.machine != qui {
            return None;
        }

        // ── LE SERVICE : CELUI QUI EXISTE, OU UN NEUF ───────────────────────
        //
        // Un daemon n'a pas à déclarer son service avant de l'annoncer : la
        // première annonce d'un nom le crée. L'exiger d'abord obligerait à
        // passer par l'application mobile pour lancer un daemon, ce qu'aucun
        // déploiement automatisé ne peut faire.
        let nom = annonce.service.as_str();
        let service = match self.entrepot.service_par_nom(qui, nom).ok()? {
            Some(deja) => deja,
            None => {
                let neuf = Identifiant::depuis_entropie(
                    asl_id::Genre::Service,
                    (self.tirer_un_identifiant)()?,
                );
                self.entrepot
                    .declarer_service(
                        neuf,
                        asl_registre::Provenance::Ici,
                        qui,
                        asl_registre::NomRange::nouveau(nom).ok()?,
                    )
                    .ok()?;
                neuf
            }
        };

        // ── LA SESSION VIVANTE ──────────────────────────────────────────────
        let (vivante, _ordres) =
            asl_annuaire::Session::ouvrir(service, self.bail, &annonce, self.vu_depuis, instant())
                .ok()?;

        // ── LES SONDES PARTENT, ET LA RÉPONSE N'ATTEND PAS ──────────────────
        //
        // **ON RÉPOND AVANT D'AVOIR MESURÉ**, et c'est ce que
        // `asl_proto::Verdict::EnCours` existe pour dire. Attendre le
        // trois-temps ferait patienter le daemon jusqu'à trois secondes par
        // point, et bloquerait la boucle entière — qui n'a qu'une tâche.
        //
        // Les verdicts reviennent par le canal, et `au_tour` les applique.
        self.lancer_les_sondes(service, &vivante, &_ordres);

        let mut sortie = alloc_reponse();
        let combien = vivante.reponse().ok()?.encoder(&mut sortie).ok()?;
        sortie.truncate(combien);

        self.vivier.poser(service, &self.connexion, vivante);
        Some(sortie)
    }

    /// Toutes les instances portant ce nom que le demandeur POURRAIT voir.
    ///
    /// # OÙ L'ON CHERCHE, ET POURQUOI PAS PARTOUT
    ///
    /// Un nom de service n'est unique que sur une machine : `depot` existe chez
    /// tout le monde. Chercher « tous les services nommés `depot` » dans
    /// l'annuaire entier reviendrait à balayer une base dont la taille ne dépend
    /// pas de la question posée — et à composer une liste dont l'étage 2
    /// écarterait presque tout.
    ///
    /// On part donc des COMPTES qui peuvent avoir quelque chose à nous montrer :
    /// le nôtre, et ceux qui nous ont accordé une autorisation. C'est un
    /// sur-ensemble de ce qui se rendra — **l'étage 2 décide encore, une par
    /// une** —, mais un sur-ensemble borné par nos propres droits.
    fn rassembler_par_nom(&self, nom: &str) -> Vec<Resolution> {
        let Some(qui) = self.session.machine() else {
            return Vec::new();
        };
        let Ok(Some(rangee)) = self.entrepot.machine(qui) else {
            return Vec::new();
        };

        // Le compte du demandeur, et ceux qui lui ont accordé quelque chose.
        let mut comptes = vec![rangee.proprietaire];
        if let Ok(recues) = self.entrepot.autorisations_recues(rangee.proprietaire) {
            for quoi in recues {
                if !comptes.contains(&quoi.par) {
                    comptes.push(quoi.par);
                }
            }
        }

        let mut trouvees = Vec::new();
        for compte in comptes {
            let Ok(machines) = self.entrepot.machines_de_compte(compte) else {
                continue;
            };
            for (quelle, _) in machines {
                let Ok(Some(service)) = self.entrepot.service_par_nom(quelle, nom) else {
                    continue;
                };
                if let Some(resolution) = self.rassembler(quelle, nom) {
                    trouvees.push(resolution);
                }
                let _ = service;
            }
        }
        trouvees
    }

    /// Tous les services d'une machine, tels qu'ils sont annoncés.
    ///
    /// **LE DEMANDEUR EST UN APPAREIL, ET NON UNE MACHINE** : c'est
    /// l'application mobile qui regarde. On rassemble donc au nom de son COMPTE,
    /// et l'on emprunte la même décision — celle qui sert la résolution — parce
    /// qu'il n'y a aucune raison qu'un écran voie ce qu'un daemon ne verrait pas.
    fn rassembler_les_services(&self, machine: Identifiant) -> Trouvaille {
        let Some(appareil) = self.session.appareil() else {
            return Trouvaille::Rien;
        };
        let Ok(Some(rangee)) = self.entrepot.appareil(appareil) else {
            return Trouvaille::Rien;
        };
        // **LA MACHINE VISÉE EST LUE MAINTENANT, ET LA DÉCISION SE PREND APRÈS.**
        // C'est notre propre mémoire : la lire ne dit rien à personne. La RENDRE
        // est une décision, et elle se prend à l'étage 2.
        let Ok(Some(visee)) = self.entrepot.machine(machine) else {
            return Trouvaille::Rien;
        };
        let Ok(services) = self.entrepot.services_de_machine(machine) else {
            return Trouvaille::Rien;
        };

        // **ON NE FILTRE PLUS LES SERVICES NON VIVANTS.** L'écran veut aussi ceux
        // qui sont partis (`docs/modele.md` §4.2) : un service déclaré dont la
        // connexion est tombée doit apparaître, sans quoi il semblerait n'avoir
        // jamais existé.
        let annonces = services
            .into_iter()
            .filter_map(|(quel, enregistre)| {
                // Le nom d'un service est une clé (alphabet restreint), donc
                // toujours de l'UTF-8 valide ; un octet corrompu n'affole rien —
                // le service est simplement omis.
                let nom = core::str::from_utf8(enregistre.nom.octets()).ok()?;
                let mut sortie = alloc_reponse();
                let combien = match self.vivier.annonce(quel) {
                    // Dans le vivier, mais peut-être en instance de départ tant
                    // que le balayage ne l'a pas ôtée : on regarde son état.
                    Some(vivante) => match vivante.etat(instant()) {
                        asl_annuaire::Etat::Parti { motif } => asl_api::corps::ServiceRendu {
                            service: quel,
                            nom,
                            etat: asl_api::corps::ServiceEtat::Parti {
                                volontaire: Some(matches!(
                                    motif,
                                    asl_annuaire::MotifDeDepart::Volontaire
                                )),
                            },
                        }
                        .encoder(&mut sortie)
                        .ok()?,
                        // Vivant : on réémet l'objet d'annonce déjà éprouvé, tel
                        // qu'un daemon le reçoit, plutôt que d'en réécrire un.
                        asl_annuaire::Etat::Annonce | asl_annuaire::Etat::Joignable { .. } => {
                            let mut objet = alloc_reponse();
                            let n = vivante.reponse().ok()?.encoder(&mut objet).ok()?;
                            objet.truncate(n);
                            asl_api::corps::ServiceRendu {
                                service: quel,
                                nom,
                                etat: asl_api::corps::ServiceEtat::Annonce { annonce: &objet },
                            }
                            .encoder(&mut sortie)
                            .ok()?
                        }
                    },
                    // Déclaré, mais aucune session vivante : parti, motif perdu.
                    None => asl_api::corps::ServiceRendu {
                        service: quel,
                        nom,
                        etat: asl_api::corps::ServiceEtat::Parti { volontaire: None },
                    }
                    .encoder(&mut sortie)
                    .ok()?,
                };
                sortie.truncate(combien);
                Some(sortie)
            })
            .collect();

        Trouvaille::ServicesDeMachine {
            demandeur: rangee.proprietaire,
            proprietaire: visee.proprietaire,
            annonces,
        }
    }

    /// Les machines du compte qui demande, pour l'écran qui les liste.
    ///
    /// **LE COMPTE EST CELUI DE L'APPAREIL, ET PERSONNE NE LE NOMME.** On lit
    /// l'appareil de la session pour son propriétaire, comme
    /// [`Self::rassembler_les_autorisations`] ; nommer un compte donnerait à un
    /// appareil le droit de lire les machines d'un autre.
    fn rassembler_les_machines(&self) -> Trouvaille {
        let Some(appareil) = self.session.appareil() else {
            return Trouvaille::Rien;
        };
        let Ok(Some(rangee)) = self.entrepot.appareil(appareil) else {
            return Trouvaille::Rien;
        };
        let Ok(machines) = self.entrepot.machines_de_compte(rangee.proprietaire) else {
            return Trouvaille::Rien;
        };

        let elements = machines
            .into_iter()
            .filter_map(|(quelle, machine)| {
                // Le nom rangé est un texte libre déjà validé UTF-8 à l'entrée
                // (`Lecteur::texte_libre`) ; un octet corrompu ne panique pas —
                // la machine est simplement omise.
                let nom = core::str::from_utf8(machine.nom.octets()).ok()?;
                let rendue = asl_api::corps::MachineRendue {
                    machine: quelle,
                    nom,
                    capacites: asl_api::corps::Capacites {
                        annonce: machine.annonce,
                        lecture: machine.lecture,
                    },
                    enrolee: machine.cle.is_some(),
                };
                let mut sortie = alloc_reponse();
                let combien = rendue.encoder(&mut sortie).ok()?;
                sortie.truncate(combien);
                Some(sortie)
            })
            .collect();

        Trouvaille::Machines(elements)
    }

    /// Les appareils du compte qui demande, révoqués compris.
    fn rassembler_les_appareils(&self) -> Trouvaille {
        let Some(appareil) = self.session.appareil() else {
            return Trouvaille::Rien;
        };
        let Ok(Some(rangee)) = self.entrepot.appareil(appareil) else {
            return Trouvaille::Rien;
        };
        let Ok(appareils) = self.entrepot.appareils_de_compte(rangee.proprietaire) else {
            return Trouvaille::Rien;
        };

        let elements = appareils
            .into_iter()
            .filter_map(|(quel, enregistre, rangee)| {
                // **UNE DESCRIPTION ILLISIBLE EST OMISE, PAS L'APPAREIL.** Le
                // modèle a été rangé par `NomRange`, donc il est de l'UTF-8
                // valide ; si un jour il ne l'était plus, c'est une étiquette
                // d'affichage qui manquerait, pas l'appareil qu'elle décrit.
                let description = rangee.as_ref().and_then(|quoi| {
                    Some(asl_api::corps::DescriptionAppareil {
                        systeme: match quoi.systeme {
                            asl_registre::Systeme::Ios => asl_api::corps::Systeme::Ios,
                            asl_registre::Systeme::Android => asl_api::corps::Systeme::Android,
                            asl_registre::Systeme::Macos => asl_api::corps::Systeme::Macos,
                        },
                        modele: core::str::from_utf8(quoi.modele.octets()).ok()?,
                    })
                });
                let rendue = asl_api::corps::AppareilRendu {
                    appareil: quel,
                    attestation: match enregistre.atteste {
                        asl_registre::Attestation::Aucune => {
                            asl_api::corps::PlateformeAttestation::Aucune
                        }
                        asl_registre::Attestation::Apple => {
                            asl_api::corps::PlateformeAttestation::Apple
                        }
                        asl_registre::Attestation::Android => {
                            asl_api::corps::PlateformeAttestation::Android
                        }
                    },
                    revoque: enregistre.revoque,
                    description,
                };
                let mut sortie = alloc_reponse();
                let combien = rendue.encoder(&mut sortie).ok()?;
                sortie.truncate(combien);
                Some(sortie)
            })
            .collect();

        Trouvaille::Appareils(elements)
    }

    /// Les autorisations d'un compte, dans les deux sens.
    fn rassembler_les_autorisations(&self) -> Trouvaille {
        let Some(appareil) = self.session.appareil() else {
            return Trouvaille::Rien;
        };
        let Ok(Some(rangee)) = self.entrepot.appareil(appareil) else {
            return Trouvaille::Rien;
        };
        let compte = rangee.proprietaire;

        let (Ok(accordees), Ok(recues)) = (
            self.entrepot.autorisations_accordees(compte),
            self.entrepot.autorisations_recues_nommees(compte),
        ) else {
            return Trouvaille::Rien;
        };

        // **UN SEUL TABLEAU POUR LES DEUX SENS.** `par` et `a` disent déjà de
        // quel côté chacune est, et un lecteur qui connaît son identifiant sait
        // lequel il est. Deux tableaux auraient obligé l'application à savoir
        // dans lequel chercher.
        let elements = accordees
            .into_iter()
            .chain(recues)
            .filter_map(|(quelle, quoi)| {
                // L'étiquette rangée est un texte libre déjà validé UTF-8 à
                // l'entrée (`Lecteur::texte_libre`) ; un octet corrompu ne
                // panique pas — l'autorisation est simplement omise.
                let etiquette = core::str::from_utf8(quoi.etiquette.octets()).ok()?;
                let rendue = asl_api::corps::AutorisationRendue {
                    autorisation: quelle,
                    par: quoi.par,
                    a: quoi.a,
                    portee: match quoi.portee {
                        asl_registre::Portee::ToutLeCompte => asl_api::corps::Portee::ToutLeCompte,
                        asl_registre::Portee::UneMachine(q) => {
                            asl_api::corps::Portee::UneMachine(q)
                        }
                        asl_registre::Portee::UnService(q) => asl_api::corps::Portee::UnService(q),
                    },
                    revoquee: quoi.revoquee,
                    etiquette,
                };
                let mut sortie = alloc_reponse();
                let combien = rendue.encoder(&mut sortie).ok()?;
                sortie.truncate(combien);
                Some(sortie)
            })
            .collect();

        Trouvaille::Autorisations(elements)
    }

    /// Lance une sonde par point sondable, et rend la main aussitôt.
    ///
    /// # SEUL LE CANDIDAT RÉFLEXIF EST SONDÉ
    ///
    /// `sonde::sondable` en est le juge, et son en-tête dit pourquoi : sonder
    /// une adresse ANNONCÉE serait inutile — c'est une adresse du réseau du
    /// daemon, pas du nôtre — et ferait de l'annuaire un balayeur de notre
    /// propre réseau, avec notre IP.
    fn lancer_les_sondes(
        &mut self,
        service: Identifiant,
        vivante: &asl_annuaire::Session,
        ordres: &asl_annuaire::Ordres,
    ) {
        for point in ordres.a_sonder() {
            if *self.en_vol >= sonde::EN_VOL_MAX {
                // **ON NE SONDE PAS, ET C'EST HONNÊTE** : le verdict reste
                // `en_cours`, ce qui est exactement la vérité.
                break;
            }
            let mut candidats = [asl_proto::Candidat {
                protocole: point.protocole,
                adresse: core::net::IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED),
                port: point.port,
                origine: asl_proto::Origine::Reflexif,
            }; asl_proto::ADRESSES_MAX + 1];
            let combien = vivante.candidats(point, &mut candidats);

            let Some(ou) = candidats
                .get(..combien)
                .unwrap_or_default()
                .iter()
                .find_map(|candidat| sonde::sondable(*candidat).map(|ou| (ou, *candidat)))
            else {
                continue;
            };

            let (adresse, candidat) = ou;
            let rapports = self.rapports.clone();
            *self.en_vol = self.en_vol.saturating_add(1);
            tokio::spawn(async move {
                let aboutie = sonde::aboutit(adresse).await.then_some(candidat);
                // Le canal est fermé quand l'annuaire s'éteint : il n'y a alors
                // plus personne pour le verdict, et ce n'est pas une faute.
                let _ = rapports.send(Verdict {
                    service,
                    point,
                    aboutie,
                    quand: asl_proto::Horodatage::depuis_millisecondes(
                        maintenant().saturating_div(1_000),
                    ),
                    maintenant: instant(),
                });
            });
        }
    }

    /// Rassemble ce qu'il faut pour décider d'une résolution.
    ///
    /// # POURQUOI TANT DE LECTURES POUR UNE QUESTION SI SIMPLE
    ///
    /// « Où est ce service ? » se décide sur quatre faits : ce que le demandeur
    /// a le DROIT de faire (ses capacités), à QUI il appartient, à qui appartient
    /// ce qu'il vise, et ce qu'on lui a accordé. Aucun ne se déduit des autres.
    ///
    /// **Un seul manquant, et l'on ne décide pas** : rendre `None` fait répondre
    /// `404`, exactement comme un refus.
    fn rassembler(&self, machine: Identifiant, nom: &str) -> Option<Resolution> {
        // Le demandeur : c'est la machine qui a prouvé sa clé sur CETTE
        // connexion, jamais une machine qu'une requête nommerait.
        let qui = self.session.machine()?;
        let demandeur = self.entrepot.machine(qui).ok().flatten()?;
        let demandeur = asl_auth::Machine::nouvelle(
            qui,
            demandeur.proprietaire,
            asl_auth::Capacites {
                annonce: demandeur.annonce,
                lecture: demandeur.lecture,
            },
        )
        .ok()?;

        let service = self.entrepot.service_par_nom(machine, nom).ok().flatten()?;
        let visee = self.entrepot.machine(machine).ok().flatten()?;
        let cible = asl_auth::Cible::nouvelle(service, machine, visee.proprietaire).ok()?;

        let autorisations = self
            .entrepot
            .autorisations_recues(demandeur.proprietaire())
            .ok()?
            .into_iter()
            .filter_map(|quoi| {
                asl_auth::Autorisation::nouvelle(
                    quoi.par,
                    quoi.a,
                    match quoi.portee {
                        asl_registre::Portee::ToutLeCompte => asl_auth::Portee::ToutLeCompte,
                        asl_registre::Portee::UneMachine(quelle) => {
                            asl_auth::Portee::UneMachine(quelle)
                        }
                        asl_registre::Portee::UnService(quel) => asl_auth::Portee::UnService(quel),
                    },
                    quoi.revoquee,
                )
                .ok()
            })
            .collect();

        // **CE QUI EST ANNONCÉ, LU MAINTENANT ET RÉVÉLÉ PLUS TARD.** C'est
        // notre propre mémoire : la lire ne dit rien à personne. La RENDRE est
        // une décision, et elle se prend à l'étage 2, après l'autorisation.
        let annonce = self.vivier.annonce(service).and_then(|vivante| {
            let mut sortie = alloc_reponse();
            let combien = vivante.reponse().ok()?.encoder(&mut sortie).ok()?;
            sortie.truncate(combien);
            Some(sortie)
        });

        Some(Resolution {
            demandeur,
            cible,
            autorisations,
            annonce,
        })
    }
}

/// L'instant courant, comme `asl-annuaire` le compte.
///
/// **EN MILLISECONDES, ET MONOTONE PAR CONVENTION.** `asl_annuaire::Instant` est
/// une horloge de DÉCISION — elle sert à dire « ce bail a-t-il expiré ». On la
/// tire de la même source que le reste de la boucle, en divisant les
/// microsecondes : un bail se compte en dizaines de secondes, et la
/// milliseconde y est déjà une précision de trop.
fn instant() -> asl_annuaire::Instant {
    asl_annuaire::Instant::depuis_millisecondes(maintenant().saturating_div(1_000))
}

/// Combien de temps entre deux balayages des codes périmés, en millisecondes.
///
/// Cinq minutes. Un code vaut dix minutes ; il ne survit donc jamais plus de
/// quinze à sa mort, et il est refusé pendant tout ce temps.
const BALAYAGE_DES_CODES_MS: u64 = 5 * 60 * 1_000;

/// Le port qu'on note quand un pair prétend parler depuis le zéro.
const PORT_DE_SECOURS: asl_proto::Port = match asl_proto::Port::depuis_u16(1) {
    Ok(port) => port,
    Err(_) => panic!("un est un port"),
};

/// Un tampon pour une réponse d'annonce.
///
/// `asl_proto::cadrage::MESSAGE_MAX` est la borne du protocole : au-delà, le
/// message ne serait de toute façon pas lisible par un pair.
fn alloc_reponse() -> Vec<u8> {
    vec![0_u8; asl_proto::cadrage::MESSAGE_MAX]
}

/// L'application qui sert l'API de l'annuaire en HTTP/3.
pub struct Annuaire<'a> {
    /// Un conducteur et une session par connexion vivante.
    connexions: HashMap<Vec<u8>, ParConnexion>,
    /// Ce qui se souvient, partagé par toutes les connexions.
    entrepot: &'a Entrepot,
    /// Toutes les annonces vivantes.
    vivier: Vivier,
    /// Par où les sondes rapportent.
    rapports: tokio::sync::mpsc::UnboundedSender<Verdict>,
    /// Ce qu'elles rapportent, recueilli à chaque tour.
    verdicts: tokio::sync::mpsc::UnboundedReceiver<Verdict>,
    /// Combien de sondes sont en vol.
    en_vol: usize,
    /// De quoi tirer un identifiant de service.
    tirer_un_identifiant: &'a (dyn Fn() -> Option<[u8; 16]> + Send + Sync),
    /// De quoi tirer un défi.
    ///
    /// `Send + Sync` : l'écoute tourne dans une tâche, et ce qu'elle tient doit
    /// pouvoir y aller avec elle.
    tirer_un_defi: &'a (dyn Fn() -> Option<Defi> + Send + Sync),
    /// Combien de connexions ont parlé HTTP/3.
    servies: u64,
    /// Ce que cet annuaire exige d'un appareil qui s'enrôle.
    ///
    /// **Il n'y a pas de défaut** — voir `asl_auth::Politique`. L'exploitant
    /// dit laquelle il tient, et `asl-server` refuse de démarrer sans.
    politique: asl_auth::Politique,
    /// De quoi vérifier les attestations, si l'exploitant l'a fourni.
    attestations: Attestations<'a>,
    /// Le bail qu'on accorde : la cadence attendue et le délai d'inactivité.
    ///
    /// # POURQUOI IL VIENT DE L'ASSEMBLEUR, ET N'EST PLUS UNE CONSTANTE
    ///
    /// C'était la SEULE politique codée en dur dans cette boucle, alors que
    /// toutes les autres — l'attestation, l'inactivité du transport, le nombre
    /// de connexions — viennent du binaire. Une politique qu'on ne peut pas
    /// choisir est une politique qu'on ne peut pas éprouver : il fallait
    /// attendre trente secondes pour voir un bail expirer.
    ///
    /// **ET SURTOUT, IL DOIT S'ACCORDER AVEC L'INACTIVITÉ DU TRANSPORT.** Deux
    /// constantes dans deux fichiers finissent par diverger ; un paramètre
    /// laisse `asl-server` les dériver l'une de l'autre.
    bail: asl_proto::Bail,
    /// Quand les codes expirés ont été balayés pour la dernière fois.
    dernier_balayage: u64,
    /// Les pairs révoqués dont il reste des connexions à fermer.
    revoques: Vec<Identifiant>,
    /// Ce que le tireur demande de fermer ici : une clé de machine révoquée,
    /// une annonce retirée, un appareil révoqué, appliqués depuis l'AUTRE
    /// racine (`docs/replication.md` §3.3).
    ///
    /// # POURQUOI UN CANAL, ET NON UN APPEL DIRECT
    ///
    /// Le tireur tourne dans SA tâche, et ne tient aucune connexion — c'est
    /// cette boucle qui les tient. Il applique l'opération à l'entrepôt partagé,
    /// puis NOMME ce qu'il faut fermer ; `au_tour` le verse dans [`Self::revoques`],
    /// et la fermeture suit le même chemin qu'une révocation locale.
    fermetures: Option<tokio::sync::mpsc::UnboundedReceiver<Identifiant>>,
    /// La voie entre racines : nos clés, et où dire ce qui s'y passe.
    voie: Voie<'a>,
    /// L'identifiant `n-…` que la clé du pair donne, calculé une fois.
    pair_attendu: Option<Identifiant>,
    /// Ce que la requête en cours a préparé pour son flux de la voie.
    ///
    /// Vivant le temps d'un `a_la_lecture` : déposé par le service, ramassé
    /// par la boucle juste après, jamais gardé d'un tour à l'autre.
    suite: Option<SuiteAuPair>,
}

impl<'a> Annuaire<'a> {
    /// Une application neuve, servant depuis cet entrepôt.
    ///
    /// **ELLE NE PREND PLUS DE LIAISON DE CANAL** : celle-ci est propre à chaque
    /// connexion, et s'exporte de sa poignée de main plutôt que de se calculer
    /// une fois pour toutes depuis notre certificat.
    ///
    /// `tirer_un_defi` rend trente-deux octets imprévisibles, ou `None` si le noyau
    /// a refusé — auquel cas la réponse sera `500`, jamais un défi de repli.
    ///
    /// `voie` porte les clés de la voie entre racines, ou [`Voie::AUCUNE`].
    #[must_use]
    pub fn new(
        entrepot: &'a Entrepot,
        tirer_un_defi: &'a (dyn Fn() -> Option<Defi> + Send + Sync),
        tirer_un_identifiant: &'a (dyn Fn() -> Option<[u8; 16]> + Send + Sync),
        politique: asl_auth::Politique,
        attestations: Attestations<'a>,
        bail: asl_proto::Bail,
        voie: Voie<'a>,
    ) -> Self {
        let (rapports, verdicts) = tokio::sync::mpsc::unbounded_channel();
        let pair_attendu = voie.pair.as_ref().map(asl_cle::identifiant_de_racine);
        Self {
            connexions: HashMap::new(),
            entrepot,
            vivier: Vivier::nouveau(),
            rapports,
            verdicts,
            en_vol: 0,
            tirer_un_identifiant,
            tirer_un_defi,
            servies: 0,
            politique,
            attestations,
            bail,
            dernier_balayage: 0,
            revoques: Vec::new(),
            voie,
            pair_attendu,
            suite: None,
            fermetures: None,
        }
    }

    /// Écoute ce que le tireur demande de fermer ici (`docs/replication.md`
    /// §3.3).
    ///
    /// **APPELÉ UNE FOIS, AU MONTAGE** : le tireur applique les opérations de
    /// l'autre racine à l'entrepôt, et pousse par ce canal les machines et
    /// appareils dont les connexions doivent tomber ici. `au_tour` les verse
    /// dans la file des révocations, et la boucle les ferme comme les siennes.
    pub fn ecouter_les_fermetures(
        &mut self,
        fermetures: tokio::sync::mpsc::UnboundedReceiver<Identifiant>,
    ) {
        self.fermetures = Some(fermetures);
    }

    /// Écrit ce qui attend sur le flux de la voie, cadre la suite dans la
    /// part, et le ferme s'il est fini.
    ///
    /// Rend `true` quand le flux n'a plus rien à faire ici — fermé, ou
    /// refusé par le transport — et doit être oublié.
    fn vidanger(conducteur: &mut Http3, connexion: &mut Connection, flux: &mut FluxPair) -> bool {
        loop {
            flux.cadrer_une_trame();
            if flux.en_attente.is_empty() {
                break;
            }
            let resultat = connexion.write(flux.flux, &flux.en_attente);
            match resultat {
                // Le transport est plein : la suite au tour suivant.
                Ok(0) => break,
                Ok(pris) => {
                    flux.en_attente.drain(..pris.min(flux.en_attente.len()));
                }
                // Le flux n'émet plus — le pair l'a annulé, ou la connexion
                // se ferme. Ce qui restait est perdu, et le tireur reprendra
                // depuis son curseur : c'est ce que le curseur existe pour
                // permettre.
                Err(_) => return true,
            }
        }
        if flux.en_attente.is_empty() && flux.a_clore {
            let _ = conducteur.clore(&mut Pont(connexion), flux.flux);
            return true;
        }
        false
    }

    /// Oublie le flux de la voie de cette connexion — et garde ce qu'il
    /// restait d'un instantané, pour le flux suivant.
    fn oublier_le_flux(etat: &mut ParConnexion) {
        if let Some(flux) = etat.flux_pair.take()
            && flux.curseur.is_none()
            && !flux.a_venir.is_empty()
        {
            etat.reste_d_instantane = Some(flux.a_venir);
        }
    }

    /// Ce que chaque flux de la voie a de neuf à pousser, ce tour-ci.
    ///
    /// # UNE LECTURE D'ENTIER PAR TOUR, ET LE JOURNAL SEULEMENT S'IL A BOUGÉ
    ///
    /// `Entrepot::derniere_operation` est posé après chaque commit qui
    /// journalise ; tant qu'il n'a pas dépassé ce que le flux a vu, il n'y a
    /// rien à relire. Et tant qu'un flux a de l'attente, il ne relit pas non
    /// plus : c'est la contre-pression de `FluxPair`.
    fn suivre_le_journal(&mut self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let derniere = self.entrepot.derniere_operation();
        let mut a_pousser = Vec::new();
        for (clef, etat) in &mut self.connexions {
            let Some(flux) = &mut etat.flux_pair else {
                continue;
            };
            if flux.en_attente.is_empty()
                && flux.a_venir.is_empty()
                && !flux.a_clore
                && let Some(curseur) = flux.curseur
                && flux.vu_jusqu_a < derniere
            {
                match self.entrepot.operations_apres(curseur) {
                    Ok(Rattrapage::Operations(cadres)) => {
                        flux.vu_jusqu_a = derniere;
                        if !cadres.is_empty() {
                            match dernier_compteur(&cadres) {
                                Some(compteur) => {
                                    flux.curseur = Some(compteur);
                                    flux.a_venir.extend(cadres);
                                }
                                None => {
                                    (self.voie.journal)(
                                        "une opération du journal ne se relit pas : le flux se ferme",
                                    );
                                    flux.a_clore = true;
                                }
                            }
                        }
                    }
                    // Le journal s'est expiré sous le lecteur, ou la base
                    // refuse : on ferme, et le tireur rouvre depuis son
                    // curseur — il recevra le `410`, et s'amorcera.
                    Ok(Rattrapage::HorsJournal { .. }) | Err(_) => {
                        (self.voie.journal)(
                            "le journal ne remonte plus jusqu'au curseur d'un flux ouvert : il se ferme",
                        );
                        flux.a_clore = true;
                    }
                }
            }
            if flux.a_pousser() {
                a_pousser.push((clef.clone(), Vec::new()));
            }
        }
        a_pousser
    }

    /// Combien d'annonces vivent.
    #[must_use]
    pub fn annonces_vivantes(&self) -> usize {
        self.vivier.combien()
    }

    /// Combien de connexions ont parlé HTTP/3.
    #[must_use]
    pub const fn servies(&self) -> u64 {
        self.servies
    }

    /// Traduit les pairs révoqués en connexions à fermer.
    ///
    /// # C'EST ICI QUE « EFFET IMMÉDIAT » DEVIENT VRAI
    ///
    /// Révoquer écrit dans l'entrepôt, ce qui suffit à refuser la PROCHAINE
    /// authentification. Mais une connexion déjà authentifiée porte son pair
    /// avec elle — c'est tout l'intérêt du transport tenu (`protocole.md` §3) —,
    /// et elle continuerait donc de servir. **La connexion EST le bail** : la
    /// fermer fait tomber les annonces du daemon, sans qu'on ait à toucher au
    /// vivier ; `a_la_fermeture` s'en charge, comme pour un départ ordinaire.
    ///
    /// **Une seule traduction par tour, et la liste est vidée.** Un pair qui
    /// ouvrirait une connexion neuve après coup ne s'authentifierait pas : sa
    /// clé n'est plus là. Il n'y a donc rien à retenir.
    fn consignes_de_fermeture(&mut self) -> crate::quic::Consignes {
        if self.revoques.is_empty() {
            return crate::quic::Consignes::default();
        }
        let revoques = core::mem::take(&mut self.revoques);
        let a_fermer = self
            .connexions
            .iter()
            .filter(|(_, etat)| {
                etat.session
                    .pair()
                    .is_some_and(|pair| revoques.contains(&pair))
            })
            .map(|(clef, _)| clef.clone())
            .collect();
        crate::quic::Consignes {
            a_fermer,
            a_pousser: Vec::new(),
        }
    }

    /// La poussée d'un service, telle qu'elle part sur le fil.
    ///
    /// **ELLE NE PORTE AUCUN IDENTIFIANT DE SERVICE** (`protocole.md` §1.4) : la
    /// connexion le détermine déjà, et l'y remettre serait un champ qui peut
    /// CONTREDIRE la connexion sur laquelle il arrive.
    fn composer_une_poussee(&self, service: Identifiant) -> Option<Vec<u8>> {
        let vivante = self.vivier.annonce(service)?;
        let mut sortie = alloc_reponse();
        let combien = vivante.poussee().ok()?.encoder(&mut sortie).ok()?;
        sortie.truncate(combien);
        Some(sortie)
    }

    /// Efface les codes d'enrôlement périmés, de loin en loin.
    ///
    /// # POURQUOI PAS À CHAQUE TOUR
    ///
    /// C'est un balayage de table, et la boucle en fait des milliers par
    /// seconde. **Il ne change aucune décision** — un code expiré est refusé de
    /// toute façon, `asl_auth::decider_enrolement` le dit —, donc rien n'exige
    /// qu'il soit prompt. Il empêche seulement une table de secrets morts de
    /// grandir sans fin.
    fn balayer_les_codes(&mut self) {
        let maintenant_ms = maintenant().saturating_div(1_000);
        if maintenant_ms.saturating_sub(self.dernier_balayage) < BALAYAGE_DES_CODES_MS {
            return;
        }
        self.dernier_balayage = maintenant_ms;
        // Une base qui refuse ne doit pas arrêter la boucle : le balayage
        // reviendra, et rien ne dépend de lui.
        let _ = self.entrepot.expirer_les_enrolements(maintenant_ms);
    }

    /// Ferme cette connexion sur une faute d'HTTP/3.
    ///
    /// §8.1 : le code applicatif dit au pair ce qu'il a fait de travers. Sans
    /// lui, il attendrait son délai d'inactivité sans savoir pourquoi.
    fn condamner(connexion: &mut Connection, faute: &ams_h3::Error) {
        connexion.close_with(faute.close_code(), maintenant());
    }
}

impl Application for Annuaire<'_> {
    fn au_tour(&mut self, _maintenant: u64) -> crate::quic::Consignes {
        // **LES VERDICTS ARRIVENT ICI, ET NULLE PART AILLEURS.** Une sonde est
        // une tâche à part : elle ne touche pas au vivier, elle rapporte. C'est
        // ce qui permet d'attendre trois secondes un trois-temps sans arrêter
        // la boucle, qui n'a qu'une tâche pour toutes les connexions.
        let mut a_pousser = Vec::new();
        while let Ok(verdict) = self.verdicts.try_recv() {
            self.en_vol = self.en_vol.saturating_sub(1);
            // **ON NE POUSSE QUE CE QUI A CHANGÉ.** `appliquer` refuse un
            // verdict tardif — le service peut être parti, réannoncé, ou déjà
            // mesuré autrement —, et pousser un état inchangé ferait du bruit
            // sur une connexion qu'un daemon tient pour des mois.
            if !self.vivier.appliquer(&verdict) {
                continue;
            }
            let Some(clef) = self.vivier.connexion_de(verdict.service) else {
                continue;
            };
            let clef = clef.to_vec();
            let Some(octets) = self.composer_une_poussee(verdict.service) else {
                continue;
            };
            a_pousser.push((clef, octets));
        }
        // Et l'on oublie ce qui a expiré — une annonce dont la connexion est
        // tombée sans qu'on l'apprenne n'a personne pour la retirer.
        self.vivier.oublier_les_expirees(instant());
        self.balayer_les_codes();
        // **LA VOIE ENTRE RACINES SUIT LE JOURNAL ICI** : c'est le seul
        // rendez-vous qui n'appartienne à aucune connexion, et une écriture
        // faite sur une connexion se pousse sur une autre.
        a_pousser.extend(self.suivre_le_journal());
        // **CE QUE LE TIREUR A APPLIQUÉ FERME AUSSI ICI** : une clé révoquée ou
        // une annonce retirée par l'autre racine tombe sur cette boucle comme
        // une révocation locale (§3.3).
        if let Some(fermetures) = &mut self.fermetures {
            while let Ok(quoi) = fermetures.try_recv() {
                if !self.revoques.contains(&quoi) {
                    self.revoques.push(quoi);
                }
            }
        }
        let mut consignes = self.consignes_de_fermeture();
        consignes.a_pousser = a_pousser;
        consignes
    }

    fn a_pousser(&mut self, connexion: &mut Connection, octets: &[u8]) {
        // **SUR LES FLUX QUE LE CONDUCTEUR TIENT, ET NULLE PART AILLEURS.** Un
        // daemon en ouvre au plus un — `GET /v1/poussees` —, et celui qui n'en a
        // ouvert aucun ne reçoit rien : il a répondu `en_cours` et n'a pas
        // demandé la suite.
        let clef = connexion.local_id().as_bytes().to_vec();
        let Some(etat) = self.connexions.get_mut(&clef) else {
            return;
        };
        // **UNE CONNEXION DE LA VOIE N'A QU'UN FLUX, ET C'EST LE SIEN.** Ce
        // qui s'y écrit est ce que `suivre_le_journal` y a mis en attente ;
        // la consigne ne porte rien, elle dit « écris ce que tu tiens ».
        if let Some(flux) = &mut etat.flux_pair {
            // **UN FLUX QUI SE FERME NE SE DIT PAS** : il a porté sa part, et
            // le tireur en rouvre un — une ligne par part serait presque une
            // ligne par opération (§8). Ce qui se dit est le sens qui s'ouvre
            // et se ferme, et c'est la connexion.
            if Self::vidanger(&mut etat.conducteur, connexion, flux) {
                Self::oublier_le_flux(etat);
            }
            return;
        }
        let tenus: Vec<StreamId> = etat.conducteur.tenus().to_vec();
        for flux in tenus {
            // **UNE ÉCRITURE QUI ÉCHOUE NE FERME RIEN.** Le pair a peut-être
            // fermé son flux entre-temps ; le verdict est perdu, et le prochain
            // le remplacera — la poussée porte la liste ENTIÈRE, pas un delta.
            let _ = etat.conducteur.pousser(&mut Pont(connexion), flux, octets);
        }
    }

    fn a_l_etablissement(&mut self, connexion: &mut Connection, _pair: SocketAddr) {
        // ── LA LIAISON EST CELLE DE CETTE CONNEXION, ET DE NULLE AUTRE ──────
        //
        // Elle était calculée une fois au démarrage, depuis notre certificat.
        // Elle est désormais EXPORTÉE de la poignée de main qui vient de se
        // terminer (RFC 8446 §7.5) : deux connexions au même serveur en tirent
        // deux valeurs, et c'est ce qui ferme le relais.
        //
        // **`None` NE SE RATTRAPE PAS.** Il faudrait que la poignée de main ne
        // soit pas terminée, alors que ce rendez-vous ne passe qu'après. Une
        // session sans liaison juste ne doit pas exister : on ferme, et le pair
        // recommence.
        let Some(liaison) = crate::liaison_de_la_connexion(connexion) else {
            connexion.close_with(ams_quic_tls::generic_close_code(), maintenant());
            return;
        };
        let clef = connexion.local_id().as_bytes().to_vec();
        let etat = self.connexions.entry(clef).or_insert_with(|| ParConnexion {
            conducteur: Http3::default(),
            session: Session::new(liaison),
            flux_pair: None,
            reste_d_instantane: None,
        });
        self.servies = self.servies.saturating_add(1);
        // §6.2.1 : notre flux de contrôle et nos réglages, tout de suite — puis
        // les deux flux QPACK de §4.2 de RFC 9204.
        if let Err(faute) = etat.conducteur.on_established(&mut Pont(connexion)) {
            Self::condamner(connexion, &faute);
        }
    }

    /// Un datagramme déchiffré de ce pair : son bail repart.
    ///
    /// # C'EST ICI, ET PLUS DANS `a_la_lecture`
    ///
    /// **LA CONNEXION VIVANTE EST LE KEEPALIVE.** `protocole.md` §1.2 : il n'y a
    /// pas de verbe pour rafraîchir, et cette ligne est ce qui le rend vrai.
    ///
    /// Elle était dans `a_la_lecture`, c'est-à-dire dans « un flux est
    /// lisible ». **Un `PING` de maintien n'ouvre aucun flux** (§10.1.2 de
    /// RFC 9000) : un daemon qui tient sa connexion sans rien demander voyait
    /// donc son annonce expirer sous lui, alors qu'il faisait exactement ce
    /// qu'on lui demande. Le rendez-vous du datagramme, lui, les voit tous.
    fn a_la_reception(&mut self, connexion: &Connection, _pair: SocketAddr) {
        self.vivier
            .keepalive(connexion.local_id().as_bytes(), instant());
    }

    fn a_la_lecture(&mut self, connexion: &mut Connection, flux: StreamId, pair: SocketAddr) {
        let clef = connexion.local_id().as_bytes().to_vec();
        let Some(etat) = self.connexions.get_mut(&clef) else {
            return;
        };
        // **DEUX EMPRUNTS DISJOINTS D'UN MÊME `etat`** : le conducteur pilote le
        // transport, la session sert la requête. Les séparer ici évite de
        // recopier l'un ou l'autre à chaque flux.
        let ParConnexion {
            conducteur,
            session,
            flux_pair,
            reste_d_instantane,
        } = etat;
        let racine_avant = session.racine();
        let mut service = Service {
            session,
            politique: self.politique,
            attestations: self.attestations,
            a_fermer: &mut self.revoques,
            entrepot: self.entrepot,
            vivier: &mut self.vivier,
            rapports: self.rapports.clone(),
            en_vol: &mut self.en_vol,
            connexion: clef.clone(),
            tirer_un_identifiant: self.tirer_un_identifiant,
            bail: self.bail,
            corps: Vec::new(),
            vu_depuis: asl_proto::VuDepuis {
                adresse: pair.ip(),
                // Un pair qui parle depuis le port zéro n'existe pas : une
                // socket connectée en a toujours un.
                port: asl_proto::Port::depuis_u16(pair.port()).unwrap_or(PORT_DE_SECOURS),
            },
            defi: (self.tirer_un_defi)(),
            voie: self.voie,
            pair_attendu: self.pair_attendu,
            flux_pair_tenu: flux_pair.is_some(),
            suite: &mut self.suite,
            reste_d_instantane,
        };
        if let Err(faute) = conducteur.on_readable(&mut Pont(connexion), &mut service, flux) {
            Self::condamner(connexion, &faute);
            self.suite = None;
            return;
        }
        // **LE SENS ENTRANT S'OUVRE QUAND L'AUTRE RACINE A PROUVÉ SA CLÉ**, et
        // c'est ce qui se dit (§8) — avec son identifiant.
        if racine_avant.is_none()
            && let Some(racine) = session.racine()
        {
            (self.voie.journal)(&format!(
                "voie depuis {racine} ouverte : l'autre racine a prouvé sa clé — elle tire d'ici"
            ));
        }
        // **CE QUE LA REQUÊTE A PRÉPARÉ PART SUR SON PROPRE FLUX**, tout de
        // suite : la réponse tenue vient d'y être écrite, et les cadres la
        // suivent dans le même tour. Ce qui n'entre pas attend, et
        // `au_tour` fera le reste.
        if let Some(suite) = self.suite.take() {
            let mut neuf = FluxPair {
                flux,
                en_attente: Vec::new(),
                a_venir: suite.cadres,
                portes: 0,
                curseur: suite.curseur,
                vu_jusqu_a: suite.vu_jusqu_a,
                a_clore: false,
            };
            if Self::vidanger(conducteur, connexion, &mut neuf) {
                if neuf.curseur.is_none() && !neuf.a_venir.is_empty() {
                    *reste_d_instantane = Some(neuf.a_venir);
                }
            } else {
                *flux_pair = Some(neuf);
            }
        }
    }

    fn a_l_arret(&mut self, connexion: &mut Connection, _pair: SocketAddr) {
        let clef = connexion.local_id().as_bytes().to_vec();
        let Some(etat) = self.connexions.get_mut(&clef) else {
            return;
        };
        // §5.2, premier temps : l'identifiant maximal. Il dit « n'ouvre plus
        // rien » sans condamner une seule requête déjà en vol.
        if let Err(faute) = etat.conducteur.shutdown(&mut Pont(connexion)) {
            Self::condamner(connexion, &faute);
        }
    }

    fn a_l_epuisement(&mut self, connexion: &mut Connection, _pair: SocketAddr) {
        let clef = connexion.local_id().as_bytes().to_vec();
        let Some(etat) = self.connexions.get_mut(&clef) else {
            return;
        };
        // §5.2, second temps : le rang qui suit la dernière requête servie.
        // Au-delà, le client sait que rien n'a été fait et peut rejouer
        // ailleurs.
        if let Err(faute) = etat.conducteur.drain(&mut Pont(connexion)) {
            Self::condamner(connexion, &faute);
        }
    }

    /// §5.2 : « `H3_NO_ERROR` » — on s'en va, et tout s'est bien passé. Fermer
    /// avec autre chose ferait chercher au client une faute qui n'existe pas.
    fn code_de_fermeture(&self) -> u64 {
        ams_h3::NO_ERROR
    }

    fn a_la_fermeture(&mut self, connexion: &Connection, _pair: SocketAddr) {
        // **ET C'EST ICI QUE LE BAIL TOMBE.** Tout ce que cette connexion avait
        // annoncé cesse d'exister, immédiatement — c'est le gain le plus net du
        // transport tenu. Avec des annonces périodiques, un daemon arrêté
        // proprement restait faussement présent jusqu'à l'expiration.
        //
        // **`Volontaire`, ET NON `Inactivite`.** La distinction compte pour qui
        // regarde (`protocole.md` §1.3), et l'écoute ne sait pas encore la
        // faire : elle ferme sur signal comme sur délai. Le motif juste viendra
        // avec ce qui distingue les deux — le dire ici plutôt que de laisser
        // croire que c'est déjà fait.
        let partis = self.vivier.retirer(
            connexion.local_id().as_bytes(),
            asl_annuaire::MotifDeDepart::Volontaire,
        );
        let _ = partis;
        if let Some(etat) = self.connexions.remove(connexion.local_id().as_bytes())
            && let Some(racine) = etat.session.racine()
        {
            // Le sens entrant se ferme avec la connexion de l'autre racine,
            // et c'est ce qui se dit (§8).
            (self.voie.journal)(&format!(
                "voie depuis {racine} fermée : la connexion de l'autre racine est tombée"
            ));
        }
    }
}
