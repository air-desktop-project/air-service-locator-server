//! La fédération (`docs/annuaires.md` §2 bis, §2 ter, §5.4 ;
//! `docs/protocole.md` §3 ter ; `docs/replication.md` décisions 34, 49, 52).
//!
//! # DEUX CÔTÉS, ET CE MODULE PORTE LES DEUX
//!
//! **Côté racine** : [`EtatFedere`], l'état des services que les annuaires
//! locaux rapportent. **En mémoire, et seulement là** (C13 amendée) : il
//! n'entre jamais dans l'entrepôt, ne se réplique pas entre racines — chaque
//! racine a sa voie vers chaque membre —, et tombe de lui-même quand plus
//! aucun membre ne le confirme.
//!
//! **Côté annuaire local** : [`Federateur`], la connexion SORTANTE vers une
//! racine. Il prouve la clé d'identité de l'annuaire, tire les machines de
//! ses domaines, les range, et pousse l'état de ses services — sans fin, avec
//! la reprise du tireur (`crate::tireur`). Et [`ServicesPublies`], ce que la
//! boucle qui sert publie pour lui : elle seule tient le vivier.
//!
//! # POURQUOI DES REQUÊTES COURTES RÉPÉTÉES, ET NON DEUX FLUX SANS FIN
//!
//! La spec esquissait deux flux tenus, un par sens. **La pile QUIC ne relève
//! jamais la fenêtre d'un flux** (`crate::tireur`, en-tête) : seize kibioctets
//! par flux et par sens, sur toute sa vie. La voie entre racines s'en sort en
//! coupant ses flux en parts ; un flux MONTANT sans fin — du client vers le
//! serveur — n'a pas cette ressource, puisque c'est le client qui écrit et que
//! la pile ne lui rend jamais de crédit. D'où des requêtes courtes, chacune
//! sur son flux, à une cadence, et dès que quelque chose change : ce qui
//! arrive est entier, et une requête perdue est refaite par la suivante.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use asl_api::annuaire::{DeclarationDePair, EtatDePaire, PaireRendue};
use asl_cle::CleSecrete;
use asl_id::Identifiant;
use asl_registre::{EntreeDEtat, MACHINE_FEDEREE_OCTETS, MachineFederee, NomRange};
use asl_store::Entrepot;

use crate::quic::maintenant;
use crate::tireur::{Connexion, Faute, Reprise, resoudre};

/// Combien de temps une racine croit un rapport qu'aucun membre ne
/// confirme : trente secondes (décidé le 2026-09-27, Thierry).
pub const EXPIRATION_US: u64 = 30 * 1_000_000;

/// Tous les combien un membre dont la paire est mal réglée le redit au
/// journal, en microsecondes : **dix minutes** (0.36.0, décision 70).
///
/// Assez souvent pour qu'un `journalctl -u asl-server --since -15min` le
/// montre toujours, et qu'on ne puisse pas lire le journal d'un membre mal
/// réglé sans le voir ; assez rarement pour ne pas noyer ce qui compte — à la
/// cadence des tours, dix secondes, ce serait trois cent soixante lignes par
/// heure, et l'œil apprend vite à sauter ce qui se répète. Un changement, lui,
/// se dit tout de suite.
pub const RAPPEL_DE_PAIRE_US: u64 = 10 * 60 * 1_000_000;

/// La cadence à laquelle un annuaire local rafraîchit tout — les machines
/// qu'il tire, l'état qu'il pousse —, en millisecondes. Dix secondes : trois
/// rapports manqués avant qu'une racine n'oublie.
pub const CADENCE_MS: u64 = 10_000;

/// Combien de machines fédérées tiennent dans une part.
///
/// Une part est ce qu'un flux porte sans que la fenêtre se ferme
/// ([`crate::h3::PART_OCTETS_MAX`]) ; une machine fédérée a une taille fixe.
pub const MACHINES_PAR_PART: usize = crate::h3::PART_OCTETS_MAX / MACHINE_FEDEREE_OCTETS;

/// La plus grande part d'état qu'un annuaire local poste : ce qu'une racine
/// accepte en corps (`asl_session::CORPS_OCTETS_MAX`).
const PART_D_ETAT_OCTETS: usize = asl_session::CORPS_OCTETS_MAX;

// La réponse d'annonce qu'une entrée porte est bornée par le message d'annonce
// dont elle est l'écho ; les deux bornes vivent dans deux crates qui ne se
// tirent pas, et c'est ici qu'on tient leur égalité.
const _: () = assert!(asl_registre::REPONSE_FEDEREE_OCTETS_MAX == asl_proto::cadrage::MESSAGE_MAX);
// Une entrée, même la plus longue, tient dans une part.
const _: () = assert!(asl_registre::ENTREE_D_ETAT_OCTETS_MAX <= PART_D_ETAT_OCTETS);

// ── Côté racine ─────────────────────────────────────────────────────────────

/// Ce qu'un membre a dit d'un service.
#[derive(Debug, Clone)]
struct Tenue {
    /// Le service, tel que ce membre l'a déclaré.
    service: Identifiant,
    /// Sa réponse d'annonce, s'il le dit vivant.
    reponse: Option<Vec<u8>>,
    /// Quand ce rapport est arrivé, en microsecondes.
    recu_a: u64,
}

/// Ce qu'une racine sait des services des domaines hébergés, en ce moment.
///
/// **Rangé par machine et par nom** — la clé sous laquelle une résolution
/// cherche —, puis **par membre** : les deux membres d'une paire rapportent
/// chacun ce que LUI voit, et un daemon ne s'annonce qu'à l'un des deux.
/// Leurs identifiants de service peuvent différer (chacun a déclaré le sien
/// si la réplication entre eux n'avait pas encore passé) ; c'est la machine
/// et le nom qui désignent le service pour qui le cherche.
#[derive(Debug, Default)]
pub struct EtatFedere {
    /// `machine ‖ nom` → membre → ce qu'il en a dit.
    tenus: HashMap<Vec<u8>, HashMap<Identifiant, Tenue>>,
    /// Ce que chaque membre a rapporté la dernière fois — `(entrées,
    /// vivantes)` —, pour que le journal ne dise un rapport qu'à la première
    /// fois et quand il change.
    derniers_rapports: HashMap<Identifiant, (usize, usize)>,
    /// Ce que chaque membre a conclu de sa paire, la dernière fois qu'il l'a
    /// dit (0.36.0, décision 70) — pour `GET /v1/annuaires`. **En mémoire,
    /// comme le reste** : une racine qui redémarre l'apprend au tour suivant
    /// de chaque membre, dix secondes au plus.
    paires: HashMap<Identifiant, EtatDePaire>,
}

/// Ce qu'une racine rend d'un service fédéré.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LueFederee {
    /// Le service.
    pub service: Identifiant,
    /// Sa réponse d'annonce, s'il est vivant.
    pub reponse: Option<Vec<u8>>,
    /// Le membre dont le rapport a été retenu : c'est LUI qui a sondé, et
    /// c'est ce que `sonde_par` dit à l'écran (décision 60).
    pub membre: Identifiant,
}

/// La clé d'un service : sa machine, puis son nom.
fn clef_de_service(machine: Identifiant, nom: &[u8]) -> Vec<u8> {
    let mut clef = Vec::with_capacity(17_usize.saturating_add(nom.len()));
    clef.push(machine.genre().prefixe());
    clef.extend_from_slice(machine.octets());
    clef.extend_from_slice(nom);
    clef
}

/// Ce qu'on retient des rapports des membres sur UN service.
///
/// **Vivant si un membre le dit** (décision 49), et sa réponse est celle
/// du rapport vivant le plus récent. Déclaré mais parti si les membres qui
/// en parlent encore le disent tous parti. Rien si aucun rapport n'a moins
/// de `expiration` microsecondes : le silence ne prouve rien (C6).
fn retenir(
    tenus: &HashMap<Identifiant, Tenue>,
    maintenant: u64,
    expiration: u64,
) -> Option<LueFederee> {
    let mut plus_recent: Option<(&Identifiant, &Tenue)> = None;
    let mut vivant: Option<(&Identifiant, &Tenue)> = None;
    for (membre, tenue) in tenus
        .iter()
        .filter(|(_, tenue)| tenue.recu_a.saturating_add(expiration) >= maintenant)
    {
        if plus_recent.is_none_or(|(_, avant)| tenue.recu_a > avant.recu_a) {
            plus_recent = Some((membre, tenue));
        }
        if tenue.reponse.is_some() && vivant.is_none_or(|(_, avant)| tenue.recu_a > avant.recu_a) {
            vivant = Some((membre, tenue));
        }
    }
    vivant.or(plus_recent).map(|(membre, tenue)| LueFederee {
        service: tenue.service,
        reponse: tenue.reponse.clone(),
        membre: *membre,
    })
}

impl EtatFedere {
    /// Un état vide.
    #[must_use]
    pub fn nouveau() -> Self {
        Self::default()
    }

    /// Range ce qu'un membre dit d'un service : il remplace ce que CE membre
    /// en disait, et rien de ce que l'autre en dit.
    pub fn ranger(&mut self, membre: Identifiant, entree: &EntreeDEtat<'_>, maintenant: u64) {
        self.tenus
            .entry(clef_de_service(entree.machine, entree.nom.octets()))
            .or_default()
            .insert(
                membre,
                Tenue {
                    service: entree.service,
                    reponse: entree.reponse.map(<[u8]>::to_vec),
                    recu_a: maintenant,
                },
            );
    }

    /// Ce que les membres disent de ce service, en ce moment.
    ///
    /// **Vivant si un membre le dit** (décision 49), et sa réponse est celle
    /// du rapport vivant le plus récent. Déclaré mais parti si les membres
    /// qui en parlent encore le disent tous parti. Rien si aucun rapport n'a
    /// moins de `expiration` microsecondes : le silence ne prouve rien, et
    /// l'on n'en dit rien (C6).
    #[must_use]
    pub fn lire(
        &self,
        machine: Identifiant,
        nom: &[u8],
        maintenant: u64,
        expiration: u64,
    ) -> Option<LueFederee> {
        retenir(
            self.tenus.get(&clef_de_service(machine, nom))?,
            maintenant,
            expiration,
        )
    }

    /// Tous les services qu'on rapporte d'une machine, en ce moment, avec
    /// leur nom — ce que `GET /v1/machines/{m}/services` rend pour une
    /// machine d'un domaine confié (décision 60).
    ///
    /// **La même règle que [`Self::lire`], service par service** : vivant si
    /// un membre le dit, parti si tous ceux qui en parlent encore le disent
    /// parti, rien pour ce que plus personne ne confirme. L'ordre est celui
    /// des noms, pour qu'un écran relu ne voie pas ses lignes danser.
    #[must_use]
    pub fn services_de(
        &self,
        machine: Identifiant,
        maintenant: u64,
        expiration: u64,
    ) -> Vec<(Vec<u8>, LueFederee)> {
        let prefixe = clef_de_service(machine, b"");
        let mut trouves: Vec<(Vec<u8>, LueFederee)> = self
            .tenus
            .iter()
            .filter_map(|(clef, tenus)| {
                let nom = clef.strip_prefix(prefixe.as_slice())?;
                Some((nom.to_vec(), retenir(tenus, maintenant, expiration)?))
            })
            .collect();
        trouves.sort_by(|a, b| a.0.cmp(&b.0));
        trouves
    }

    /// Oublie ce qu'aucun membre ne confirme plus : la mémoire ne grossit pas
    /// d'annuaires disparus.
    pub fn oublier_les_perimes(&mut self, maintenant: u64, expiration: u64) {
        self.tenus.retain(|_, tenus| {
            tenus.retain(|_, tenue| tenue.recu_a.saturating_add(expiration) >= maintenant);
            !tenus.is_empty()
        });
    }

    /// Combien de services sont tenus, frais ou non.
    #[must_use]
    pub fn combien(&self) -> usize {
        self.tenus.len()
    }

    /// Note ce qu'un membre vient de rapporter ; rend `true` si c'est la
    /// première fois, ou si le compte a changé — ce que le journal doit dire.
    pub fn noter_un_rapport(
        &mut self,
        membre: Identifiant,
        entrees: usize,
        vivantes: usize,
    ) -> bool {
        self.derniers_rapports.insert(membre, (entrees, vivantes)) != Some((entrees, vivantes))
    }

    /// Note ce qu'un membre conclut de sa paire ; rend `true` si c'est la
    /// première fois ou si cela a changé — ce que le journal doit dire.
    pub fn noter_une_paire(&mut self, membre: Identifiant, etat: EtatDePaire) -> bool {
        self.paires.insert(membre, etat) != Some(etat)
    }

    /// Ce que ce membre a conclu de sa paire, s'il l'a dit depuis que cette
    /// racine tourne.
    #[must_use]
    pub fn paire_de(&self, membre: Identifiant) -> Option<EtatDePaire> {
        self.paires.get(&membre).copied()
    }
}

/// L'annuaire local s'est-il sondé DE L'INTÉRIEUR (décision 60) ?
///
/// Il a vu le daemon arriver depuis `vu_depuis` ; `ou_le_joindre` sont les
/// adresses où on le joint lui-même. Si le daemon est venu de l'une d'elles,
/// l'annuaire local et la machine sont le même hôte : son « joignable » dit
/// ce qu'on voit de l'intérieur, et rien de ce qu'un client verra dehors.
///
/// **Seules les adresses littérales comptent** (C20) : un locateur qui serait
/// un nom ne se résout pas ici, et ne fait rien conclure. **Une IPv4 vue au
/// travers d'une socket double pile arrive habillée en IPv6**
/// (`::ffff:a.b.c.d`) : on la déshabille avant de comparer.
#[must_use]
pub fn sonde_de_l_interieur(
    vu_depuis: std::net::IpAddr,
    ou_le_joindre: &[asl_registre::Adresse],
) -> bool {
    ou_le_joindre.iter().any(|adresse| {
        adresse
            .texte()
            .parse::<std::net::SocketAddr>()
            .is_ok_and(|ou| ou.ip().to_canonical() == vu_depuis.to_canonical())
    })
}

// ── Côté annuaire local ─────────────────────────────────────────────────────

/// Un service tel que l'annuaire local le publie pour les racines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePublie {
    /// Le service.
    pub service: Identifiant,
    /// Sa machine.
    pub machine: Identifiant,
    /// Son nom.
    pub nom: NomRange,
    /// Sa réponse d'annonce, s'il est vivant.
    pub reponse: Option<Vec<u8>>,
}

/// Ce que la boucle qui sert publie, et que les fédérateurs poussent.
///
/// # POURQUOI UNE PUBLICATION, ET NON UNE LECTURE DU VIVIER
///
/// Le vivier appartient à la boucle : c'est UNE tâche qui sert toutes les
/// connexions, et un fédérateur n'y a pas accès. Elle publie donc, au plus
/// quelques fois par seconde, la liste entière — elle est petite, c'est une
/// maison —, et elle en compte les versions pour qu'un fédérateur sache
/// qu'elle a changé sans la comparer.
#[derive(Debug, Default)]
pub struct ServicesPublies {
    /// La dernière liste publiée.
    liste: Mutex<Vec<ServicePublie>>,
    /// Combien de fois elle a changé.
    version: AtomicU64,
}

impl ServicesPublies {
    /// Une publication vide.
    #[must_use]
    pub fn nouvelle() -> Self {
        Self::default()
    }

    /// Publie cette liste, si elle diffère de la précédente.
    pub fn publier(&self, liste: Vec<ServicePublie>) {
        let mut tenue = self
            .liste
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *tenue != liste {
            *tenue = liste;
            self.version.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// La liste, et sa version.
    #[must_use]
    pub fn lire(&self) -> (u64, Vec<ServicePublie>) {
        let tenue = self
            .liste
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (self.version.load(Ordering::Acquire), tenue.clone())
    }

    /// Sa version.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }
}

/// Découpe ces services en corps de `POST /v1/federation/etat`, chacun
/// au plus d'une part.
///
/// Une entrée ne se coupe jamais : chaque corps est une suite d'entrées
/// entières, que la racine lit tout ou rien.
#[must_use]
pub fn corps_d_etat(services: &[ServicePublie]) -> Vec<Vec<u8>> {
    let mut corps = Vec::new();
    let mut courant: Vec<u8> = Vec::new();
    let mut tampon = vec![0_u8; asl_registre::ENTREE_D_ETAT_OCTETS_MAX];
    for publie in services {
        let entree = EntreeDEtat {
            service: publie.service,
            machine: publie.machine,
            nom: publie.nom,
            reponse: publie.reponse.as_deref(),
        };
        // Une réponse au-delà de la borne ne se rapporte pas : elle ne serait
        // pas plus longue que l'annonce qu'elle reflète, et ne peut donc venir
        // que d'un défaut — on la tait plutôt que de refuser le reste.
        let Ok(ecrit) = entree.ecrire(&mut tampon) else {
            continue;
        };
        if courant.len().saturating_add(ecrit) > PART_D_ETAT_OCTETS {
            corps.push(core::mem::take(&mut courant));
        }
        courant.extend_from_slice(tampon.get(..ecrit).unwrap_or_default());
    }
    if !courant.is_empty() {
        corps.push(courant);
    }
    corps
}

/// Lit une part de machines fédérées : des enregistrements entiers, à la
/// suite.
///
/// # Errors
///
/// [`Faute::Illisible`] si la part n'est pas faite d'enregistrements entiers,
/// ou si l'un d'eux ne se lit pas.
pub fn lire_une_part_de_machines(octets: &[u8]) -> Result<Vec<MachineFederee>, Faute> {
    let (morceaux, reste) = octets.as_chunks::<MACHINE_FEDEREE_OCTETS>();
    if !reste.is_empty() {
        return Err(Faute::Illisible);
    }
    morceaux
        .iter()
        .map(|morceau| MachineFederee::lire(morceau).map_err(|_| Faute::Illisible))
        .collect()
}

/// Ce qu'un membre d'annuaire local conclut de sa paire (0.36.0, décision 70),
/// partagé entre ses fédérateurs — un par racine — et la boucle qui sert
/// `GET /v1/version`.
///
/// # C'EST LE MEMBRE QUI DÉTECTE, ET IL LE DIT FORT
///
/// Les racines lui disent, à chaque tour, les membres acceptés de son
/// annuaire (`PUT /v1/federation/paire`) ; il les compare à son `--peer`
/// ([`EtatDePaire::juger`]). Une paire mal réglée — un autre membre accepté
/// et pas de `--peer`, ou un `--peer` qui ne désigne aucun membre accepté —
/// se dit au journal **dès qu'on l'apprend, puis toutes les dix minutes**
/// ([`RAPPEL_DE_PAIRE_US`]), et `GET /v1/version` la rend. **Le membre ne
/// s'arrête pas** : seul, il sert encore ses daemons, et c'est ce qu'on veut
/// d'un secours.
///
/// **Partagé, et c'est ce qui évite le doublon** : deux fédérateurs
/// apprennent la même chose de deux racines ; la ligne ne sort qu'une fois.
#[derive(Debug)]
pub struct PaireJugee {
    /// Ce qu'on a conclu, et quand on l'a dit.
    tenue: Mutex<TenueDePaire>,
    /// Tous les combien redire une paire mal réglée, en microsecondes.
    rappel_us: u64,
}

/// L'intérieur de [`PaireJugee`].
#[derive(Debug, Default)]
struct TenueDePaire {
    /// La conclusion, si l'on a entendu les racines.
    etat: Option<EtatDePaire>,
    /// Les membres acceptés qu'elles ont dits.
    membres: Vec<Identifiant>,
    /// Quand la dernière ligne est partie au journal, en microsecondes.
    dite_a: u64,
}

impl Default for PaireJugee {
    fn default() -> Self {
        Self::nouvelle()
    }
}

impl PaireJugee {
    /// Rien encore : les racines n'ont rien dit.
    #[must_use]
    pub fn nouvelle() -> Self {
        Self::avec_rappel(RAPPEL_DE_PAIRE_US)
    }

    /// La même, avec un autre rappel — un essai n'attend pas dix minutes.
    #[must_use]
    pub fn avec_rappel(rappel_us: u64) -> Self {
        Self {
            tenue: Mutex::new(TenueDePaire::default()),
            rappel_us,
        }
    }

    /// Ce qu'on a conclu, si les racines ont parlé.
    #[must_use]
    pub fn etat(&self) -> Option<EtatDePaire> {
        self.tenue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .etat
    }

    /// Range ce que les racines viennent de dire, et rend la ligne à écrire
    /// au journal, s'il en faut une : **à la première fois et à chaque
    /// changement**, et, tant que la paire est mal réglée, **toutes les
    /// [`RAPPEL_DE_PAIRE_US`]**.
    pub fn constater(
        &self,
        moi: Identifiant,
        pair: Option<Identifiant>,
        membres: &[Identifiant],
        maintenant: u64,
    ) -> Option<String> {
        let etat = EtatDePaire::juger(moi, pair, membres);
        let mut tenue = self
            .tenue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let change = tenue.etat != Some(etat) || tenue.membres != membres;
        let rappel = etat.alerte() && maintenant >= tenue.dite_a.saturating_add(self.rappel_us);
        tenue.etat = Some(etat);
        tenue.membres = membres.to_vec();
        if !change && !rappel {
            return None;
        }
        tenue.dite_a = maintenant;
        Some(ligne_de_paire(etat, moi, pair, membres))
    }
}

/// La ligne du journal pour cette conclusion.
fn ligne_de_paire(
    etat: EtatDePaire,
    moi: Identifiant,
    pair: Option<Identifiant>,
    membres: &[Identifiant],
) -> String {
    let autres: Vec<String> = membres
        .iter()
        .filter(|membre| **membre != moi)
        .map(|membre| membre.texte().as_str().to_owned())
        .collect();
    let autres = if autres.is_empty() {
        "aucun".to_owned()
    } else {
        autres.join(", ")
    };
    let pair = pair.map_or_else(String::new, |pair| pair.texte().as_str().to_owned());
    match etat {
        EtatDePaire::SansPeer => format!(
            "PAIRE MAL RÉGLÉE (sans-peer) : les racines disent que cet annuaire local ({moi}) \
             a un autre membre accepté, {autres}, et ce membre tourne SANS --peer — les deux ne \
             se répliquent pas, chacun frappe ses propres s-…, et un daemon qui bascule de l'un \
             à l'autre change d'identifiant. Réglez --peer <hôte:port> et --peer-key <la clé \
             publique de {autres}> (docs/annuaires.md §2 ter, décision 70). Cet annuaire \
             continue de servir."
        ),
        EtatDePaire::PeerInconnu => format!(
            "PAIRE MAL RÉGLÉE (peer-inconnu) : --peer désigne {pair}, qui n'est pas un autre \
             membre accepté de cet annuaire local ({moi}) — autre(s) membre(s) accepté(s) : \
             {autres}. Corrigez --peer-key (docs/annuaires.md §2 ter, décision 70). Cet \
             annuaire continue de servir."
        ),
        EtatDePaire::Reglee => format!(
            "paire réglée : --peer désigne {pair}, l'autre membre accepté de cet annuaire \
             local ({moi})."
        ),
        EtatDePaire::Seul => format!(
            "paire : cet annuaire local ({moi}) n'a pas d'autre membre accepté, et tourne sans \
             --peer — il est seul."
        ),
    }
}

/// La connexion d'un annuaire local vers UNE racine, et ce qu'elle porte.
///
/// **Elle possède ce qu'elle tient**, comme [`crate::tireur::Tireur`] : la
/// tâche vit aussi longtemps que le serveur.
pub struct Federateur {
    /// Ce qui se souvient — là où les machines reçues se rangent.
    pub entrepot: Arc<Entrepot>,
    /// La racine — `hôte:port`.
    pub adresse: String,
    /// Ce qu'on croit de la racine : son identité — dite (`=<n-…>`) ou tirée
    /// de la liste embarquée (décision 56) —, et rien d'autre (décision 58).
    pub confiance: crate::confiance::Confiance,
    /// La clé d'identité de cet annuaire.
    pub identite: CleSecrete,
    /// La cadence de maintien de la connexion, en microsecondes.
    pub keepalive_us: u64,
    /// L'inactivité annoncée, en microsecondes.
    pub idle_us: u64,
    /// La cadence à laquelle tout se rafraîchit, en millisecondes
    /// ([`CADENCE_MS`] en service).
    pub cadence_ms: u64,
    /// Ce que la boucle publie.
    pub publies: Arc<ServicesPublies>,
    /// Ce qu'il faut fermer ici quand une machine sort de nos domaines.
    pub fermetures: crate::h3::Fermetures,
    /// De quoi tirer un aléa pour le bruit de la reprise.
    pub alea: Box<dyn Fn() -> u16 + Send + Sync>,
    /// Le journal d'exploitation.
    pub journal: Box<dyn Fn(String) + Send + Sync>,
    /// Le plafond du recul, en millisecondes.
    pub plafond_recul_ms: u64,
    /// Où l'on nous joint (décision 57) — de l'ASCII sans guillemet ni
    /// barre, que les réglages ou la détection ont jugé. Publié à chaque
    /// ouverture, et **dès qu'il change pendant la session** (décision 64).
    /// **Une liste vide retire ce qui était publié** : l'adresse déclarée sert
    /// de nouveau ; **aucune liste** (localisateur pas encore détecté) ne
    /// publie rien, et les racines gardent ce qu'elles tenaient.
    pub locateurs: Arc<LocateursPublies>,
    /// Le `n-…` que la clé de `--peer-key` donne, si ce membre a un
    /// `--peer` (0.36.0, décision 70) : c'est ce qu'il dit aux racines, et ce
    /// qu'il compare aux membres acceptés qu'elles lui rendent.
    pub pair: Option<Identifiant>,
    /// Ce qu'il en conclut, partagé avec les autres fédérateurs et la boucle.
    pub paire: Arc<PaireJugee>,
}

/// Où l'on joint cet annuaire, tel que les fédérateurs le publient aux
/// racines — et ses versions, comme [`ServicesPublies`].
///
/// **Fixes** avec `--locator <hôte:port>` : posés au démarrage, ils ne
/// bougent plus. **Détectés** avec `--locator auto` (décision 64) : la tâche
/// de `crate::localisateur` les republie quand l'adresse change, et chaque
/// fédérateur le voit au tour suivant de sa boucle.
///
/// `None` n'est pas une liste vide : c'est « on ne sait pas encore ». Une
/// liste vide retire ce qui était publié ; « on ne sait pas » ne dit rien, et
/// la racine garde la dernière publication — qui a plus de chances d'être
/// juste qu'un retrait vers l'adresse déclarée à l'inscription.
#[derive(Debug, Default)]
pub struct LocateursPublies {
    /// La dernière liste publiée, si l'on en a une.
    liste: Mutex<Option<Vec<String>>>,
    /// Combien de fois elle a changé.
    version: AtomicU64,
}

impl LocateursPublies {
    /// Des locateurs fixes, connus dès le démarrage.
    #[must_use]
    pub fn fixes(liste: Vec<String>) -> Self {
        Self {
            liste: Mutex::new(Some(liste)),
            version: AtomicU64::new(0),
        }
    }

    /// Rien encore : le localisateur n'est pas détecté.
    #[must_use]
    pub fn inconnus() -> Self {
        Self::default()
    }

    /// Publie cette liste, si elle diffère de la précédente ; rend `true` si
    /// elle a changé.
    pub fn publier(&self, liste: Vec<String>) -> bool {
        let mut tenue = self
            .liste
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if tenue.as_ref() == Some(&liste) {
            return false;
        }
        *tenue = Some(liste);
        self.version.fetch_add(1, Ordering::AcqRel);
        true
    }

    /// La liste, et sa version.
    #[must_use]
    pub fn lire(&self) -> (u64, Option<Vec<String>>) {
        let tenue = self
            .liste
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (self.version.load(Ordering::Acquire), tenue.clone())
    }

    /// Sa version.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }
}

/// Le corps de `PUT /v1/federation/locateurs` : `{"locateurs":[…]}`.
#[must_use]
pub fn corps_de_locateurs(locateurs: &[String]) -> Vec<u8> {
    let cites: Vec<String> = locateurs
        .iter()
        .map(|locateur| format!("\"{locateur}\""))
        .collect();
    format!("{{\"locateurs\":[{}]}}", cites.join(",")).into_bytes()
}

impl Federateur {
    /// Fédère vers cette racine, sans fin.
    ///
    /// **CETTE FONCTION NE REND JAMAIS** tant que la tâche vit : à chaque
    /// rupture, on recule et l'on rappelle (`replication.md` §2.3).
    pub async fn federer_sans_fin(self) {
        let mut reprise = Reprise::nouvelle(self.plafond_recul_ms.max(1));
        loop {
            match self.une_session().await {
                Ok(()) => {
                    (self.journal)(format!(
                        "fédération vers {} fermée : la connexion s'est terminée",
                        self.adresse
                    ));
                    reprise.reussite();
                }
                Err(quoi) => (self.journal)(format!(
                    "fédération vers {} : {quoi} — reprise n° {}",
                    self.adresse,
                    reprise.essais().saturating_add(1)
                )),
            }
            let delai = reprise.prochain_delai((self.alea)());
            tokio::time::sleep(core::time::Duration::from_millis(delai)).await;
        }
    }

    /// Une session : ouvrir, prouver, puis rafraîchir à la cadence et à
    /// chaque changement, jusqu'à ce que la connexion tombe.
    async fn une_session(&self) -> Result<(), Faute> {
        let cible = resoudre(&self.adresse).await?;
        let mut connexion =
            Connexion::ouvrir(cible, &self.adresse, &self.confiance, self.idle_us).await?;
        connexion.maintenir(self.keepalive_us);
        // **LA MÊME PREUVE QU'UNE RACINE** — genre `n`, notre clé
        // d'identité : c'est la racine qui sait, de ses inscriptions, que
        // cette clé est celle d'un annuaire local accepté.
        connexion.prouver_notre_racine(&self.identite).await?;
        (self.journal)(format!(
            "fédération vers {} ouverte : clé prouvée (TLS : identité par la clé)",
            self.adresse,
        ));
        let mut locateurs_publies = self.publier_les_locateurs(&mut connexion, None).await?;

        let cadence_us = self.cadence_ms.saturating_mul(1_000);
        let mut prochaine = 0_u64;
        let mut version_poussee = None;
        // **CE QUI A ÉTÉ DIT AU JOURNAL**, pour ne le redire que s'il change :
        // la cadence est de dix secondes, et un journal qui répète la même
        // ligne six fois par minute noie celle qui compte.
        let mut machines_dites = None;
        let mut etat_dit = None;
        // Une racine d'avant la 0.36.0 ne connaît pas la paire : on le dit
        // une fois par session, pas à chaque tour.
        let mut paire_muette = false;
        loop {
            let maintenant = maintenant();
            let version = self.publies.version();
            if maintenant >= prochaine {
                let machines = self.tirer_les_machines(&mut connexion).await?;
                if machines_dites != Some(machines) {
                    (self.journal)(format!(
                        "fédération vers {} : {machines} machine(s) de nos domaines reçue(s)",
                        self.adresse
                    ));
                    machines_dites = Some(machines);
                }
                let pousse = self.pousser_l_etat(&mut connexion).await?;
                self.dire_l_etat(&mut etat_dit, pousse);
                version_poussee = Some(version);
                // **LA PAIRE, À CHAQUE TOUR** (décision 70) : on dit son
                // `--peer`, on apprend les membres acceptés, on juge.
                self.juger_la_paire(&mut connexion, &mut paire_muette)
                    .await?;
                prochaine = maintenant.saturating_add(cadence_us);
            } else if version_poussee != Some(version) {
                // **UN CHANGEMENT PART TOUT DE SUITE** : un daemon qui arrive ou
                // s'en va se voit aux racines dans le tour, pas à la cadence.
                let pousse = self.pousser_l_etat(&mut connexion).await?;
                self.dire_l_etat(&mut etat_dit, pousse);
                version_poussee = Some(version);
            }
            // **UN LOCALISATEUR QUI CHANGE PART TOUT DE SUITE** (décision
            // 64) : un préfixe renouvelé par l'opérateur se voit aux racines
            // dans le tour, sans attendre une reconnexion.
            if self.locateurs.version() != locateurs_publies {
                locateurs_publies = self
                    .publier_les_locateurs(&mut connexion, Some(locateurs_publies))
                    .await?;
            }
            connexion.entretenir(200).await?;
            if !connexion.vivante() {
                return Ok(());
            }
        }
    }

    /// Dit au journal ce qui vient d'être poussé, si cela a changé depuis la
    /// dernière fois : `(services, vivants)`.
    fn dire_l_etat(&self, dit: &mut Option<(usize, usize)>, pousse: (usize, usize)) {
        if *dit != Some(pousse) {
            let (services, vivants) = pousse;
            (self.journal)(format!(
                "fédération vers {} : état poussé — {services} service(s), dont {vivants} \
                 vivant(s), accepté (204)",
                self.adresse
            ));
            *dit = Some(pousse);
        }
    }

    /// `PUT /v1/federation/paire` : dit notre `--peer`, apprend les membres
    /// acceptés de notre annuaire, et juge (décision 70).
    ///
    /// **Rien de ce qui ne va pas ici ne coupe la voie** : une racine d'avant
    /// la 0.36.0 rend `404` — on le dit une fois, et l'on continue —, et une
    /// réponse illisible ne dit rien de plus. La fédération sert d'abord les
    /// daemons ; la paire n'est qu'un avertissement.
    async fn juger_la_paire(
        &self,
        connexion: &mut Connexion,
        muette: &mut bool,
    ) -> Result<(), Faute> {
        let mut corps = [0_u8; 64];
        let combien = DeclarationDePair { pair: self.pair }
            .encoder(&mut corps)
            .unwrap_or(0);
        let reponse = connexion
            .requete(
                b"PUT",
                b"/v1/federation/paire",
                &[(b"content-type", b"application/json")],
                corps.get(..combien).unwrap_or_default(),
            )
            .await?;
        let lue = match reponse.statut.value() {
            200 => PaireRendue::decoder(&reponse.corps).ok(),
            _ => None,
        };
        let Some(lue) = lue else {
            if !*muette {
                (self.journal)(format!(
                    "fédération vers {} : la racine ne dit pas la paire ({}) — antérieure à \
                     la 0.36.0 ?",
                    self.adresse,
                    reponse.statut.value()
                ));
                *muette = true;
            }
            return Ok(());
        };
        let membres: Vec<Identifiant> = lue.membres().collect();
        let moi = asl_cle::identifiant_de_racine(&self.identite.publique());
        if let Some(ligne) = self.paire.constater(moi, self.pair, &membres, maintenant()) {
            (self.journal)(ligne);
        }
        Ok(())
    }

    /// Tire toutes les parts des machines de nos domaines, et les range ;
    /// rend combien il y en a.
    async fn tirer_les_machines(&self, connexion: &mut Connexion) -> Result<usize, Faute> {
        let mut machines = Vec::new();
        loop {
            let chemin = format!("/v1/federation/machines?apres={}", machines.len());
            let reponse = connexion
                .requete(b"GET", chemin.as_bytes(), &[], b"")
                .await?;
            match reponse.statut.value() {
                200 => {}
                autre => return Err(Faute::Statut(autre)),
            }
            let part = lire_une_part_de_machines(&reponse.corps)?;
            let pleine = part.len() == MACHINES_PAR_PART;
            machines.extend(part);
            if !pleine {
                break;
            }
        }
        let rangement = self
            .entrepot
            .ranger_les_machines_federees(&machines)
            .map_err(Faute::Entrepot)?;
        for sortie in rangement.sorties {
            self.fermetures.fermer(sortie);
        }
        // **CE QUI ATTENDAIT SA MACHINE EST RANGÉ** (0.36.0, décision 69) :
        // des services du pair, tirés avant que les racines nous aient donné
        // leur machine. Le journal le dit, une fois par rejeu.
        if rangement.rejoues > 0 {
            (self.journal)(format!(
                "fédération vers {} : {} service(s) du pair, gardé(s) en attente de leur \
                 machine, rangé(s)",
                self.adresse, rangement.rejoues
            ));
        }
        for (perdant, gagnant) in rangement.effets.remplaces {
            self.fermetures.renommer(perdant, gagnant);
        }
        Ok(machines.len())
    }

    /// Publie où l'on nous joint — **à chaque ouverture** (`avant` vaut
    /// `None`) : une adresse qui a changé pendant la coupure est dite dès la
    /// reprise, et une publication identique n'écrit rien aux racines ; puis
    /// **à chaque changement** (`avant` est la version déjà publiée), et le
    /// journal le dit. Rend la version publiée.
    ///
    /// **Rien n'est publié tant qu'on ne sait pas** (`--locator auto` sans
    /// adresse candidate) : la racine garde ce qu'elle tenait.
    async fn publier_les_locateurs(
        &self,
        connexion: &mut Connexion,
        avant: Option<u64>,
    ) -> Result<u64, Faute> {
        let (version, liste) = self.locateurs.lire();
        let Some(liste) = liste else {
            return Ok(version);
        };
        let reponse = connexion
            .requete(
                b"PUT",
                b"/v1/federation/locateurs",
                &[(b"content-type", b"application/json")],
                &corps_de_locateurs(&liste),
            )
            .await?;
        match reponse.statut.value() {
            204 => {}
            autre => return Err(Faute::Statut(autre)),
        }
        if avant.is_some() {
            (self.journal)(format!(
                "fédération vers {} : localisateur publié — {} (204)",
                self.adresse,
                liste.join(", ")
            ));
        }
        Ok(version)
    }

    /// Pousse l'état publié, part après part ; rend `(services, vivants)`.
    async fn pousser_l_etat(&self, connexion: &mut Connexion) -> Result<(usize, usize), Faute> {
        let (_, publies) = self.publies.lire();
        let compte = (
            publies.len(),
            publies
                .iter()
                .filter(|service| service.reponse.is_some())
                .count(),
        );
        for corps in corps_d_etat(&publies) {
            let reponse = connexion
                .requete(
                    b"POST",
                    b"/v1/federation/etat",
                    &[(b"content-type", b"application/octet-stream")],
                    &corps,
                )
                .await?;
            match reponse.statut.value() {
                204 => {}
                autre => return Err(Faute::Statut(autre)),
            }
        }
        Ok(compte)
    }
}

#[cfg(test)]
mod essais {
    use super::*;
    use asl_id::Genre;

    fn id(genre: Genre, octet: u8) -> Identifiant {
        Identifiant::depuis_entropie(genre, [octet; 16])
    }

    fn nom(texte: &str) -> NomRange {
        NomRange::nouveau(texte).unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn la_paire_se_dit_au_changement_puis_tous_les_rappels_si_elle_est_mal_reglee() {
        // **DÉCISION 70** : une ligne dès qu'on apprend, puis une par rappel
        // tant que c'est mal réglé ; rien de plus quand tout va bien.
        let (moi, autre, etranger) = (
            id(Genre::Annuaire, 1),
            id(Genre::Annuaire, 2),
            id(Genre::Annuaire, 3),
        );
        let jugee = PaireJugee::avec_rappel(1_000);
        assert_eq!(
            jugee.etat(),
            None,
            "rien tant que les racines n'ont pas parlé"
        );
        assert_eq!(PaireJugee::default().etat(), None);

        // Seul : dit une fois, jamais redit.
        let ligne = jugee
            .constater(moi, None, &[moi], 0)
            .expect("la première fois");
        assert!(
            ligne.starts_with("paire :") && ligne.contains("seul"),
            "{ligne}"
        );
        assert_eq!(jugee.constater(moi, None, &[moi], 5_000), None);
        assert_eq!(jugee.etat(), Some(EtatDePaire::Seul));

        // Un second est accepté, et pas de `--peer` : tout de suite, puis au
        // rappel — pas avant.
        let ligne = jugee
            .constater(moi, None, &[moi, autre], 6_000)
            .expect("un changement se dit");
        assert!(ligne.starts_with("PAIRE MAL RÉGLÉE (sans-peer)"), "{ligne}");
        assert!(ligne.contains(autre.texte().as_str()) && ligne.contains(moi.texte().as_str()));
        assert_eq!(jugee.constater(moi, None, &[moi, autre], 6_500), None);
        let rappel = jugee
            .constater(moi, None, &[moi, autre], 7_000)
            .expect("le rappel");
        assert_eq!(rappel, ligne);
        assert_eq!(jugee.etat(), Some(EtatDePaire::SansPeer));

        // Un `--peer` qui n'est pas l'autre membre.
        let ligne = jugee
            .constater(moi, Some(etranger), &[moi, autre], 7_100)
            .expect("un changement se dit");
        assert!(
            ligne.starts_with("PAIRE MAL RÉGLÉE (peer-inconnu)"),
            "{ligne}"
        );
        assert!(
            ligne.contains(etranger.texte().as_str()) && ligne.contains(autre.texte().as_str())
        );
        // … ou un `--peer` alors qu'on est seul.
        let ligne = jugee
            .constater(moi, Some(etranger), &[moi], 7_200)
            .expect("les membres ont changé");
        assert!(ligne.contains("aucun"), "{ligne}");

        // Réglée : dit une fois.
        let ligne = jugee
            .constater(moi, Some(autre), &[moi, autre], 7_300)
            .expect("un changement se dit");
        assert!(ligne.starts_with("paire réglée"), "{ligne}");
        assert_eq!(
            jugee.constater(moi, Some(autre), &[moi, autre], 99_000),
            None
        );
        assert_eq!(jugee.etat(), Some(EtatDePaire::Reglee));
    }

    #[test]
    fn une_racine_retient_la_paire_de_chaque_membre() {
        let mut etat = EtatFedere::nouveau();
        let (speedy, helium) = (id(Genre::Annuaire, 1), id(Genre::Annuaire, 2));
        assert_eq!(etat.paire_de(speedy), None);
        assert!(etat.noter_une_paire(speedy, EtatDePaire::SansPeer));
        assert!(!etat.noter_une_paire(speedy, EtatDePaire::SansPeer));
        assert!(etat.noter_une_paire(speedy, EtatDePaire::Reglee));
        assert_eq!(etat.paire_de(speedy), Some(EtatDePaire::Reglee));
        assert_eq!(etat.paire_de(helium), None);
    }

    #[test]
    fn vivant_si_un_membre_le_dit_et_rien_quand_tous_se_taisent() {
        let mut etat = EtatFedere::nouveau();
        let machine = id(Genre::Machine, 1);
        let (a, b) = (id(Genre::Annuaire, 1), id(Genre::Annuaire, 2));
        let vivante = EntreeDEtat {
            service: id(Genre::Service, 1),
            machine,
            nom: nom("depot"),
            reponse: Some(b"{\"a\":1}"),
        };
        let partie = EntreeDEtat {
            service: id(Genre::Service, 2),
            reponse: None,
            ..vivante
        };
        etat.ranger(a, &vivante, 100);
        etat.ranger(b, &partie, 200);
        // B est plus récent, mais A le dit vivant : il l'est.
        let lue = etat.lire(machine, b"depot", 250, 1_000);
        assert_eq!(
            lue,
            Some(LueFederee {
                service: vivante.service,
                reponse: Some(b"{\"a\":1}".to_vec()),
                membre: a,
            })
        );
        // Le rapport de A a vieilli : seul B parle, et il le dit parti.
        let lue = etat.lire(machine, b"depot", 1_150, 1_000);
        assert_eq!(
            lue,
            Some(LueFederee {
                service: partie.service,
                reponse: None,
                membre: b,
            })
        );
        // Plus personne : rien.
        assert_eq!(etat.lire(machine, b"depot", 5_000, 1_000), None);
        assert_eq!(etat.lire(machine, b"autre", 250, 1_000), None);
        assert_eq!(etat.combien(), 1);
        etat.oublier_les_perimes(5_000, 1_000);
        assert_eq!(etat.combien(), 0);
    }

    #[test]
    fn les_services_d_une_machine_se_lisent_par_nom_et_seulement_les_siens() {
        let mut etat = EtatFedere::nouveau();
        let (machine, autre) = (id(Genre::Machine, 1), id(Genre::Machine, 2));
        let membre = id(Genre::Annuaire, 1);
        let depot = EntreeDEtat {
            service: id(Genre::Service, 1),
            machine,
            nom: nom("depot"),
            reponse: Some(b"1"),
        };
        let archive = EntreeDEtat {
            service: id(Genre::Service, 2),
            nom: nom("archive"),
            reponse: None,
            ..depot
        };
        let ailleurs = EntreeDEtat {
            service: id(Genre::Service, 3),
            machine: autre,
            ..depot
        };
        etat.ranger(membre, &depot, 100);
        etat.ranger(membre, &archive, 100);
        etat.ranger(membre, &ailleurs, 100);
        let lus = etat.services_de(machine, 150, 1_000);
        // Rangés par nom, sans la machine d'à côté.
        assert_eq!(
            lus,
            vec![
                (
                    b"archive".to_vec(),
                    LueFederee {
                        service: archive.service,
                        reponse: None,
                        membre,
                    }
                ),
                (
                    b"depot".to_vec(),
                    LueFederee {
                        service: depot.service,
                        reponse: Some(b"1".to_vec()),
                        membre,
                    }
                ),
            ]
        );
        // Plus personne ne confirme : plus rien.
        assert!(etat.services_de(machine, 5_000, 1_000).is_empty());
    }

    #[test]
    fn une_sonde_de_l_interieur_se_reconnait_a_l_adresse_du_daemon() {
        let adresses = |textes: &[&str]| -> Vec<asl_registre::Adresse> {
            textes
                .iter()
                .map(|texte| {
                    asl_registre::Adresse::nouvelle(texte).unwrap_or_else(|_| unreachable!())
                })
                .collect()
        };
        let ip =
            |texte: &str| -> std::net::IpAddr { texte.parse().unwrap_or_else(|_| unreachable!()) };
        let speedy = adresses(&[
            "[2a01:cb19:d27:2f00:3ac9:86ff:fe47:9d54]:6630",
            "192.0.2.51:6630",
        ]);
        // Le cas du 27/09 : speedy est la machine, et le daemon vient de lui.
        assert!(sonde_de_l_interieur(
            ip("2a01:cb19:d27:2f00:3ac9:86ff:fe47:9d54"),
            &speedy
        ));
        // Une IPv4 habillée en IPv6 par la socket double pile.
        assert!(sonde_de_l_interieur(ip("::ffff:192.0.2.51"), &speedy));
        // Un daemon venu d'ailleurs : une vraie sonde.
        assert!(!sonde_de_l_interieur(ip("2a01:cb19:d27:2f00::77"), &speedy));
        // Un nom ne fait rien conclure (C20), et rien ne se résout.
        assert!(!sonde_de_l_interieur(
            ip("192.0.2.51"),
            &adresses(&["speedy.maison:6630"])
        ));
        assert!(!sonde_de_l_interieur(ip("192.0.2.51"), &[]));
    }

    #[test]
    fn un_rapport_ne_se_dit_qu_a_la_premiere_fois_et_quand_il_change() {
        let mut etat = EtatFedere::nouveau();
        let membre = id(Genre::Annuaire, 1);
        assert!(etat.noter_un_rapport(membre, 1, 1));
        assert!(!etat.noter_un_rapport(membre, 1, 1));
        assert!(etat.noter_un_rapport(membre, 1, 0));
        assert!(etat.noter_un_rapport(id(Genre::Annuaire, 2), 1, 0));
    }

    #[test]
    fn le_rapport_vivant_le_plus_recent_donne_la_reponse() {
        let mut etat = EtatFedere::nouveau();
        let machine = id(Genre::Machine, 1);
        let premiere = EntreeDEtat {
            service: id(Genre::Service, 1),
            machine,
            nom: nom("depot"),
            reponse: Some(b"1"),
        };
        let seconde = EntreeDEtat {
            reponse: Some(b"2"),
            ..premiere
        };
        etat.ranger(id(Genre::Annuaire, 2), &seconde, 300);
        etat.ranger(id(Genre::Annuaire, 1), &premiere, 100);
        let lue = etat.lire(machine, b"depot", 350, 1_000);
        assert_eq!(lue.and_then(|lue| lue.reponse), Some(b"2".to_vec()));
    }

    #[test]
    fn la_publication_compte_ses_changements() {
        let publies = ServicesPublies::nouvelle();
        let service = ServicePublie {
            service: id(Genre::Service, 1),
            machine: id(Genre::Machine, 1),
            nom: nom("depot"),
            reponse: None,
        };
        assert_eq!(publies.version(), 0);
        publies.publier(vec![service.clone()]);
        publies.publier(vec![service.clone()]);
        assert_eq!(publies.lire(), (1, vec![service]));
    }

    #[test]
    fn l_etat_se_coupe_en_parts_d_entrees_entieres() {
        let reponse = vec![b'x'; 3_000];
        let services: Vec<ServicePublie> = (0..5_u8)
            .map(|rang| ServicePublie {
                service: id(Genre::Service, rang),
                machine: id(Genre::Machine, 1),
                nom: nom("depot"),
                reponse: Some(reponse.clone()),
            })
            .collect();
        let corps = corps_d_etat(&services);
        assert!(corps.len() >= 2);
        let mut relues = 0;
        for part in &corps {
            assert!(part.len() <= PART_D_ETAT_OCTETS);
            let mut reste = part.as_slice();
            while !reste.is_empty() {
                let (_, occupe) = EntreeDEtat::lire(reste).unwrap_or_else(|_| unreachable!());
                reste = reste.get(occupe..).unwrap_or_default();
                relues += 1;
            }
        }
        assert_eq!(relues, 5);
        assert!(corps_d_etat(&[]).is_empty());
    }

    #[test]
    fn une_part_de_machines_se_lit_entiere_ou_pas() {
        assert!(lire_une_part_de_machines(&[]).is_ok_and(|machines| machines.is_empty()));
        assert!(lire_une_part_de_machines(&[0; 3]).is_err());
        assert!(lire_une_part_de_machines(&[0; MACHINE_FEDEREE_OCTETS]).is_err());
    }

    #[test]
    fn les_locateurs_publies_comptent_leurs_changements_et_distinguent_l_inconnu() {
        let detectes = LocateursPublies::inconnus();
        assert_eq!(detectes.lire(), (0, None));
        assert!(detectes.publier(vec!["[2001:db8::1]:6630".to_owned()]));
        assert!(!detectes.publier(vec!["[2001:db8::1]:6630".to_owned()]));
        assert!(detectes.publier(vec!["[2001:db8::2]:6630".to_owned()]));
        assert_eq!(
            detectes.lire(),
            (2, Some(vec!["[2001:db8::2]:6630".to_owned()]))
        );
        // Des fixes vides : un retrait, qui se publie — ce n'est pas l'inconnu.
        let fixes = LocateursPublies::fixes(Vec::new());
        assert_eq!(fixes.lire(), (0, Some(Vec::new())));
        assert!(!fixes.publier(Vec::new()));
        assert_eq!(fixes.version(), 0);
    }

    #[test]
    fn le_corps_des_locateurs_les_cite_dans_l_ordre() {
        assert_eq!(corps_de_locateurs(&[]), br#"{"locateurs":[]}"#);
        assert_eq!(
            corps_de_locateurs(&["[2001:db8::7]:6630".to_owned(), "192.0.2.7:6630".to_owned()]),
            br#"{"locateurs":["[2001:db8::7]:6630","192.0.2.7:6630"]}"#
        );
    }
}
