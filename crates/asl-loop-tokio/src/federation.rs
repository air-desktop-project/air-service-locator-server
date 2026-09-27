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

use asl_cle::CleSecrete;
use asl_id::Identifiant;
use asl_registre::{EntreeDEtat, MACHINE_FEDEREE_OCTETS, MachineFederee, NomRange};
use asl_store::Entrepot;

use crate::quic::maintenant;
use crate::tireur::{Connexion, Faute, Reprise, nom_tls, resoudre};

/// Combien de temps une racine croit un rapport qu'aucun membre ne
/// confirme : trente secondes (décidé le 2026-09-27, Thierry).
pub const EXPIRATION_US: u64 = 30 * 1_000_000;

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
}

/// Ce qu'une racine rend d'un service fédéré.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LueFederee {
    /// Le service.
    pub service: Identifiant,
    /// Sa réponse d'annonce, s'il est vivant.
    pub reponse: Option<Vec<u8>>,
}

/// La clé d'un service : sa machine, puis son nom.
fn clef_de_service(machine: Identifiant, nom: &[u8]) -> Vec<u8> {
    let mut clef = Vec::with_capacity(17_usize.saturating_add(nom.len()));
    clef.push(machine.genre().prefixe());
    clef.extend_from_slice(machine.octets());
    clef.extend_from_slice(nom);
    clef
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
        let tenus = self.tenus.get(&clef_de_service(machine, nom))?;
        let frais = tenus
            .values()
            .filter(|tenue| tenue.recu_a.saturating_add(expiration) >= maintenant);
        let mut plus_recent: Option<&Tenue> = None;
        let mut vivant: Option<&Tenue> = None;
        for tenue in frais {
            if plus_recent.is_none_or(|avant| tenue.recu_a > avant.recu_a) {
                plus_recent = Some(tenue);
            }
            if tenue.reponse.is_some() && vivant.is_none_or(|avant| tenue.recu_a > avant.recu_a) {
                vivant = Some(tenue);
            }
        }
        vivant.or(plus_recent).map(|tenue| LueFederee {
            service: tenue.service,
            reponse: tenue.reponse.clone(),
        })
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

/// La connexion d'un annuaire local vers UNE racine, et ce qu'elle porte.
///
/// **Elle possède ce qu'elle tient**, comme [`crate::tireur::Tireur`] : la
/// tâche vit aussi longtemps que le serveur.
pub struct Federateur {
    /// Ce qui se souvient — là où les machines reçues se rangent.
    pub entrepot: Arc<Entrepot>,
    /// La racine — `hôte:port`.
    pub adresse: String,
    /// Les certificats d'autorité, en PEM, qui valident la racine.
    pub racines_pem: Vec<u8>,
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
        let mut connexion = Connexion::ouvrir(
            cible,
            &nom_tls(&self.adresse),
            &self.racines_pem,
            self.idle_us,
        )
        .await?;
        connexion.maintenir(self.keepalive_us);
        // **LA MÊME PREUVE QU'UNE RACINE** — genre `n`, notre clé
        // d'identité : c'est la racine qui sait, de ses inscriptions, que
        // cette clé est celle d'un annuaire local accepté.
        connexion.prouver_notre_racine(&self.identite).await?;
        (self.journal)(format!(
            "fédération vers {} ouverte : clé prouvée",
            self.adresse
        ));

        let cadence_us = self.cadence_ms.saturating_mul(1_000);
        let mut prochaine = 0_u64;
        let mut version_poussee = None;
        loop {
            let maintenant = maintenant();
            let version = self.publies.version();
            if maintenant >= prochaine {
                self.tirer_les_machines(&mut connexion).await?;
                self.pousser_l_etat(&mut connexion).await?;
                version_poussee = Some(version);
                prochaine = maintenant.saturating_add(cadence_us);
            } else if version_poussee != Some(version) {
                // **UN CHANGEMENT PART TOUT DE SUITE** : un daemon qui arrive ou
                // s'en va se voit aux racines dans le tour, pas à la cadence.
                self.pousser_l_etat(&mut connexion).await?;
                version_poussee = Some(version);
            }
            connexion.entretenir(200).await?;
            if !connexion.vivante() {
                return Ok(());
            }
        }
    }

    /// Tire toutes les parts des machines de nos domaines, et les range.
    async fn tirer_les_machines(&self, connexion: &mut Connexion) -> Result<(), Faute> {
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
        let sorties = self
            .entrepot
            .ranger_les_machines_federees(&machines)
            .map_err(Faute::Entrepot)?;
        for sortie in sorties {
            self.fermetures.fermer(sortie);
        }
        Ok(())
    }

    /// Pousse l'état publié, part après part.
    async fn pousser_l_etat(&self, connexion: &mut Connexion) -> Result<(), Faute> {
        let (_, publies) = self.publies.lire();
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
        Ok(())
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
            })
        );
        // Le rapport de A a vieilli : seul B parle, et il le dit parti.
        let lue = etat.lire(machine, b"depot", 1_150, 1_000);
        assert_eq!(
            lue,
            Some(LueFederee {
                service: partie.service,
                reponse: None,
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
}
