//! Réveiller un appareil : ce que l'annuaire décide avant, pendant et après
//! l'appel sortant, **sans entrée-sortie** (`protocole.md` §2.2, « Les
//! notifications », « La sécurité », « Échec », 2026-09-25).
//!
//! # POURQUOI UNE CRATE, ET À L'ÉTAGE 2
//!
//! C'est la première fois qu'une racine se connecte à une adresse qu'elle n'a
//! pas choisie : une URL qu'un appareil lui a donnée. Les défenses contre la
//! requête détournée (SSRF), l'amplification et le sondage sont des
//! DÉCISIONS — quelle adresse est permise, quelle requête part, ce qu'on lit
//! de la réponse, combien d'envois on s'autorise. Elles se prennent sur des
//! faits qu'on leur donne : une adresse résolue, des octets reçus, l'heure.
//!
//! Les loger dans la boucle les aurait mises hors du régime de couverture au
//! prétexte que le voisin ouvre une socket (C2). Ici, chaque règle est une
//! fonction pure, éprouvée une par une, et fuzzée là où elle lit des octets
//! d'un inconnu. La boucle (`asl-loop-tokio::reveil`) résout, se connecte,
//! chiffre, et ne décide de rien.
//!
//! # CE QUI N'EST PAS ICI
//!
//! La forme du point — `https`, un nom, le port 443 — est à la dépose, dans
//! `asl_api::point`, et l'envoi la relit par la même fonction. Le TLS est
//! celui d'`ams-tls`. La résolution est celle du système.

#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use asl_api::point::UrlDePoussee;
use asl_id::Identifiant;

// ── Les adresses (`protocole.md` §2.2, « La sécurité », 2) ──────────────────

/// Pourquoi une adresse est refusée.
///
/// **Le nom de la règle va au journal d'exploitation**, avec l'appareil et
/// l'hôte : c'est ce qu'un exploitant doit voir en premier (§2.2, « Échec »).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Regle {
    /// `127.0.0.0/8`, `::1`.
    Bouclage,
    /// `0.0.0.0`, `::`.
    NonSpecifiee,
    /// RFC 1918, `fc00::/7`.
    Privee,
    /// `169.254.0.0/16`, `fe80::/10`.
    LienLocal,
    /// L'espace partagé des opérateurs, `100.64.0.0/10` (RFC 6598).
    Partage,
    /// `224.0.0.0/4`, `ff00::/8`.
    Multidiffusion,
    /// `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`,
    /// `3fff::/20`.
    Documentation,
    /// Tout le reste de ce qui n'est pas unicast global : `0.0.0.0/8`,
    /// `192.0.0.0/24`, `198.18.0.0/15`, `240.0.0.0/4` et la diffusion, les
    /// assignations de protocole de l'IETF, et en IPv6 tout ce qui est hors
    /// de `2000::/3`.
    Reservee,
}

impl Regle {
    /// Son nom, tel que le journal le dit.
    #[must_use]
    pub const fn nom(self) -> &'static str {
        match self {
            Self::Bouclage => "bouclage",
            Self::NonSpecifiee => "non spécifiée",
            Self::Privee => "privée",
            Self::LienLocal => "lien local",
            Self::Partage => "espace partagé",
            Self::Multidiffusion => "multidiffusion",
            Self::Documentation => "documentation",
            Self::Reservee => "réservée",
        }
    }
}

/// Cette adresse est-elle une adresse unicast GLOBALE, qu'une racine peut
/// appeler ?
///
/// # LA LISTE EST CELLE DE CE QUI EST REFUSÉ, ET TOUT LE RESTE PASSE
///
/// En IPv4, l'espace public n'a pas de préfixe à lui : on refuse ce que les
/// registres de l'IANA disent non global. En IPv6, c'est l'inverse, et plus
/// sûr : **seul `2000::/3` est unicast global**, et tout ce qui est dehors
/// est refusé d'emblée — sauf les deux formes qui portent une IPv4, jugées
/// comme elle.
///
/// # UNE IPv4 ENFOUIE SE JUGE COMME L'IPv4 QU'ELLE PORTE
///
/// `::ffff:127.0.0.1` est `127.0.0.1` pour la pile qui s'y connecte ;
/// `64:ff9b::a00:1` est `10.0.0.1` derrière une passerelle NAT64 ;
/// `2002:a00:1::` est le relais 6to4 de `10.0.0.1` ; une adresse Teredo porte
/// son serveur en clair et son client inversé. Les juger comme des IPv6
/// ordinaires laisserait passer, sous un habit neuf, tout ce que les règles
/// IPv4 refusent.
///
/// # Errors
///
/// La [`Regle`] qui la refuse.
pub fn juger(adresse: IpAddr) -> Result<(), Regle> {
    match adresse {
        IpAddr::V4(v4) => juger_v4(v4),
        IpAddr::V6(v6) => juger_v6(v6),
    }
}

/// Le jugement d'une IPv4.
fn juger_v4(adresse: Ipv4Addr) -> Result<(), Regle> {
    let [a, b, c, _] = adresse.octets();
    let regle = match (a, b, c) {
        _ if adresse.is_unspecified() => Regle::NonSpecifiee,
        (0, _, _) | (192, 0, 0) | (198, 18 | 19, _) | (192, 88, 99) => Regle::Reservee,
        (10, _, _) | (172, 16..=31, _) | (192, 168, _) => Regle::Privee,
        (100, 64..=127, _) => Regle::Partage,
        (127, _, _) => Regle::Bouclage,
        (169, 254, _) => Regle::LienLocal,
        (192, 0, 2) | (198, 51, 100) | (203, 0, 113) => Regle::Documentation,
        (224..=239, _, _) => Regle::Multidiffusion,
        (240..=255, _, _) => Regle::Reservee,
        _ => return Ok(()),
    };
    Err(regle)
}

/// Le jugement d'une IPv6.
fn juger_v6(adresse: Ipv6Addr) -> Result<(), Regle> {
    let [s0, s1, s2, s3, s4, s5, ..] = adresse.segments();
    // Les trois places où une IPv4 se loge : les octets 2 à 5 (6to4), 4 à 7
    // (le serveur Teredo), et les quatre derniers (le reste).
    let [_, _, a, b, c, d, e, f, _, _, _, _, w, x, y, z] = adresse.octets();
    let en_6to4 = Ipv4Addr::new(a, b, c, d);
    let serveur_teredo = Ipv4Addr::new(c, d, e, f);
    let en_queue = Ipv4Addr::new(w, x, y, z);
    if adresse.is_unspecified() {
        return Err(Regle::NonSpecifiee);
    }
    if adresse.is_loopback() {
        return Err(Regle::Bouclage);
    }
    // `::ffff:0:0/96` et `64:ff9b::/96` : l'IPv4 est dans les quatre derniers
    // octets.
    if (s0 == 0 && s1 == 0 && s2 == 0 && s3 == 0 && s4 == 0 && s5 == 0xFFFF)
        || (s0 == 0x64 && s1 == 0xFF9B && s2 == 0 && s3 == 0 && s4 == 0 && s5 == 0)
    {
        return juger_v4(en_queue);
    }
    if s0 >= 0xFF00 {
        return Err(Regle::Multidiffusion);
    }
    if s0 & 0xFFC0 == 0xFE80 {
        return Err(Regle::LienLocal);
    }
    if s0 & 0xFE00 == 0xFC00 {
        return Err(Regle::Privee);
    }
    // **HORS DE `2000::/3`, RIEN N'EST UNICAST GLOBAL** — `64:ff9b:1::/48`
    // (NAT64 local), `100::/64`, `fec0::/10` et le reste des réservés.
    if s0 & 0xE000 != 0x2000 {
        return Err(Regle::Reservee);
    }
    // 6to4 : l'IPv4 est dans les octets 2 à 5.
    if s0 == 0x2002 {
        return juger_v4(en_6to4);
    }
    // Teredo, `2001::/32` : le serveur en clair aux octets 4 à 7, le client
    // inversé aux quatre derniers. Les deux doivent être publics.
    if s0 == 0x2001 && s1 == 0 {
        juger_v4(serveur_teredo)?;
        return juger_v4(Ipv4Addr::from_bits(!en_queue.to_bits()));
    }
    if (s0 == 0x2001 && s1 == 0x0DB8) || (s0 == 0x3FFF && s1 & 0xF000 == 0) {
        return Err(Regle::Documentation);
    }
    // Le reste de `2001::/23` : les assignations de protocole de l'IETF.
    if s0 == 0x2001 && s1 < 0x0200 {
        return Err(Regle::Reservee);
    }
    Ok(())
}

/// Juge TOUTES les adresses qu'un nom a rendues.
///
/// # UNE SEULE MAUVAISE, ET LE NOM EST HOSTILE
///
/// On ne se rabat pas sur une autre : un nom qui rend une adresse publique et
/// une adresse interne est un nom qu'on a fabriqué pour que l'une des deux
/// passe — et c'est la pile, pas nous, qui choisirait laquelle on appelle.
/// **Aucune adresse** n'est pas un refus des règles : c'est un nom qui ne se
/// résout pas, et l'envoi est abandonné.
///
/// # Errors
///
/// La première adresse refusée, et sa règle.
pub fn juger_toutes(adresses: &[IpAddr]) -> Result<(), (IpAddr, Regle)> {
    for adresse in adresses {
        juger(*adresse).map_err(|regle| (*adresse, regle))?;
    }
    Ok(())
}

// ── La requête (`protocole.md` §2.2, « Le client sortant ») ─────────────────

/// Le délai de vie qu'on demande au serveur de poussée, en secondes : un
/// jour. Un appareil éteint plus longtemps relira à l'ouverture.
pub const TTL_SECONDES: u32 = 86_400;

/// La requête qui réveille, entière.
///
/// # RIEN À CHOISIR POUR L'ATTAQUANT, SAUF L'URL
///
/// La méthode, les en-têtes et le corps — VIDE — sont fixes. L'URL a déjà
/// passé [`UrlDePoussee::analyser`] : de l'ASCII graphique, sans espace ni
/// retour à la ligne, donc rien qui puisse fermer la ligne de requête ou
/// glisser un en-tête. `Topic` fait coalescer chez le serveur de poussée un
/// message neuf avec celui qui attend encore (RFC 8030 §5.4) ; `Connection:
/// close` dit qu'on n'en enverra pas d'autre.
#[must_use]
pub fn requete(point: &UrlDePoussee<'_>) -> Vec<u8> {
    let (devant, cible) = point.cible();
    let mut octets = Vec::new();
    for morceau in [
        "POST ",
        devant,
        cible,
        " HTTP/1.1\r\nHost: ",
        point.hote(),
        "\r\nTTL: 86400\r\nTopic: nouvelles\r\nUrgency: normal\r\nContent-Length: 0\r\n\
         Connection: close\r\n\r\n",
    ] {
        octets.extend_from_slice(morceau.as_bytes());
    }
    octets
}

// ── La réponse : la ligne de statut, et rien d'autre ────────────────────────

/// Ce qu'une ligne de statut peut faire, au plus, avant qu'on renonce.
pub const LIGNE_DE_STATUT_MAX: usize = 1024;

/// Ce que les octets reçus disent, jusqu'ici.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Statut {
    /// La ligne n'est pas encore entière : lire encore.
    Incomplet,
    /// Le code de statut.
    Code(u16),
    /// Ce n'est pas une ligne de statut HTTP/1.1 : on abandonne.
    Illisible,
}

/// Lit la ligne de statut en tête de ces octets.
///
/// **Seule la ligne compte** (§2.2, « La sécurité », 3) : les en-têtes et le
/// corps ne sont pas lus. `HTTP/1.1 ` ou `HTTP/1.0 `, trois chiffres, puis
/// une espace ou la fin de la ligne. Au-delà de [`LIGNE_DE_STATUT_MAX`] sans
/// fin de ligne, c'est illisible — un serveur qui fait attendre une ligne sans
/// fin ne la verra pas lue.
#[must_use]
pub fn lire_le_statut(octets: &[u8]) -> Statut {
    let Some(fin) = octets.windows(2).position(|paire| paire == b"\r\n") else {
        return if octets.len() > LIGNE_DE_STATUT_MAX {
            Statut::Illisible
        } else {
            Statut::Incomplet
        };
    };
    let ligne = octets.get(..fin).unwrap_or_default();
    let Some(reste) = ligne
        .strip_prefix(b"HTTP/1.1 ")
        .or_else(|| ligne.strip_prefix(b"HTTP/1.0 "))
    else {
        return Statut::Illisible;
    };
    match reste {
        [c, d, u] | [c, d, u, b' ', ..]
            if c.is_ascii_digit() && d.is_ascii_digit() && u.is_ascii_digit() =>
        {
            Statut::Code(
                u16::from(c.saturating_sub(b'0'))
                    .saturating_mul(100)
                    .saturating_add(u16::from(d.saturating_sub(b'0')).saturating_mul(10))
                    .saturating_add(u16::from(u.saturating_sub(b'0'))),
            )
        }
        _ => Statut::Illisible,
    }
}

/// Ce qu'un envoi a donné (§2.2, « Échec »).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Issue {
    /// `2xx`.
    Reussi,
    /// `404` ou `410` : l'abonnement est mort. On n'y envoie plus rien tant
    /// que l'appareil n'a pas déposé un point neuf.
    Mort,
    /// Tout le reste — `429`, `5xx`, une redirection, qui est un échec et
    /// jamais un chemin : abandonné, et le prochain événement réessaiera.
    Abandonne,
}

/// L'issue de ce code.
#[must_use]
pub const fn issue(code: u16) -> Issue {
    match code {
        200..=299 => Issue::Reussi,
        404 | 410 => Issue::Mort,
        _ => Issue::Abandonne,
    }
}

// ── Les freins (`protocole.md` §2.2, « La sécurité », 5) ────────────────────

/// Une minute, en millisecondes : la fenêtre des deux limites de débit.
pub const MINUTE_MS: u64 = 60_000;

/// Combien d'envois un même hôte reçoit par minute, au plus.
pub const PAR_HOTE_ET_PAR_MINUTE: usize = 60;

/// Combien d'envois sont en vol, au plus.
pub const EN_VOL_MAX: usize = 8;

/// Pourquoi un envoi ne part pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frein {
    /// Cet appareil a déjà été réveillé depuis moins d'une minute : dix
    /// autorisations dans la minute font un seul réveil.
    Appareil,
    /// Cet hôte a reçu soixante envois dans la minute.
    Hote,
    /// Huit envois sont déjà en vol.
    EnVol,
    /// Ce point a répondu `404` ou `410`, et l'appareil n'en a pas déposé
    /// d'autre.
    Mort,
}

/// Ce qu'une racine retient de ses envois : des freins, pas des faits.
///
/// # EN MÉMOIRE, ET JAMAIS RÉPLIQUÉ (décision 27)
///
/// Rien de cela n'est rangé ni ne passe à l'autre racine. Répliquer une mort
/// ferait croire à une racine ce que l'autre a vu de SON réseau ; répliquer
/// une limite en ferait un amplificateur. Un redémarrage les oublie, et c'est
/// voulu : ce ne sont pas des états du produit, ce sont des gardes du
/// moment.
///
/// **L'heure est donnée**, en millisecondes : cette crate ne la lit pas.
#[derive(Debug, Default)]
pub struct Freins {
    /// Par appareil, quand il a été réveillé pour la dernière fois.
    appareils: BTreeMap<Identifiant, u64>,
    /// Par hôte, les instants des envois de la dernière minute.
    hotes: BTreeMap<String, Vec<u64>>,
    /// Les points morts : par appareil, l'identité du point qui a répondu
    /// `404` ou `410` — son estampille, que l'appelant donne telle quelle.
    morts: BTreeMap<Identifiant, (u64, Identifiant)>,
    /// Combien d'envois sont en vol.
    en_vol: usize,
}

impl Freins {
    /// Aucun envoi connu.
    #[must_use]
    pub fn neufs() -> Self {
        Self::default()
    }

    /// Cet envoi peut-il partir ? S'il le peut, il est COMPTÉ — l'appareil
    /// marqué, l'hôte chargé, un envoi en vol de plus ; [`Freins::rendre`]
    /// le retire du vol quand il est fini.
    ///
    /// `point` est l'identité du point rangé (son estampille, en compteur et
    /// racine) : un point mort ne l'est que tant que l'appareil n'en a pas
    /// déposé un autre.
    ///
    /// **Rien n'est compté sur un refus** : un envoi freiné n'a rien coûté,
    /// et ne doit pas freiner le suivant.
    ///
    /// # Errors
    ///
    /// Le [`Frein`] qui retient l'envoi.
    pub fn admettre(
        &mut self,
        appareil: Identifiant,
        point: (u64, Identifiant),
        hote: &str,
        maintenant: u64,
    ) -> Result<(), Frein> {
        // Ce qui est sorti de la fenêtre s'oublie : la mémoire reste bornée
        // par ce qui a été envoyé dans la minute. **Compté depuis l'envoi**,
        // et non depuis « il y a une minute » : une horloge qui démarre à
        // zéro ne doit pas oublier ce qu'elle a fait à l'instant zéro.
        let dans_la_minute = |quand: u64| maintenant.saturating_sub(quand) < MINUTE_MS;
        self.appareils.retain(|_, quand| dans_la_minute(*quand));
        self.hotes.retain(|_, envois| {
            envois.retain(|quand| dans_la_minute(*quand));
            !envois.is_empty()
        });
        match self.morts.get(&appareil) {
            Some(mort) if *mort == point => return Err(Frein::Mort),
            // Un point neuf ressuscite l'appareil.
            Some(_) => {
                self.morts.remove(&appareil);
            }
            None => {}
        }
        if self.appareils.contains_key(&appareil) {
            return Err(Frein::Appareil);
        }
        let hote = hote.to_ascii_lowercase();
        if self
            .hotes
            .get(&hote)
            .is_some_and(|envois| envois.len() >= PAR_HOTE_ET_PAR_MINUTE)
        {
            return Err(Frein::Hote);
        }
        if self.en_vol >= EN_VOL_MAX {
            return Err(Frein::EnVol);
        }
        self.appareils.insert(appareil, maintenant);
        self.hotes.entry(hote).or_default().push(maintenant);
        self.en_vol = self.en_vol.saturating_add(1);
        Ok(())
    }

    /// Un envoi admis est fini, quelle qu'en soit l'issue.
    pub const fn rendre(&mut self) {
        self.en_vol = self.en_vol.saturating_sub(1);
    }

    /// Ce point a répondu `404` ou `410`.
    pub fn marquer_mort(&mut self, appareil: Identifiant, point: (u64, Identifiant)) {
        self.morts.insert(appareil, point);
    }

    /// Combien d'envois sont en vol.
    #[must_use]
    pub const fn en_vol(&self) -> usize {
        self.en_vol
    }
}
