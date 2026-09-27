//! Qui l'on croit, sans résoudre un nom (`protocole.md` §0, `annuaires.md`
//! §2 quater, décisions 53–56 et 59, C20).
//!
//! # POURQUOI UNE CRATE, ET À L'ÉTAGE 2
//!
//! La règle « l'identité est la clé » se prend des deux côtés du fil : le
//! serveur la tient pour croire un pair (réplication, fédération), le client
//! pour croire une racine ou un annuaire local. Jusqu'à la 0.30.0, elle vivait
//! dans `asl-loop-tokio` — un étage 3, qui embarquerait sa boucle et son
//! entrepôt dans un client —, et le client a dû la **réécrire** (client
//! 0.17.0 : `asl-client::racines`, `asl-client-tokio::confiance`), la liste
//! embarquée comprise. Deux copies d'une ancre de confiance, c'est deux
//! endroits où une clé peut être recopiée de travers.
//!
//! Ici : **la liste embarquée**, **la règle** (un seul maillon, dont la clé se
//! déduit en un identifiant attendu), et **la vérification d'une liste**
//! servie par `GET /v1/racines`. Des fonctions pures sur des octets, 100 %
//! couvertes (C2), fuzzées là où elles lisent un inconnu (C3). Le client les
//! tire comme il tire `asl-cle` et `asl-api`.
//!
//! # CE QUI N'EST PAS ICI
//!
//! `rustls` : la preuve de possession — la signature de `CertificateVerify`
//! contre la clé qu'on vient d'accepter — reste dans l'étage 3 de chaque
//! côté, qui branche son vérificateur sur cette règle. Aucune résolution de
//! nom, aucune socket, aucune horloge.

#![no_std]

use asl_api::annuaire::ListeDeRacines;
use asl_cle::{CLE_PUBLIQUE_OCTETS, ClePublique, cle_du_certificat, identifiant_de_racine};
use asl_id::{Genre, Identifiant};

// ── Les racines embarquées (`annuaires.md` §2, décision 56) ─────────────────

/// Une racine, telle que le logiciel la connaît avant tout contact.
///
/// **CE QUI EST ÉPINGLÉ, C'EST LA CLÉ** : l'identifiant s'en déduit, et les
/// locateurs ne disent que où la joindre — des adresses d'abord (C20 : aucun
/// résolveur requis), des noms ensuite, comme commodités.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RacineEmbarquee {
    /// Son identifiant, qui se déduit de la clé.
    pub identifiant: &'static str,
    /// Sa clé d'identité Ed25519.
    pub cle: [u8; CLE_PUBLIQUE_OCTETS],
    /// Où la joindre : adresses d'abord, noms ensuite.
    pub locateurs: &'static [&'static str],
}

impl RacineEmbarquee {
    /// Sa clé, en point. `None` seulement pour une clé recopiée de travers —
    /// un essai tient que ce n'est le cas d'aucune.
    #[must_use]
    pub fn cle_publique(&self) -> Option<ClePublique> {
        ClePublique::depuis_octets(self.cle).ok()
    }

    /// Son identifiant, lu. `None` pour un texte qui n'en est pas un.
    #[must_use]
    pub fn identite(&self) -> Option<Identifiant> {
        Identifiant::analyser_genre(Genre::Annuaire, self.identifiant).ok()
    }

    /// Ce locateur la désigne-t-il ? L'un des siens, ou l'alias commun.
    ///
    /// **La comparaison est textuelle, sans casse** : un locateur est ce que
    /// l'exploitant a écrit, et `[2001:41d0:20a:900::1dd4]:6630` ou
    /// `nitrogen.air-desktop.org:6630` désignent la même racine parce que la
    /// liste le dit — pas parce qu'un résolveur l'aurait dit.
    #[must_use]
    pub fn designee_par(&self, locateur: &str) -> bool {
        locateur.eq_ignore_ascii_case(ALIAS_DES_RACINES)
            || self
                .locateurs
                .iter()
                .any(|connu| connu.eq_ignore_ascii_case(locateur))
    }
}

/// Les deux racines d'air-desktop-project. Les clés ont été relevées sur les
/// bancs le 2026-09-27 (`/etc/asl-server/identite.key.pub`).
pub const RACINES: [RacineEmbarquee; 2] = [
    RacineEmbarquee {
        identifiant: "n-0PWT8HZD80QMSPPDZ5CQXXYHQC",
        cle: [
            0x42, 0x9c, 0x70, 0xc6, 0x36, 0x51, 0xb4, 0xbb, 0x14, 0x3c, 0xac, 0xa6, 0x79, 0x60,
            0xff, 0x70, 0xee, 0xde, 0x5d, 0x8e, 0x41, 0x8a, 0x9d, 0x0b, 0xc2, 0xbe, 0x12, 0xe1,
            0x9a, 0xc6, 0xf5, 0xfd,
        ],
        locateurs: &[
            "[2001:41d0:20a:900::1dd4]:6630",
            "178.32.16.250:6630",
            "nitrogen.air-desktop.org:6630",
        ],
    },
    RacineEmbarquee {
        identifiant: "n-3K3P6H252W8K9370QG1YYTWBWB",
        cle: [
            0x75, 0xa0, 0x31, 0xae, 0x9f, 0xb9, 0xb6, 0x49, 0x36, 0x76, 0x29, 0x83, 0x72, 0x12,
            0x13, 0x22, 0xcc, 0x04, 0x37, 0x9e, 0x3b, 0x70, 0xd8, 0xd5, 0xf0, 0x11, 0xac, 0x61,
            0xf6, 0x8a, 0x8a, 0x8d,
        ],
        locateurs: &[
            "[2001:41d0:20a:900::1d32]:6630",
            "178.32.16.249:6630",
            "argon.air-desktop.org:6630",
        ],
    },
];

/// Le locateur commun aux deux racines — un nom, donc une commodité.
pub const ALIAS_DES_RACINES: &str = "asl-root.air-desktop.org:6630";

/// Les racines embarquées que ce locateur désigne : la sienne, les deux pour
/// l'alias commun, aucune sinon.
pub fn racines_du_locateur(locateur: &str) -> impl Iterator<Item = &'static RacineEmbarquee> {
    RACINES
        .iter()
        .filter(move |racine| racine.designee_par(locateur))
}

// ── La règle « clé = identité » (décisions 53 et 54) ────────────────────────

/// L'identité que porte ce certificat, s'il est un certificat d'identité : un
/// **seul maillon** (`maillons` compte le certificat de tête et ses
/// intermédiaires), dont la clé Ed25519 se déduit en un `n-…`.
///
/// **RIEN D'AUTRE N'EST LU** : ni nom, ni date, ni émetteur (décision 54).
/// Une chaîne de deux n'est pas un certificat d'identité, quelle que soit la
/// clé de sa tête.
#[must_use]
pub fn identite_du_certificat(maillons: usize, certificat: &[u8]) -> Option<Identifiant> {
    if maillons != 1 {
        return None;
    }
    cle_du_certificat(certificat)
        .ok()
        .map(|cle| identifiant_de_racine(&cle))
}

/// Ce certificat est-il celui d'une identité attendue ? Rend laquelle.
///
/// C'est la moitié pure du vérificateur : l'étage 3 y ajoute la preuve de
/// possession (la signature de la poignée de main contre cette même clé).
#[must_use]
pub fn identite_attendue(
    maillons: usize,
    certificat: &[u8],
    attendues: &[Identifiant],
) -> Option<Identifiant> {
    identite_du_certificat(maillons, certificat).filter(|identite| attendues.contains(identite))
}

// ── Une liste servie par `GET /v1/racines` (décision 56) ────────────────────

/// Pourquoi une liste de racines est refusée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FauteDeListe {
    /// Elle ne se lit pas.
    Illisible,
    /// Une clé n'est pas un point Ed25519.
    ClePasUnPoint,
    /// Une clé ne se déduit pas en l'identifiant écrit à côté : la liste ment.
    Mensonge,
}

/// Lit et VÉRIFIE une liste de `GET /v1/racines`, et la rend lue.
///
/// **Une seule racine dont la clé ne donne pas l'identifiant écrit à côté
/// refuse la liste entière** : c'est une liste fausse, et l'on ne trie pas
/// dans une liste fausse. Qui l'a servie a été jugé par la connexion — c'est
/// elle, vérifiée par clé, qui signe.
///
/// # Errors
///
/// [`FauteDeListe`].
pub fn verifier_la_liste(corps: &[u8]) -> Result<ListeDeRacines<'_>, FauteDeListe> {
    let liste = ListeDeRacines::decoder(corps).map_err(|_| FauteDeListe::Illisible)?;
    for lue in liste.racines() {
        let cle = ClePublique::depuis_octets(lue.cle).map_err(|_| FauteDeListe::ClePasUnPoint)?;
        if identifiant_de_racine(&cle) != lue.annuaire {
            return Err(FauteDeListe::Mensonge);
        }
    }
    Ok(liste)
}
