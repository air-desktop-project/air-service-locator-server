//! Les clés Ed25519 des machines, et **ce qu'elles signent**.
//!
//! # CE QUE CETTE CRATE TRANCHE, ET QUI N'ÉTAIT PAS SPÉCIFIÉ
//!
//! `docs/protocole.md` dit qu'une machine détient une paire de clés et que
//! « l'authentification est portée par la connexion ». Trois questions restaient
//! ouvertes ; les voici, et les réponses retenues.
//!
//! ## 1. Où la vérification a-t-elle lieu ?
//!
//! **Dans le protocole applicatif, par un défi–réponse — pas dans TLS.**
//!
//! S'appuyer sur l'authentification cliente de TLS aurait lié une décision de
//! sécurité à ce que la pile QUIC empruntée sait faire aujourd'hui, et l'aurait
//! placée dans une crate qu'on n'écrit pas. Un défi–réponse que nous tenons se
//! vérifie de bout en bout, et il ne dépend d'aucune option de transport.
//!
//! ## 2. Que signe exactement une machine ?
//!
//! **Un message à champs de longueur FIXE**, et c'est ce qui le rend sûr sans
//! aucun préfixe de longueur :
//!
//! | Champ | Octets | Ce qu'il empêche |
//! |---|---|---|
//! | Séparateur de domaine | [`DOMAINE`] | Qu'une signature faite pour autre chose vaille ici |
//! | Genre de l'identifiant | 1 | Qu'un identifiant d'un autre genre passe |
//! | Identifiant de la machine | 16 | Qu'une signature d'une machine vaille pour une autre |
//! | Défi | 32 | Le rejeu |
//! | Liaison de canal | 32 | **Le relais** |
//!
//! **Tous les champs sont de longueur fixe, donc rien ne peut se confondre.**
//! Avec des champs variables il faudrait des préfixes de longueur, et un
//! encodage sans préfixe permettrait de déplacer la frontière entre deux champs
//! — c'est ainsi qu'on fait valoir une signature pour un message qu'on n'a pas
//! écrit.
//!
//! ## 3. Comment le rejeu est-il empêché ?
//!
//! **Par le défi**, que l'annuaire tire au hasard, n'accepte qu'une fois, et ne
//! réemploie jamais.
//!
//! # LA LIAISON DE CANAL, ET CE QU'IL FAUT SAVOIR SI ELLE MANQUE
//!
//! Un défi seul n'arrête pas un RELAIS : un intermédiaire qui transmet le défi
//! du vrai annuaire à la machine, puis la signature en retour, s'authentifie
//! comme elle. Seule une valeur propre à la connexion TLS — un *exporter*
//! (RFC 8446 §7.5) — ferme ce chemin.
//!
//! **Cette crate l'EXIGE en paramètre**, précisément pour qu'on ne puisse pas
//! l'oublier en silence. Mais elle ne peut pas vérifier que ce qu'on lui donne
//! en est un.
//!
//! **Si le transport n'en fournit pas, le relais reste ouvert, et il faut le
//! savoir.** L'écrire ici vaut mieux que de laisser croire à une garantie que
//! l'assemblage n'a pas.
//!
//! # Pourquoi une crate à part
//!
//! `asl-client` en a besoin pour SIGNER, et il ne doit pas embarquer pour autant
//! les décisions d'autorisation de l'annuaire (`asl-auth`) — qui ne le
//! regardent pas. Les deux vivent donc séparément.

#![no_std]

use asl_id::{Genre, Identifiant};
use ed25519_dalek::{
    Signature as SignatureDalek, Signer as _, SigningKey, Verifier as _, VerifyingKey,
};

/// Le séparateur de domaine, en octets.
///
/// **Il change à chaque version du protocole.** Une signature faite pour `v1`
/// ne doit jamais valoir pour `v2` : c'est ce qui empêche qu'un changement de
/// sens d'un champ rende soudain valides des signatures anciennes.
pub const DOMAINE: &[u8] = b"air-service-locator/v1/authentification-machine\x00";

/// La taille d'un défi.
pub const DEFI_OCTETS: usize = 32;

/// La taille d'une liaison de canal.
pub const LIAISON_OCTETS: usize = 32;

/// La taille d'une clé publique Ed25519.
pub const CLE_PUBLIQUE_OCTETS: usize = 32;

/// La taille d'une clé secrète Ed25519.
pub const CLE_SECRETE_OCTETS: usize = 32;

/// La taille d'une signature Ed25519.
pub const SIGNATURE_OCTETS: usize = 64;

/// La taille du message signé.
pub const MESSAGE_OCTETS: usize = DOMAINE.len() + 1 + 16 + DEFI_OCTETS + LIAISON_OCTETS;

// ── Les valeurs ─────────────────────────────────────────────────────────────

/// Un défi, tiré par l'annuaire.
///
/// **Il n'est jamais tiré ici** : cette crate est sans entrée-sortie, et l'aléa
/// vient de l'appelant. Sa qualité est sa responsabilité — un défi prévisible
/// rouvre le rejeu que ce champ existe pour fermer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Defi([u8; DEFI_OCTETS]);

impl Defi {
    /// Depuis trente-deux octets d'aléa.
    #[must_use]
    pub const fn depuis_octets(octets: [u8; DEFI_OCTETS]) -> Self {
        Self(octets)
    }

    /// Les octets.
    #[must_use]
    pub const fn octets(&self) -> &[u8; DEFI_OCTETS] {
        &self.0
    }
}

/// Ce qui lie une signature à SA connexion.
///
/// Doit être un *exporter* TLS de la connexion en cours. Voir l'en-tête du
/// module pour ce qui arrive si le transport n'en fournit pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiaisonDeCanal([u8; LIAISON_OCTETS]);

impl LiaisonDeCanal {
    /// Depuis trente-deux octets d'exporter.
    #[must_use]
    pub const fn depuis_octets(octets: [u8; LIAISON_OCTETS]) -> Self {
        Self(octets)
    }

    /// Les octets.
    #[must_use]
    pub const fn octets(&self) -> &[u8; LIAISON_OCTETS] {
        &self.0
    }
}

/// Une signature Ed25519.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_OCTETS]);

impl Signature {
    /// Depuis soixante-quatre octets.
    ///
    /// **Aucune validation ici**, et c'est voulu : une signature est un
    /// justificatif, pas une valeur. Ce qui compte est qu'elle vérifie, et c'est
    /// [`ClePublique::verifie`] qui le dit.
    #[must_use]
    pub const fn depuis_octets(octets: [u8; SIGNATURE_OCTETS]) -> Self {
        Self(octets)
    }

    /// Les octets.
    #[must_use]
    pub const fn octets(&self) -> &[u8; SIGNATURE_OCTETS] {
        &self.0
    }
}

// ── Le message signé ────────────────────────────────────────────────────────

/// Compose le message qu'une machine signe.
///
/// **Champs de longueur fixe, aucun préfixe de longueur, aucune ambiguïté.**
/// Voir l'en-tête du module.
#[must_use]
pub fn message_a_signer(
    machine: Identifiant,
    defi: &Defi,
    liaison: &LiaisonDeCanal,
) -> [u8; MESSAGE_OCTETS] {
    // **L'ÉCART DE TAILLE EST IMPOSSIBLE, ET C'EST LE COMPILATEUR QUI LE DIT.**
    //
    // Une première version écrivait avec un curseur et un `if let` sur chaque
    // tranche : la branche `else` était inatteignable, puisque la somme des
    // champs vaut exactement `MESSAGE_OCTETS`. Du code mort sur un chemin
    // cryptographique, c'est-à-dire du code que personne n'éprouvera jamais et
    // que tout le monde croira éprouvé.
    //
    // L'assertion ci-dessous fait échouer la COMPILATION si un champ change de
    // taille sans que `MESSAGE_OCTETS` suive. Le `zip` n'a donc plus rien à
    // rattraper.
    const _: () = assert!(
        MESSAGE_OCTETS == DOMAINE.len() + 1 + 16 + DEFI_OCTETS + LIAISON_OCTETS,
        "la taille du message ne correspond plus à la somme de ses champs"
    );

    let genre = [machine.genre().prefixe()];
    let source = DOMAINE
        .iter()
        .chain(genre.iter())
        .chain(machine.octets().iter())
        .chain(defi.octets().iter())
        .chain(liaison.octets().iter());

    let mut message = [0_u8; MESSAGE_OCTETS];
    for (place, octet) in message.iter_mut().zip(source) {
        *place = *octet;
    }
    message
}

// ── Les clés ────────────────────────────────────────────────────────────────

/// Ce qui peut clocher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Faute {
    /// Les octets ne forment pas un point valide de la courbe.
    ClePubliqueInvalide,
    /// Un identifiant de machine était attendu.
    PasUneMachine {
        /// Le genre fourni.
        obtenu: Genre,
    },
}

/// La clé publique d'une machine, telle que l'annuaire la connaît.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClePublique(VerifyingKey);

impl ClePublique {
    /// Lit une clé publique.
    ///
    /// # Erreurs
    ///
    /// [`Faute::ClePubliqueInvalide`] si les octets ne forment pas un point
    /// valide. **C'est une vérification réelle**, pas une formalité : tous les
    /// tableaux de trente-deux octets ne sont pas des clés Ed25519, et en
    /// accepter un ferait échouer toute vérification ultérieure sans qu'on
    /// sache pourquoi.
    pub fn depuis_octets(octets: [u8; CLE_PUBLIQUE_OCTETS]) -> Result<Self, Faute> {
        VerifyingKey::from_bytes(&octets)
            .map(Self)
            .map_err(|_| Faute::ClePubliqueInvalide)
    }

    /// Les octets.
    #[must_use]
    pub fn octets(&self) -> [u8; CLE_PUBLIQUE_OCTETS] {
        self.0.to_bytes()
    }

    /// Cette signature prouve-t-elle que la machine détient sa clé ?
    ///
    /// # CE QUE CETTE FONCTION VÉRIFIE, ET CE QU'ELLE NE VÉRIFIE PAS
    ///
    /// Elle vérifie que la signature porte sur **ce** message : ce domaine,
    /// cette machine, ce défi, cette connexion.
    ///
    /// Elle ne vérifie PAS que le défi est frais ni qu'il n'a pas déjà servi —
    /// c'est un FAIT que l'annuaire établit, et il n'est pas dans la signature.
    /// Une vérification qui rendrait `true` sur un défi rejoué serait
    /// parfaitement correcte, et l'assemblage serait faux : la fraîcheur se
    /// tient là où l'on garde les défis, pas ici.
    #[must_use]
    pub fn verifie(
        &self,
        machine: Identifiant,
        defi: &Defi,
        liaison: &LiaisonDeCanal,
        signature: &Signature,
    ) -> bool {
        // Un identifiant qui n'est pas une machine ne peut pas vérifier : le
        // genre entre dans le message signé, donc il ne s'agirait pas du même
        // message. On le refuse ici quand même, pour que la faute se voie.
        if machine.genre() != Genre::Machine {
            return false;
        }
        let message = message_a_signer(machine, defi, liaison);
        let signature = SignatureDalek::from_bytes(signature.octets());
        self.0.verify(&message, &signature).is_ok()
    }
}

/// La clé secrète d'une machine.
///
/// # L'ANNUAIRE N'EN DÉTIENT JAMAIS
///
/// Elle est générée SUR la machine et n'en sort pas (`docs/modele.md` §2.3).
/// Elle vit dans cette crate parce que `asl-client` en a besoin pour signer, et
/// que le message signé doit être composé au même endroit des deux côtés —
/// deux copies de cette composition finiraient par diverger, et la signature
/// cesserait de vérifier sans que personne comprenne pourquoi.
///
/// `ed25519-dalek` l'efface de la mémoire à sa destruction (feature `zeroize`).
#[derive(Debug)]
pub struct CleSecrete(SigningKey);

impl CleSecrete {
    /// Depuis trente-deux octets d'entropie.
    ///
    /// **L'aléa vient de l'appelant.** Une clé tirée d'un compteur serait
    /// devinable, et toute l'authentification de ce produit repose là-dessus.
    #[must_use]
    pub fn depuis_entropie(entropie: [u8; CLE_SECRETE_OCTETS]) -> Self {
        Self(SigningKey::from_bytes(&entropie))
    }

    /// La clé publique correspondante — celle qu'on confie à l'annuaire.
    #[must_use]
    pub fn publique(&self) -> ClePublique {
        ClePublique(self.0.verifying_key())
    }

    /// Signe le défi de l'annuaire.
    ///
    /// # Erreurs
    ///
    /// [`Faute::PasUneMachine`]. **Signer avec un identifiant d'un autre genre
    /// est refusé ici**, et non plus tard : la signature serait valide, mais
    /// pour un message que l'annuaire ne composera jamais — et le daemon
    /// chercherait la panne du côté de sa clé.
    pub fn signer(
        &self,
        machine: Identifiant,
        defi: &Defi,
        liaison: &LiaisonDeCanal,
    ) -> Result<Signature, Faute> {
        if machine.genre() != Genre::Machine {
            return Err(Faute::PasUneMachine {
                obtenu: machine.genre(),
            });
        }
        let message = message_a_signer(machine, defi, liaison);
        Ok(Signature(self.0.sign(&message).to_bytes()))
    }
}
