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

/// L'étiquette que les deux camps donnent à leur exportateur TLS.
///
/// # ELLE EST ÉCRITE ICI, ET UNE SEULE FOIS
///
/// C'est la même raison qui mettait [`message_a_signer`] dans cette crate :
/// **les deux côtés doivent dériver identiquement.** Le serveur l'exporte de sa
/// connexion, le daemon de la sienne ; si les étiquettes divergeaient d'un
/// octet, aucune signature ne vérifierait plus, et la panne serait
/// indiscernable d'une clé fausse.
///
/// Elle porte la version du protocole, pour la raison de [`DOMAINE`] : une
/// liaison dérivée pour `v1` ne doit jamais valoir pour `v2`.
///
/// **Aucun contexte ne l'accompagne** (`None`). RFC 8446 §7.5 en admet un ; il
/// servirait à séparer deux usages sur une même connexion, et il n'y en a qu'un.
/// En passer un vide ne serait pas la même chose que n'en passer aucun — c'est
/// une différence que les deux camps devraient tenir d'accord pour rien.
pub const ETIQUETTE_LIAISON: &[u8] = b"air-service-locator/v1/liaison-de-canal";

/// La taille d'une clé publique Ed25519.
pub const CLE_PUBLIQUE_OCTETS: usize = 32;

/// La taille d'une clé secrète Ed25519.
pub const CLE_SECRETE_OCTETS: usize = 32;

/// La taille d'une signature Ed25519.
pub const SIGNATURE_OCTETS: usize = 64;

/// La taille du message signé.
pub const MESSAGE_OCTETS: usize = DOMAINE.len() + 1 + 16 + DEFI_OCTETS + LIAISON_OCTETS;

/// Le séparateur de domaine d'une **preuve de possession**.
///
/// # POURQUOI UN SECOND DOMAINE PLUTÔT QU'UN CHAMP DE PLUS
///
/// Les deux messages ne prouvent pas la même chose. [`DOMAINE`] prouve « je suis
/// CETTE machine, déjà connue de toi » ; celui-ci prouve « je détiens la clé que
/// je te présente », et il sert précisément là où l'identifiant N'EXISTE PAS
/// ENCORE.
///
/// **Les séparer empêche qu'une signature de l'un vaille pour l'autre.** Sans
/// cela, une preuve d'authentification captée sur une connexion vaudrait preuve
/// de possession sur une autre — et il suffirait d'écouter une machine
/// s'authentifier pour enrôler sa clé ailleurs.
pub const DOMAINE_POSSESSION: &[u8] = b"air-service-locator/v1/possession-de-cle\x00";

/// La taille du message d'une preuve de possession.
pub const MESSAGE_POSSESSION_OCTETS: usize =
    DOMAINE_POSSESSION.len() + CLE_PUBLIQUE_OCTETS + DEFI_OCTETS + LIAISON_OCTETS;

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
/// # C'EST UN *EXPORTER* TLS, ET LA DETTE QUI ÉTAIT ÉCRITE ICI EST PAYÉE
///
/// Ce paragraphe disait : « Le plus fort est un *exporter* TLS (RFC 8446 §7.5).
/// C'est ce que ce type devrait porter, et ce qu'il portera. Ce qu'il porte
/// aujourd'hui est l'empreinte du certificat du serveur, et il faut dire
/// pourquoi et ce que cela coûte. La pile QUIC que ce produit emprunte n'expose
/// aucun exporteur. »
///
/// **Elle en expose un.** `ams_quic_tls::Connection::export` a été écrit dans
/// `air-mail-server`, sous son propre régime de couverture, et cette crate n'en
/// garde plus que l'ÉTIQUETTE — voir [`ETIQUETTE_LIAISON`].
///
/// # CE QUE LE CHANGEMENT ACHÈTE, ET QUI N'ÉTAIT PAS ACHETÉ
///
/// L'empreinte liait à une IDENTITÉ ; l'exporteur lie à une SESSION. Les deux
/// réserves qui étaient écrites ici tombent ensemble :
///
///   1. **Deux serveurs qui partagent un certificat ne partagent plus de
///      liaison.** Un répartiteur de charge, ou deux annuaires servant le même
///      certificat, ne se confondent plus. Ce n'était pas notre cas, et cela
///      cessait de l'être sans qu'on y pense.
///   2. **Deux connexions au même serveur ne partagent plus de liaison.**
///      C'était le DÉFI qui les séparait — et le défi et la liaison se tenaient
///      donc l'un l'autre, là où un exporteur suffit seul.
///
/// **Le défi reste, et son « à usage unique » aussi.** Il ne porte plus la
/// séparation des connexions, mais il porte toujours la FRAÎCHEUR : sans lui,
/// une signature valide pour cette connexion vaudrait indéfiniment sur elle.
///
/// # ET LE RELAIS EST FERMÉ
///
/// C'est ce que C14 nommait sous « ce que l'assemblage ne garantit pas encore ».
/// Un intermédiaire qui transmettrait le défi du vrai annuaire à la machine,
/// puis la signature en retour, s'authentifierait comme elle. Pour parler TLS
/// avec la machine, il doit mener SA propre poignée de main — et la valeur qu'il
/// en dérive n'est pas celle que le vrai annuaire dérive de la sienne. La
/// signature ne vérifie plus.
///
/// Il n'y a plus d'intermédiaire que celui qui détient la clé privée du
/// serveur — mais celui-là **est** le serveur, et aucune liaison de canal n'y
/// peut rien.
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

/// Compose le message que signe celui qui prouve détenir une clé.
///
/// # C'EST LA CLÉ QUI EST SIGNÉE, ET NON UN IDENTIFIANT
///
/// [`message_a_signer`] nomme la machine ; celui-ci ne le peut pas, parce qu'il
/// sert **avant qu'il y ait un nom** :
///
/// — à la création d'un compte, l'identifiant de l'appareil est tiré par
///   l'annuaire, donc l'appareil ne peut pas le signer ;
/// — à l'enrôlement d'une machine, la clé est justement ce qu'on vient lier.
///
/// Signer la clé qu'on présente prouve exactement ce qu'il faut prouver : que
/// celui qui parle en détient la partie privée. **Le défi et la liaison de canal
/// y sont, pour les mêmes raisons qu'ailleurs** — sans le premier la preuve se
/// rejoue, sans la seconde elle se relaie.
#[must_use]
pub fn message_de_possession(
    cle: &ClePublique,
    defi: &Defi,
    liaison: &LiaisonDeCanal,
) -> [u8; MESSAGE_POSSESSION_OCTETS] {
    // Même garde qu'au-dessus, et pour la même raison : un champ qui change de
    // taille sans que la constante suive doit casser la COMPILATION.
    const _: () = assert!(
        MESSAGE_POSSESSION_OCTETS
            == DOMAINE_POSSESSION.len() + CLE_PUBLIQUE_OCTETS + DEFI_OCTETS + LIAISON_OCTETS,
        "la taille du message de possession ne correspond plus à la somme de ses champs"
    );

    let publique = cle.octets();
    let source = DOMAINE_POSSESSION
        .iter()
        .chain(publique.iter())
        .chain(defi.octets().iter())
        .chain(liaison.octets().iter());

    let mut message = [0_u8; MESSAGE_POSSESSION_OCTETS];
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
    /// Un identifiant de machine ou d'appareil était attendu.
    ///
    /// **Ce sont les deux seuls genres qui SIGNENT.** Un compte ne signe pas —
    /// il n'a pas de clé, il n'est qu'un jeu d'appareils enrôlés ; un service
    /// n'en a pas davantage — c'est la machine qui le porte qui signe pour lui.
    PasUnPair {
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
        pair: Identifiant,
        defi: &Defi,
        liaison: &LiaisonDeCanal,
        signature: &Signature,
    ) -> bool {
        // Un identifiant qui n'est ni une machine ni un appareil ne peut pas
        // vérifier : le genre entre dans le message signé, donc il ne s'agirait
        // pas du même message. On le refuse ici quand même, pour que la faute se
        // voie.
        if !est_un_pair(pair.genre()) {
            return false;
        }
        let message = message_a_signer(pair, defi, liaison);
        let signature = SignatureDalek::from_bytes(signature.octets());
        self.0.verify(&message, &signature).is_ok()
    }

    /// Cette signature prouve-t-elle que celui qui parle détient CETTE clé ?
    ///
    /// C'est [`message_de_possession`] qui est vérifié, et son en-tête dit
    /// quand cette preuve-ci sert plutôt que l'autre.
    ///
    /// **Aucun genre n'est exigé, parce qu'aucun identifiant n'entre dans le
    /// message.** C'est tout l'objet : prouver la détention d'une clé qui n'a
    /// pas encore de nom.
    #[must_use]
    pub fn prouve_sa_possession(
        &self,
        defi: &Defi,
        liaison: &LiaisonDeCanal,
        signature: &Signature,
    ) -> bool {
        let message = message_de_possession(self, defi, liaison);
        let signature = SignatureDalek::from_bytes(signature.octets());
        self.0.verify(&message, &signature).is_ok()
    }
}

/// Ce genre signe-t-il ?
const fn est_un_pair(genre: Genre) -> bool {
    matches!(genre, Genre::Machine | Genre::Appareil)
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
    /// [`Faute::PasUnPair`]. **Signer avec un identifiant d'un autre genre est
    /// refusé ici**, et non plus tard : la signature serait valide, mais pour un
    /// message que l'annuaire ne composera jamais — et le daemon chercherait la
    /// panne du côté de sa clé.
    pub fn signer(
        &self,
        pair: Identifiant,
        defi: &Defi,
        liaison: &LiaisonDeCanal,
    ) -> Result<Signature, Faute> {
        if !est_un_pair(pair.genre()) {
            return Err(Faute::PasUnPair {
                obtenu: pair.genre(),
            });
        }
        let message = message_a_signer(pair, defi, liaison);
        Ok(Signature(self.0.sign(&message).to_bytes()))
    }

    /// Signe la preuve qu'on détient cette clé — celle de [`message_de_possession`].
    ///
    /// **Elle ne peut pas échouer**, et c'est la conséquence directe de ce qui
    /// est signé : il n'y a pas d'identifiant dans ce message, donc pas de genre
    /// à refuser.
    #[must_use]
    pub fn prouver_la_possession(&self, defi: &Defi, liaison: &LiaisonDeCanal) -> Signature {
        let message = message_de_possession(&self.publique(), defi, liaison);
        Signature(self.0.sign(&message).to_bytes())
    }
}
