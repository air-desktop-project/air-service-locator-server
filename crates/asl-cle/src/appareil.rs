//! Les clés **P-256** des appareils, et ce qu'elles signent.
//!
//! # POURQUOI UNE SECONDE COURBE, ET POURQUOI CELLE-LÀ
//!
//! Les machines signent en Ed25519, et c'est le bon choix pour un daemon sur
//! un Linux : la clé vit dans un fichier, et l'algorithme est le plus simple
//! qui soit à mettre en œuvre sans se tromper.
//!
//! **Un téléphone n'est pas dans ce cas.** `docs/protocole.md` §2.1 veut que
//! sa clé vive dans le matériel sécurisé — Secure Enclave, StrongBox — sous
//! contrôle biométrique. Or **la Secure Enclave ne fait que P-256**, et
//! StrongBox aussi. Une clé Ed25519 ne peut pas y entrer. La v1 disait donc
//! une chose (« dans le matériel ») et n'en permettait qu'une autre (une clé
//! logicielle dans le Keychain, isolée par rien).
//!
//! Les appareils signent donc en **ECDSA sur P-256**, avec SHA-256. Les
//! machines ne changent pas.
//!
//! # LA FORME SUR LE FIL, ET POURQUOI RIEN N'EST EN DER
//!
//! | Quoi | Octets | Forme |
//! |---|---|---|
//! | Clé publique | 33 | SEC1 compressé : `02` ou `03` ‖ x |
//! | Signature | 64 | `r ‖ s`, chacun sur trente-deux octets, gros-boutien |
//!
//! Une signature ECDSA s'écrit d'ordinaire en DER — `SEQUENCE { INTEGER r,
//! INTEGER s }` —, et sa longueur varie de septante à septante-deux octets
//! selon les zéros de tête. **Ce dépôt refuse les longueurs qui viennent du
//! réseau** (`protocole.md` §2.1 bis) ; `r ‖ s` en fait une valeur de taille
//! fixe, comme la signature Ed25519 des machines. Apple et Android rendent du
//! DER, et c'est l'app qui le déplie — c'est trivial, et cela n'a lieu que
//! d'un côté.
//!
//! # CE QUE LE MESSAGE SIGNÉ PARTAGE AVEC LES MACHINES
//!
//! [`message_a_signer`] est LE MÊME : domaine, genre, identifiant, défi,
//! liaison. Rien n'y désigne l'algorithme, et il n'y a rien à y désigner : la
//! clé rangée dans l'annuaire dit, par sa forme, comment vérifier. Un message
//! signé en Ed25519 par une machine ne vérifiera jamais sous une clé P-256, et
//! réciproquement — ce sont deux mathématiques.
//!
//! La preuve de possession, elle, a son propre message
//! ([`message_de_possession_appareil`]) : la clé y entre, et elle ne fait pas
//! la même taille.
//!
//! # LA MALLÉABILITÉ, ET POURQUOI ELLE EST SANS EFFET ICI
//!
//! Pour toute signature ECDSA `(r, s)`, `(r, n − s)` vérifie aussi. On ne
//! l'empêche pas : une signature est un JUSTIFICATIF, pas un identifiant, et
//! le défi qu'elle couvre ne sert qu'une fois. Celui qui peut produire la
//! seconde forme détient la première, et n'apprend rien.

use asl_id::{Genre, Identifiant};
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature as SignatureP256, SigningKey, VerifyingKey};

use crate::{
    DEFI_OCTETS, DOMAINE_POSSESSION, Defi, Faute, LIAISON_OCTETS, LiaisonDeCanal, message_a_signer,
};

/// La taille d'une clé publique d'appareil : un point P-256, SEC1 compressé.
pub const CLE_APPAREIL_OCTETS: usize = 33;

/// La taille d'une clé secrète d'appareil : un scalaire.
pub const CLE_SECRETE_APPAREIL_OCTETS: usize = 32;

/// La taille d'une signature d'appareil : `r ‖ s`.
pub const SIGNATURE_APPAREIL_OCTETS: usize = 64;

/// La taille du message d'une preuve de possession d'appareil.
pub const MESSAGE_POSSESSION_APPAREIL_OCTETS: usize =
    DOMAINE_POSSESSION.len() + CLE_APPAREIL_OCTETS + DEFI_OCTETS + LIAISON_OCTETS;

/// Une signature ECDSA P-256, `r ‖ s`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureAppareil([u8; SIGNATURE_APPAREIL_OCTETS]);

impl SignatureAppareil {
    /// Depuis soixante-quatre octets.
    ///
    /// **Aucune validation ici**, pour la raison de [`crate::Signature`] : ce
    /// qui compte est qu'elle vérifie.
    #[must_use]
    pub const fn depuis_octets(octets: [u8; SIGNATURE_APPAREIL_OCTETS]) -> Self {
        Self(octets)
    }

    /// Les octets.
    #[must_use]
    pub const fn octets(&self) -> &[u8; SIGNATURE_APPAREIL_OCTETS] {
        &self.0
    }
}

/// Compose le message que signe un appareil qui prouve détenir sa clé.
///
/// Même dessin que [`crate::message_de_possession`], et même raison d'être :
/// il sert avant qu'il y ait un nom. Seule la clé change de taille.
#[must_use]
pub fn message_de_possession_appareil(
    cle: &CleAppareil,
    defi: &Defi,
    liaison: &LiaisonDeCanal,
) -> [u8; MESSAGE_POSSESSION_APPAREIL_OCTETS] {
    const _: () = assert!(
        MESSAGE_POSSESSION_APPAREIL_OCTETS
            == DOMAINE_POSSESSION.len() + CLE_APPAREIL_OCTETS + DEFI_OCTETS + LIAISON_OCTETS,
        "la taille du message de possession d'appareil ne correspond plus à ses champs"
    );

    let publique = cle.octets();
    let source = DOMAINE_POSSESSION
        .iter()
        .chain(publique.iter())
        .chain(defi.octets().iter())
        .chain(liaison.octets().iter());

    let mut message = [0_u8; MESSAGE_POSSESSION_APPAREIL_OCTETS];
    for (place, octet) in message.iter_mut().zip(source) {
        *place = *octet;
    }
    message
}

/// Le séparateur de domaine du défi d'une **attestation** de plate-forme.
///
/// # POURQUOI ENCORE UN DOMAINE, ET CE QU'IL BORNE
///
/// App Attest signe un « clientDataHash » que l'application choisit. Si ce que
/// l'application y met est libre, une attestation captée dans un autre contexte
/// vaudrait ici. Ce message FIXE ce que l'application doit y hacher : notre
/// domaine, la clé qu'elle enrôle, le défi de la connexion, et la liaison de
/// canal.
///
/// **C'est ce qui lie l'attestation à LA clé de l'appareil.** App Attest, à lui
/// seul, atteste une clé À LUI (celle de la Secure Enclave pour l'attestation),
/// et non la clé que l'appareil présente pour signer ses requêtes. Sans ce
/// champ, rien ne dirait que l'attestation concerne CETTE clé-ci — n'importe
/// quelle attestation valide vaudrait pour n'importe quelle clé.
pub const DOMAINE_ATTESTATION: &[u8] = b"air-service-locator/v1/attestation-d-appareil\x00";

/// La taille du défi d'attestation, celui dont l'appareil hache le condensat
/// pour App Attest.
pub const MESSAGE_ATTESTATION_OCTETS: usize =
    DOMAINE_ATTESTATION.len() + CLE_APPAREIL_OCTETS + DEFI_OCTETS + LIAISON_OCTETS;

/// Compose le défi qu'un appareil donne à App Attest.
///
/// **Les deux camps le dérivent identiquement** : l'application le hache pour
/// obtenir le `clientDataHash` qu'elle passe à App Attest, et l'annuaire le
/// recompose pour vérifier le nonce de l'attestation. C'est la même raison qui
/// met [`message_a_signer`] ici — un octet de divergence, et plus aucune
/// attestation ne vérifierait.
#[must_use]
pub fn message_d_attestation(
    cle: &CleAppareil,
    defi: &Defi,
    liaison: &LiaisonDeCanal,
) -> [u8; MESSAGE_ATTESTATION_OCTETS] {
    const _: () = assert!(
        MESSAGE_ATTESTATION_OCTETS
            == DOMAINE_ATTESTATION.len() + CLE_APPAREIL_OCTETS + DEFI_OCTETS + LIAISON_OCTETS,
        "la taille du défi d'attestation ne correspond plus à ses champs"
    );

    let publique = cle.octets();
    let source = DOMAINE_ATTESTATION
        .iter()
        .chain(publique.iter())
        .chain(defi.octets().iter())
        .chain(liaison.octets().iter());

    let mut message = [0_u8; MESSAGE_ATTESTATION_OCTETS];
    for (place, octet) in message.iter_mut().zip(source) {
        *place = *octet;
    }
    message
}

/// La clé publique d'un appareil, telle que l'annuaire la connaît.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleAppareil(VerifyingKey);

impl CleAppareil {
    /// Lit une clé publique.
    ///
    /// # Erreurs
    ///
    /// [`Faute::ClePubliqueInvalide`] si les octets ne forment pas un point de
    /// la courbe. **C'est une vérification réelle** : un préfixe qui n'est ni
    /// `02` ni `03`, ou un `x` sans `y` sur P-256, est refusé ici, et non au
    /// moment où une signature ne vérifie pas sans qu'on sache pourquoi.
    pub fn depuis_octets(octets: [u8; CLE_APPAREIL_OCTETS]) -> Result<Self, Faute> {
        VerifyingKey::from_sec1_bytes(&octets)
            .map(Self)
            .map_err(|_| Faute::ClePubliqueInvalide)
    }

    /// Les octets, SEC1 compressé.
    #[must_use]
    pub fn octets(&self) -> [u8; CLE_APPAREIL_OCTETS] {
        let point = self.0.to_sec1_point(true);
        let mut octets = [0_u8; CLE_APPAREIL_OCTETS];
        for (place, octet) in octets.iter_mut().zip(point.as_bytes()) {
            *place = *octet;
        }
        octets
    }

    /// Cette signature prouve-t-elle que l'appareil détient sa clé ?
    ///
    /// Ce qui est vérifié et ce qui ne l'est pas : voir
    /// [`crate::ClePublique::verifie`] — la fraîcheur du défi n'est pas dans
    /// la signature.
    ///
    /// **Seul un identifiant d'appareil vérifie.** Une clé P-256 n'est jamais
    /// celle d'une machine ; le genre entre dans le message, donc ce ne serait
    /// de toute façon pas le même — mais on le refuse ici, pour que la faute
    /// se voie.
    #[must_use]
    pub fn verifie(
        &self,
        appareil: Identifiant,
        defi: &Defi,
        liaison: &LiaisonDeCanal,
        signature: &SignatureAppareil,
    ) -> bool {
        if appareil.genre() != Genre::Appareil {
            return false;
        }
        let message = message_a_signer(appareil, defi, liaison);
        self.verifie_le_message(&message, signature)
    }

    /// Cette signature prouve-t-elle que celui qui parle détient CETTE clé ?
    #[must_use]
    pub fn prouve_sa_possession(
        &self,
        defi: &Defi,
        liaison: &LiaisonDeCanal,
        signature: &SignatureAppareil,
    ) -> bool {
        let message = message_de_possession_appareil(self, defi, liaison);
        self.verifie_le_message(&message, signature)
    }

    fn verifie_le_message(&self, message: &[u8], signature: &SignatureAppareil) -> bool {
        // `r ‖ s` avec `r` ou `s` nul, ou hors de l'ordre de la courbe, n'est
        // pas une signature : c'est ici que ces soixante-quatre octets sont
        // jugés, et non à `depuis_octets`.
        let Ok(signature) = SignatureP256::from_slice(signature.octets()) else {
            return false;
        };
        self.0.verify(message, &signature).is_ok()
    }
}

/// La clé secrète d'un appareil.
///
/// # ELLE N'EXISTE QUE POUR LES ESSAIS ET LES BANCS
///
/// Sur un vrai appareil, la clé secrète vit dans l'enclave et **n'en sort
/// jamais** : c'est le matériel qui signe, sur demande de l'app, après la
/// biométrie. Ce type sert à fabriquer des signatures là où il n'y a pas
/// d'enclave — un essai, un banc, un client de bureau.
///
/// `p256` l'efface de la mémoire à sa destruction.
#[derive(Debug)]
pub struct CleSecreteAppareil(SigningKey);

impl CleSecreteAppareil {
    /// Depuis trente-deux octets d'entropie.
    ///
    /// # Erreurs
    ///
    /// [`Faute::CleSecreteInvalide`] si les octets ne font pas un scalaire de
    /// la courbe — zéro, ou au-delà de l'ordre. C'est une chance sur 2^128
    /// pour de l'aléa, et une certitude pour un tableau à zéro.
    pub fn depuis_entropie(entropie: [u8; CLE_SECRETE_APPAREIL_OCTETS]) -> Result<Self, Faute> {
        SigningKey::from_slice(&entropie)
            .map(Self)
            .map_err(|_| Faute::CleSecreteInvalide)
    }

    /// La clé publique correspondante.
    #[must_use]
    pub fn publique(&self) -> CleAppareil {
        CleAppareil(*self.0.verifying_key())
    }

    /// Signe le défi de l'annuaire.
    ///
    /// # Erreurs
    ///
    /// [`Faute::PasUnAppareil`] si l'identifiant n'est pas celui d'un
    /// appareil — refusé ici plutôt qu'à la vérification, pour la raison de
    /// [`crate::CleSecrete::signer`].
    pub fn signer(
        &self,
        appareil: Identifiant,
        defi: &Defi,
        liaison: &LiaisonDeCanal,
    ) -> Result<SignatureAppareil, Faute> {
        if appareil.genre() != Genre::Appareil {
            return Err(Faute::PasUnAppareil {
                obtenu: appareil.genre(),
            });
        }
        let message = message_a_signer(appareil, defi, liaison);
        Ok(self.signe_le_message(&message))
    }

    /// Signe la preuve qu'on détient cette clé.
    #[must_use]
    pub fn prouver_la_possession(
        &self,
        defi: &Defi,
        liaison: &LiaisonDeCanal,
    ) -> SignatureAppareil {
        let message = message_de_possession_appareil(&self.publique(), defi, liaison);
        self.signe_le_message(&message)
    }

    fn signe_le_message(&self, message: &[u8]) -> SignatureAppareil {
        // RFC 6979 : déterministe, donc aucun aléa à fournir ici — et une
        // signature qui ne dépend que de la clé et du message.
        let signature: SignatureP256 = self.0.sign(message);
        SignatureAppareil(signature.to_bytes().into())
    }
}
