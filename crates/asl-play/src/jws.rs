//! La vérification de la signature ES256 d'un JWS, avec la clé de Google.

use asl_jwt::Jws;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;

use crate::Refus;

/// La taille d'une signature ES256, `r ‖ s`.
const SIGNATURE_OCTETS: usize = 64;

/// La clé de vérification de Google, lue depuis son SPKI DER.
///
/// C'est ce que la Play Console donne (base64 décodé) : un `SubjectPublicKeyInfo`
/// d'une clé P-256.
#[derive(Debug, Clone)]
pub struct CleGoogle(VerifyingKey);

impl CleGoogle {
    /// Lit la clé depuis son SPKI DER.
    ///
    /// # Erreurs
    ///
    /// [`Refus::CleIllisible`] si les octets ne sont pas un SPKI de clé P-256.
    pub fn depuis_spki(der: &[u8]) -> Result<Self, Refus> {
        VerifyingKey::from_public_key_der(der)
            .map(Self)
            .map_err(|_| Refus::CleIllisible)
    }
}

/// Vérifie la signature ES256 d'un JWS avec la clé SPKI de Google.
///
/// # Erreurs
///
/// [`Refus::CleIllisible`], [`Refus::SignatureFausse`].
pub fn verifier(jws: &Jws<'_>, cle_spki: &[u8]) -> Result<(), Refus> {
    let cle = CleGoogle::depuis_spki(cle_spki)?;
    let mut brute = [0_u8; SIGNATURE_OCTETS];
    let ecrits = jws
        .decoder_signature(&mut brute)
        .map_err(|_| Refus::SignatureFausse)?;
    if ecrits != SIGNATURE_OCTETS {
        return Err(Refus::SignatureFausse);
    }
    // **CE QUI EST SIGNÉ EST `en-tête_b64 . charge_b64`**, l'ASCII du fil.
    let signature = Signature::from_slice(&brute).map_err(|_| Refus::SignatureFausse)?;
    cle.0
        .verify(jws.signe(), &signature)
        .map_err(|_| Refus::SignatureFausse)
}
