//! Les quatre ECDSA qu'une chaîne d'Apple peut employer, pour `webpki`.
//!
//! `rustls-webpki` ne vérifie aucune signature lui-même : il demande une liste
//! de [`SignatureVerificationAlgorithm`], et `rustls-rustcrypto` — qui en a
//! d'excellents — les garde privés. Les voici donc, sur `p256` et `p384`.
//!
//! **La chaîne d'Apple** : une racine P-384, une intermédiaire P-384, une
//! feuille P-256. Les signatures sont donc P-384 sur SHA-384 (racine →
//! intermédiaire, intermédiaire → feuille). Les deux autres combinaisons sont
//! là parce qu'elles ne coûtent rien et qu'une intermédiaire renouvelée
//! pourrait en changer — pas parce qu'on les a vues.

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use rustls_pki_types::{
    AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id,
};
use sha2::{Digest, Sha256, Sha384};

/// Un vérificateur : une courbe, un condensat.
#[derive(Debug)]
struct Ecdsa {
    courbe: Courbe,
    condensat: Condensat,
}

#[derive(Debug, Clone, Copy)]
enum Courbe {
    P256,
    P384,
}

#[derive(Debug, Clone, Copy)]
enum Condensat {
    Sha256,
    Sha384,
}

impl SignatureVerificationAlgorithm for Ecdsa {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        match self.courbe {
            Courbe::P256 => alg_id::ECDSA_P256,
            Courbe::P384 => alg_id::ECDSA_P384,
        }
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        match self.condensat {
            Condensat::Sha256 => alg_id::ECDSA_SHA256,
            Condensat::Sha384 => alg_id::ECDSA_SHA384,
        }
    }

    fn verify_signature(
        &self,
        cle: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        // Le condensat d'abord, une fois, quelle que soit la courbe.
        let sha256;
        let sha384;
        let condense: &[u8] = match self.condensat {
            Condensat::Sha256 => {
                sha256 = Sha256::digest(message);
                &sha256
            }
            Condensat::Sha384 => {
                sha384 = Sha384::digest(message);
                &sha384
            }
        };
        match self.courbe {
            Courbe::P256 => {
                let signature =
                    p256::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
                p256::ecdsa::VerifyingKey::from_sec1_bytes(cle)
                    .map_err(|_| InvalidSignature)?
                    .verify_prehash(condense, &signature)
                    .map_err(|_| InvalidSignature)
            }
            Courbe::P384 => {
                let signature =
                    p384::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
                p384::ecdsa::VerifyingKey::from_sec1_bytes(cle)
                    .map_err(|_| InvalidSignature)?
                    .verify_prehash(condense, &signature)
                    .map_err(|_| InvalidSignature)
            }
        }
    }
}

static P256_SHA256: Ecdsa = Ecdsa {
    courbe: Courbe::P256,
    condensat: Condensat::Sha256,
};
static P256_SHA384: Ecdsa = Ecdsa {
    courbe: Courbe::P256,
    condensat: Condensat::Sha384,
};
static P384_SHA256: Ecdsa = Ecdsa {
    courbe: Courbe::P384,
    condensat: Condensat::Sha256,
};
static P384_SHA384: Ecdsa = Ecdsa {
    courbe: Courbe::P384,
    condensat: Condensat::Sha384,
};

/// Ce qu'on passe à `webpki`.
pub static ALGORITHMES: [&dyn SignatureVerificationAlgorithm; 4] =
    [&P256_SHA256, &P256_SHA384, &P384_SHA256, &P384_SHA384];
