//! Les cinq signatures qu'une chaîne du Keystore peut employer, pour `webpki`.
//!
//! `rustls-webpki` ne vérifie aucune signature lui-même : il demande une liste
//! de [`SignatureVerificationAlgorithm`], et `rustls-rustcrypto` — qui en a
//! d'excellents — les garde privés. Les voici donc, sur `p256`, `p384` et
//! `rsa`, comme `asl-apple` a écrit les siens.
//!
//! **La chaîne réelle du Fairphone 5** (capture du 2026-09-16) : la feuille
//! P-256 est signée ECDSA P-256/SHA-256 ; l'intermédiaire de TEE, P-256, est
//! signé **ECDSA P-384/SHA-256** ; celui du dessus, P-384, est signé
//! **RSA PKCS#1 v1.5/SHA-256** par la racine, qui est RSA-4096. D'où les trois
//! qu'il faut, et les deux autres ECDSA parce qu'elles ne coûtent rien et
//! qu'une autre racine — GrapheneOS, un autre fabricant — pourrait en changer.
//!
//! # RSA : PKCS#1 v1.5, SHA-256, ET RIEN D'AUTRE
//!
//! Pas de PSS, pas de SHA-384 : la racine de Google signe ainsi, et rien ne dit
//! qu'une autre fera autrement. Ajouter un algorithme qu'aucune chaîne n'emploie
//! élargit ce qu'on accepte sans rien prouver de plus. La clé publique arrive
//! de `webpki` sous sa forme PKCS#1 (`RSAPublicKey`, le contenu du BIT STRING
//! du SPKI), et `rsa` borne son module à 4 096 bits — la taille de la racine.

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use rsa::pkcs1::DecodeRsaPublicKey as _;
use rustls_pki_types::{
    AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id,
};
use sha2::{Digest, Sha256, Sha384};

/// Un vérificateur ECDSA : une courbe, un condensat.
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

/// Le vérificateur RSA PKCS#1 v1.5 sur SHA-256.
#[derive(Debug)]
struct RsaPkcs1Sha256;

impl SignatureVerificationAlgorithm for RsaPkcs1Sha256 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_PKCS1_SHA256
    }

    fn verify_signature(
        &self,
        cle: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        rsa::RsaPublicKey::from_pkcs1_der(cle)
            .map_err(|_| InvalidSignature)?
            .verify(
                rsa::pkcs1v15::Pkcs1v15Sign::new::<Sha256>(),
                &Sha256::digest(message),
                signature,
            )
            .map_err(|_| InvalidSignature)
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
static RSA_SHA256: RsaPkcs1Sha256 = RsaPkcs1Sha256;

/// Ce qu'on passe à `webpki`.
pub static ALGORITHMES: [&dyn SignatureVerificationAlgorithm; 5] = [
    &P256_SHA256,
    &P256_SHA384,
    &P384_SHA256,
    &P384_SHA384,
    &RSA_SHA256,
];
