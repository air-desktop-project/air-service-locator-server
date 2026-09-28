//! Qui l'on croit — `protocole.md` §0, `annuaires.md` §2 quater, décisions 53 à 58.
//!
//! # ON JOINT UNE ADRESSE, ON ATTEND UNE IDENTITÉ
//!
//! L'identité d'un annuaire EST sa clé d'identité Ed25519. Il la présente dans
//! un certificat qu'il a signé lui-même (`asl_cle::certificat_d_identite`), et
//! le client l'accepte si — et seulement si — cette clé est l'une de celles
//! qu'il attend. La poignée de main TLS 1.3 prouve ensuite que le serveur la
//! TIENT (RFC 8446 §4.4.3) : c'est ce couple qui fait l'identité, sans
//! autorité, sans nom, sans date (C20 : ASL fonctionne sans DNS).
//!
//! # LA TRANSITION EST CLOSE (0.34.0)
//!
//! Décision 58 : pendant la bascule, un client qui tenait une autorité PEM
//! (`--peer-ca`, `--federation-ca`, `--ca`) acceptait AUSSI la chaîne d'hier,
//! et l'annuaire la servait à qui envoyait un SNI. **C'est fini** : un annuaire
//! ne présente plus que son certificat d'identité, à tous, et un client ne
//! croit plus qu'une identité — ni autorité, ni nom, ni repli.
//!
//! # POURQUOI ICI, ET PAS DANS `ams-tls`
//!
//! C15 : la pile est celle d'`air-mail-server`, et elle ne se réécrit pas. Elle
//! n'a pas à l'être : ASL construit lui-même ses `ClientConfig`, et un
//! `ServerCertVerifier` se branche par l'API `dangerous` de `rustls` — ce
//! qu'`ams_tls::relay::dane_config` fait déjà pour DANE.

use std::net::SocketAddr;
use std::sync::Arc;

use asl_cle::{ClePublique, CleSecrete, identifiant_de_racine};
use asl_id::Identifiant;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, SignatureScheme};

use crate::tireur::Faute;

/// Ce qu'un client croit d'un annuaire qu'il joint : les identités qu'il
/// attend, et rien d'autre.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Confiance {
    /// Les identités acceptées — des `n-…`, dont la clé du certificat doit
    /// se déduire (`modele.md` §2.7). **Plusieurs** : un locateur partagé —
    /// `asl-root.air-desktop.org` — mène à l'une ou l'autre des racines.
    identites: Vec<Identifiant>,
}

impl Confiance {
    /// On attend l'une de ces clés d'identité.
    #[must_use]
    pub fn par_identite(cles: &[ClePublique]) -> Self {
        Self::par_identifiants(&cles.iter().map(identifiant_de_racine).collect::<Vec<_>>())
    }

    /// On attend l'un de ces annuaires — `--federation <locateur>=<n-…>`.
    #[must_use]
    pub fn par_identifiants(identites: &[Identifiant]) -> Self {
        Self {
            identites: identites.to_vec(),
        }
    }

    /// Les identités attendues.
    #[must_use]
    pub fn identites(&self) -> &[Identifiant] {
        &self.identites
    }
}

/// Monte la configuration cliente d'une confiance.
///
/// # Errors
///
/// [`Faute::Tls`] : aucune identité attendue.
pub fn configuration_cliente_de(confiance: &Confiance) -> Result<Arc<rustls::ClientConfig>, Faute> {
    if confiance.identites.is_empty() {
        return Err(Faute::Tls(
            "aucune identité attendue : rien à croire".to_owned(),
        ));
    }
    let fournisseur = Arc::new(ams_tls::provider_quic());
    let verificateur = Verificateur {
        identites: confiance.identites.clone(),
        fournisseur: Arc::clone(&fournisseur),
    };
    let mut config = rustls::ClientConfig::builder_with_provider(fournisseur)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|quoi| Faute::Tls(format!("TLS 1.3 : {quoi}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verificateur))
        .with_no_client_auth();
    config.alpn_protocols = ams_tls::alpn_h3();
    Ok(Arc::new(config))
}

/// Le nom qu'on donne à la poignée de main pour joindre `cible` : **son
/// ADRESSE**, jamais un nom. Pas de SNI, donc, et aucun nom n'entre dans la
/// décision de croire — même quand le locateur en est un (C20).
pub(crate) fn nom_de_serveur(cible: SocketAddr) -> ServerName<'static> {
    ServerName::IpAddress(cible.ip().into())
}

/// « Clé = identité », et rien d'autre.
#[derive(Debug)]
struct Verificateur {
    /// Les identités acceptées.
    identites: Vec<Identifiant>,
    /// Les algorithmes de signature, pour la preuve de possession.
    fournisseur: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Verificateur {
    fn verify_server_cert(
        &self,
        certificat: &CertificateDer<'_>,
        intermediaires: &[CertificateDer<'_>],
        _nom: &ServerName<'_>,
        _ocsp: &[u8],
        _maintenant: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // **UN SEUL MAILLON, LA BONNE CLÉ.** Rien d'autre n'est lu : ni nom, ni
        // date, ni émetteur (décision 54). Une chaîne de deux n'est pas un
        // certificat d'identité, quelle que soit la clé de sa tête — et une
        // chaîne d'hier, signée par une autorité, pas davantage.
        asl_racines::identite_attendue(
            1_usize.saturating_add(intermediaires.len()),
            certificat,
            &self.identites,
        )
        .map(|_| ServerCertVerified::assertion())
        .ok_or(rustls::Error::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _certificat: &CertificateDer<'_>,
        _signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // La configuration n'offre que TLS 1.3 : on n'arrive jamais ici.
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls13RequiredForQuic,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificat: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // **LA PREUVE DE POSSESSION** : la signature de `CertificateVerify`
        // (RFC 8446 §4.4.3) se vérifie contre la clé du certificat — celle
        // qu'on vient d'accepter comme identité.
        rustls::crypto::verify_tls13_signature(
            message,
            certificat,
            signature,
            &self.fournisseur.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.fournisseur
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Joint l'annuaire au bout de ce locateur, mène la poignée de main, et dit
/// s'il a été cru — ou pourquoi il ne l'a pas été.
///
/// **Rien n'est demandé à l'annuaire** : c'est la question « est-ce bien lui ? »
/// posée seule — ce qu'un diagnostic d'exploitant pose, et ce que les essais
/// posent sur de vraies sockets.
///
/// # Errors
///
/// [`Faute`] : un locateur qui ne se résout pas, une poignée de main refusée
/// — une clé qui n'est pas l'attendue en particulier.
pub async fn sonder(adresse: &str, confiance: &Confiance) -> Result<(), Faute> {
    let cible = crate::tireur::resoudre(adresse).await?;
    crate::tireur::Connexion::ouvrir(cible, adresse, confiance, 5_000_000)
        .await
        .map(|_| ())
}

/// Monte la configuration d'un annuaire qui sert : **son certificat
/// d'identité, à tous** (décisions 55, 58). ALPN `h3` comprise.
///
/// # Errors
///
/// Une clé que le fournisseur ne sait pas charger.
pub fn configuration_d_annuaire(identite: &CleSecrete) -> Result<rustls::ServerConfig, String> {
    let fournisseur = Arc::new(ams_tls::provider_quic());
    let certifiee = certificat_d_identite_charge(identite, &fournisseur)?;
    let mut configuration = rustls::ServerConfig::builder_with_provider(fournisseur)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|quoi| format!("TLS 1.3 : {quoi}"))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(certifiee)));
    configuration.alpn_protocols = ams_tls::alpn_h3();
    Ok(configuration)
}

/// Le certificat d'identité, frappé et chargé pour `rustls`.
fn certificat_d_identite_charge(
    cle: &CleSecrete,
    fournisseur: &Arc<CryptoProvider>,
) -> Result<CertifiedKey, String> {
    let der = asl_cle::certificat_d_identite(cle);
    let pkcs8 = asl_cle::cle_pkcs8(cle);
    let signataire = fournisseur
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            pkcs8.to_vec(),
        )))
        .map_err(|quoi| format!("clé d'identité : {quoi}"))?;
    Ok(CertifiedKey::new(
        vec![CertificateDer::from(der.to_vec())],
        signataire,
    ))
}

#[cfg(test)]
mod tests {
    use super::{Confiance, Verificateur};
    use asl_cle::CleSecrete;
    use rustls::client::danger::ServerCertVerifier as _;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use std::sync::Arc;

    fn monter(identites: &[&CleSecrete]) -> Verificateur {
        Verificateur {
            identites: identites
                .iter()
                .map(|cle| asl_cle::identifiant_de_racine(&cle.publique()))
                .collect(),
            fournisseur: Arc::new(ams_tls::provider_quic()),
        }
    }

    fn juger(verificateur: &Verificateur, chaine: &[Vec<u8>]) -> bool {
        let (tete, suite) = chaine.split_first().expect("une tête");
        let suite: Vec<CertificateDer<'_>> = suite
            .iter()
            .map(|der| CertificateDer::from(der.as_slice()))
            .collect();
        verificateur
            .verify_server_cert(
                &CertificateDer::from(tete.as_slice()),
                &suite,
                &ServerName::try_from("127.0.0.1").expect("une adresse"),
                &[],
                UnixTime::now(),
            )
            .is_ok()
    }

    #[test]
    fn la_cle_attendue_seule_passe() {
        let nous = CleSecrete::depuis_entropie([0x71; 32]);
        let autre = CleSecrete::depuis_entropie([0x72; 32]);
        let certificat = asl_cle::certificat_d_identite(&nous).to_vec();

        assert!(juger(&monter(&[&nous]), std::slice::from_ref(&certificat)));
        // **UNE AUTRE CLÉ N'EST PAS L'ANNUAIRE**, fût-elle parfaitement signée.
        assert!(!juger(
            &monter(&[&autre]),
            std::slice::from_ref(&certificat)
        ));
        // Plusieurs identités acceptées : l'une suffit (un locateur partagé).
        assert!(juger(
            &monter(&[&autre, &nous]),
            std::slice::from_ref(&certificat)
        ));
    }

    #[test]
    fn une_chaine_de_deux_n_est_pas_un_certificat_d_identite() {
        // Même avec la bonne clé en tête : l'identité, c'est UN maillon.
        let nous = CleSecrete::depuis_entropie([0x73; 32]);
        let certificat = asl_cle::certificat_d_identite(&nous).to_vec();
        assert!(!juger(&monter(&[&nous]), &[certificat.clone(), certificat]));
    }

    #[test]
    fn des_octets_quelconques_sont_refuses_et_rien_a_croire_ne_se_monte_pas() {
        let nous = CleSecrete::depuis_entropie([0x74; 32]);
        assert!(!juger(&monter(&[&nous]), &[vec![0x30, 0x00]]));
        assert!(super::configuration_cliente_de(&Confiance::default()).is_err());
        assert!(super::configuration_d_annuaire(&nous).is_ok());
        // Les identités se relisent.
        assert_eq!(
            Confiance::par_identite(&[nous.publique()]).identites(),
            [asl_cle::identifiant_de_racine(&nous.publique())]
        );
    }
}
