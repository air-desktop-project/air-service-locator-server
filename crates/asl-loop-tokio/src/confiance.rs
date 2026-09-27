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
//! # LA TRANSITION : DEUX FORMES, ET ON DIT LAQUELLE A SERVI
//!
//! Décision 58 : pendant la bascule, un client qui tient encore une autorité
//! PEM (`--peer-ca`, `--federation-ca`, `--ca`) accepte AUSSI la chaîne d'hier,
//! jugée comme hier (autorité + nom). Le vérificateur essaie l'identité
//! d'abord, l'autorité ensuite, et **retient laquelle a servi** : la voie le
//! journalise, et c'est ce qui dira quand l'ancienne forme ne sert plus.
//!
//! Côté serveur, le même annuaire sert **les deux certificats** : la chaîne
//! d'hier à qui envoie un SNI (les clients d'hier visent un nom), le
//! certificat d'identité à qui vise un locateur IP sans SNI — et le certificat
//! d'identité seul quand aucune chaîne n'est configurée (un annuaire local).
//!
//! # POURQUOI ICI, ET PAS DANS `ams-tls`
//!
//! C15 : la pile est celle d'`air-mail-server`, et elle ne se réécrit pas. Elle
//! n'a pas à l'être : ASL construit lui-même ses `ClientConfig`, et un
//! `ServerCertVerifier` se branche par l'API `dangerous` de `rustls` — ce
//! qu'`ams_tls::relay::dane_config` fait déjà pour DANE.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use asl_cle::{ClePublique, CleSecrete, identifiant_de_racine};
use asl_id::Identifiant;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, SignatureScheme};

use crate::tireur::{Faute, nom_tls};

/// Ce qu'un client croit d'un annuaire qu'il joint.
///
/// **Au moins une des deux** : des identités attendues (la forme nouvelle), ou
/// une autorité PEM (la forme d'hier, pendant la transition). Les deux
/// ensemble : l'identité d'abord, l'autorité en repli (décision 58).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Confiance {
    /// Les identités acceptées — des `n-…`, dont la clé du certificat doit
    /// se déduire (`modele.md` §2.7). **Plusieurs** : un locateur partagé —
    /// `asl-root.air-desktop.org` — mène à l'une ou l'autre des racines.
    identites: Vec<Identifiant>,
    /// L'autorité d'hier, en PEM, qui valide une chaîne et un nom.
    autorite_pem: Option<Vec<u8>>,
    /// Le nom que la chaîne d'hier doit porter, s'il n'est pas l'hôte du
    /// locateur — un locateur IP dont la chaîne porte un nom.
    nom: Option<String>,
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
            autorite_pem: None,
            nom: None,
        }
    }

    /// On croit ce qu'une autorité signe pour le nom visé — la forme d'hier.
    #[must_use]
    pub const fn par_autorite(pem: Vec<u8>) -> Self {
        Self {
            identites: Vec::new(),
            autorite_pem: Some(pem),
            nom: None,
        }
    }

    /// Le nom que la chaîne d'hier doit porter, quand le locateur est une
    /// adresse. **Il part en SNI** : c'est lui qui fait servir la chaîne à un
    /// annuaire en transition (décision 58).
    #[must_use]
    pub fn pour_le_nom(mut self, nom: &str) -> Self {
        self.nom = Some(nom.to_owned());
        self
    }

    /// Ajoute l'autorité d'hier en repli (décision 58).
    #[must_use]
    pub fn avec_autorite(mut self, pem: Option<Vec<u8>>) -> Self {
        self.autorite_pem = pem;
        self
    }

    /// Les identités attendues.
    #[must_use]
    pub fn identites(&self) -> &[Identifiant] {
        &self.identites
    }
}

/// La forme sous laquelle un annuaire a été cru — ce que la voie journalise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Forme {
    /// Sa clé d'identité, attendue et prouvée (la forme nouvelle).
    Identite,
    /// Une chaîne sous l'autorité PEM, pour le nom visé (la forme d'hier).
    Autorite,
}

impl core::fmt::Display for Forme {
    fn fmt(&self, sortie: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        sortie.write_str(match self {
            Self::Identite => "TLS : identité par la clé",
            Self::Autorite => "TLS : autorité et nom (forme d'hier)",
        })
    }
}

/// Ce que la poignée de main retient : la forme qui a servi.
pub(crate) type Retenue = Arc<Mutex<Option<Forme>>>;

/// Monte la configuration cliente d'une confiance, et ce qui retiendra la
/// forme qui aura servi.
///
/// # Errors
///
/// [`Faute::Tls`] : ni identité ni autorité, une autorité illisible ou vide.
pub(crate) fn configuration_cliente(
    confiance: &Confiance,
) -> Result<(Arc<rustls::ClientConfig>, Retenue), Faute> {
    let fournisseur = Arc::new(ams_tls::provider_quic());
    let repli = match &confiance.autorite_pem {
        Some(pem) => Some(verificateur_d_autorite(pem, &fournisseur)?),
        None if confiance.identites.is_empty() => {
            return Err(Faute::Tls(
                "ni identité attendue ni autorité : rien à croire".to_owned(),
            ));
        }
        None => None,
    };
    let retenue: Retenue = Arc::new(Mutex::new(None));
    let verificateur = Verificateur {
        identites: confiance.identites.clone(),
        repli,
        fournisseur: Arc::clone(&fournisseur),
        retenue: Arc::clone(&retenue),
    };
    let mut config = rustls::ClientConfig::builder_with_provider(fournisseur)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|quoi| Faute::Tls(format!("TLS 1.3 : {quoi}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verificateur))
        .with_no_client_auth();
    config.alpn_protocols = ams_tls::alpn_h3();
    Ok((Arc::new(config), retenue))
}

/// Le nom qu'on donne à la poignée de main pour joindre `cible`.
///
/// **Sans autorité, on vise l'ADRESSE** : pas de SNI, donc le serveur en
/// transition sert son certificat d'identité (décision 58), et aucun nom
/// n'entre dans la décision de croire. Avec une autorité, on vise le nom de
/// l'adresse, comme hier — le serveur sert alors sa chaîne.
///
/// # Errors
///
/// [`Faute::Tls`] pour un hôte qui n'est ni un nom ni une adresse.
pub(crate) fn nom_de_serveur(
    confiance: &Confiance,
    adresse: &str,
    cible: SocketAddr,
) -> Result<ServerName<'static>, Faute> {
    if confiance.autorite_pem.is_none() {
        return Ok(ServerName::IpAddress(cible.ip().into()));
    }
    let nom = confiance.nom.clone().unwrap_or_else(|| nom_tls(adresse));
    ServerName::try_from(nom.clone())
        .map_err(|_| Faute::Tls(format!("`{nom}` n'est pas un nom de serveur")))
}

/// Le vérificateur de la forme d'hier : une autorité PEM, un nom.
fn verificateur_d_autorite(
    pem: &[u8],
    fournisseur: &Arc<CryptoProvider>,
) -> Result<Arc<WebPkiServerVerifier>, Faute> {
    use rustls::pki_types::pem::PemObject as _;

    let mut magasin = rustls::RootCertStore::empty();
    for der in CertificateDer::pem_slice_iter(pem) {
        let der = der.map_err(|quoi| Faute::Tls(format!("certificat illisible : {quoi}")))?;
        magasin
            .add(der)
            .map_err(|quoi| Faute::Tls(format!("racine refusée : {quoi}")))?;
    }
    if magasin.is_empty() {
        return Err(Faute::Tls("aucune racine à qui faire confiance".to_owned()));
    }
    WebPkiServerVerifier::builder_with_provider(Arc::new(magasin), Arc::clone(fournisseur))
        .build()
        .map_err(|quoi| Faute::Tls(format!("vérificateur : {quoi}")))
}

/// « Clé = identité », avec l'autorité d'hier en repli.
#[derive(Debug)]
struct Verificateur {
    /// Les identités acceptées.
    identites: Vec<Identifiant>,
    /// La forme d'hier, pendant la transition.
    repli: Option<Arc<WebPkiServerVerifier>>,
    /// Les algorithmes de signature, pour la preuve de possession.
    fournisseur: Arc<CryptoProvider>,
    /// Où l'on dit quelle forme a servi.
    retenue: Retenue,
}

impl Verificateur {
    fn retenir(&self, forme: Forme) {
        if let Ok(mut place) = self.retenue.lock() {
            *place = Some(forme);
        }
    }
}

impl ServerCertVerifier for Verificateur {
    fn verify_server_cert(
        &self,
        certificat: &CertificateDer<'_>,
        intermediaires: &[CertificateDer<'_>],
        nom: &ServerName<'_>,
        ocsp: &[u8],
        maintenant: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // **UN SEUL MAILLON, LA BONNE CLÉ.** Rien d'autre n'est lu : ni nom, ni
        // date, ni émetteur (décision 54). Une chaîne de deux n'est pas un
        // certificat d'identité, quelle que soit la clé de sa tête.
        if intermediaires.is_empty()
            && let Ok(cle) = asl_cle::cle_du_certificat(certificat)
            && self.identites.contains(&identifiant_de_racine(&cle))
        {
            self.retenir(Forme::Identite);
            return Ok(ServerCertVerified::assertion());
        }
        match &self.repli {
            Some(autorite) => {
                let verdict = autorite.verify_server_cert(
                    certificat,
                    intermediaires,
                    nom,
                    ocsp,
                    maintenant,
                )?;
                self.retenir(Forme::Autorite);
                Ok(verdict)
            }
            None => Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )),
        }
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

/// La configuration cliente d'une confiance, seule — pour un client qui mène
/// lui-même sa connexion (un harnais d'essai, un diagnostic).
///
/// # Errors
///
/// [`Faute::Tls`] : ni identité ni autorité, une autorité illisible ou vide.
pub fn configuration_cliente_de(confiance: &Confiance) -> Result<Arc<rustls::ClientConfig>, Faute> {
    configuration_cliente(confiance).map(|(configuration, _)| configuration)
}

/// Joint l'annuaire au bout de ce locateur, mène la poignée de main, et rend
/// la forme sous laquelle il a été cru — ou pourquoi il ne l'a pas été.
///
/// **Rien n'est demandé à l'annuaire** : c'est la question « est-ce bien lui ? »
/// posée seule — ce qu'un diagnostic d'exploitant pose, et ce que les essais
/// posent sur de vraies sockets.
///
/// # Errors
///
/// [`Faute`] : un locateur qui ne se résout pas, une poignée de main refusée
/// — une clé qui n'est pas l'attendue en particulier.
pub async fn sonder(adresse: &str, confiance: &Confiance) -> Result<Forme, Faute> {
    let cible = crate::tireur::resoudre(adresse).await?;
    let connexion = crate::tireur::Connexion::ouvrir(cible, adresse, confiance, 5_000_000).await?;
    connexion
        .forme()
        .ok_or_else(|| Faute::Tls("la poignée de main n'a rien retenu".to_owned()))
}

/// Monte la configuration d'un annuaire qui sert : son certificat d'identité,
/// la chaîne d'hier, ou les deux (décision 58). ALPN `h3` comprise.
///
/// # Errors
///
/// Ni identité ni chaîne ; une chaîne ou une clé illisible ; une clé qui ne
/// correspond pas à sa chaîne.
pub fn configuration_d_annuaire(
    identite: Option<&CleSecrete>,
    chaine: Option<(&[u8], &[u8])>,
) -> Result<rustls::ServerConfig, String> {
    let fournisseur = Arc::new(ams_tls::provider_quic());
    let identite = identite
        .map(|cle| certificat_d_identite_charge(cle, &fournisseur))
        .transpose()?;
    let chaine = chaine
        .map(|(chaine_pem, cle_pem)| {
            ams_tls::certified_key(chaine_pem, cle_pem)
                .map(Arc::new)
                .map_err(|quoi| format!("certificat : {quoi}"))
        })
        .transpose()?;
    if identite.is_none() && chaine.is_none() {
        return Err("ni clé d'identité ni certificat : rien à présenter".to_owned());
    }
    let mut configuration = rustls::ServerConfig::builder_with_provider(fournisseur)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|quoi| format!("TLS 1.3 : {quoi}"))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Resolveur { identite, chaine }));
    configuration.alpn_protocols = ams_tls::alpn_h3();
    Ok(configuration)
}

/// Le certificat d'identité, frappé et chargé pour `rustls`.
fn certificat_d_identite_charge(
    cle: &CleSecrete,
    fournisseur: &Arc<CryptoProvider>,
) -> Result<Arc<CertifiedKey>, String> {
    let der = asl_cle::certificat_d_identite(cle);
    let pkcs8 = asl_cle::cle_pkcs8(cle);
    let signataire = fournisseur
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            pkcs8.to_vec(),
        )))
        .map_err(|quoi| format!("clé d'identité : {quoi}"))?;
    Ok(Arc::new(CertifiedKey::new(
        vec![CertificateDer::from(der.to_vec())],
        signataire,
    )))
}

/// Quel certificat servir (décision 58).
#[derive(Debug)]
struct Resolveur {
    /// Le certificat d'identité, s'il y a une clé d'identité.
    identite: Option<Arc<CertifiedKey>>,
    /// La chaîne d'hier, s'il y en a une.
    chaine: Option<Arc<CertifiedKey>>,
}

impl ResolvesServerCert for Resolveur {
    fn resolve(&self, bonjour: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // **UN SNI, C'EST UN CLIENT D'HIER** : il vise un nom et juge une
        // chaîne. Sans SNI — un locateur IP —, c'est un client qui attend une
        // identité. Sans l'un des deux certificats, l'autre sert à tous.
        match (bonjour.server_name(), &self.chaine) {
            (Some(_), Some(chaine)) => Some(Arc::clone(chaine)),
            _ => self.identite.clone().or_else(|| self.chaine.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Confiance, Forme, Verificateur};
    use asl_cle::CleSecrete;
    use rustls::client::danger::ServerCertVerifier as _;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use std::sync::{Arc, Mutex};

    fn monter(identites: &[&CleSecrete]) -> (Verificateur, super::Retenue) {
        let retenue: super::Retenue = Arc::new(Mutex::new(None));
        let verificateur = Verificateur {
            identites: identites
                .iter()
                .map(|cle| asl_cle::identifiant_de_racine(&cle.publique()))
                .collect(),
            repli: None,
            fournisseur: Arc::new(ams_tls::provider_quic()),
            retenue: Arc::clone(&retenue),
        };
        (verificateur, retenue)
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
    fn la_cle_attendue_seule_passe_et_la_forme_est_retenue() {
        let nous = CleSecrete::depuis_entropie([0x71; 32]);
        let autre = CleSecrete::depuis_entropie([0x72; 32]);
        let certificat = asl_cle::certificat_d_identite(&nous).to_vec();

        let (verificateur, retenue) = monter(&[&nous]);
        assert!(juger(&verificateur, std::slice::from_ref(&certificat)));
        assert_eq!(
            *retenue.lock().expect("pas empoisonné"),
            Some(Forme::Identite)
        );

        // **UNE AUTRE CLÉ N'EST PAS L'ANNUAIRE**, fût-elle parfaitement signée.
        let (verificateur, retenue) = monter(&[&autre]);
        assert!(!juger(&verificateur, std::slice::from_ref(&certificat)));
        assert_eq!(*retenue.lock().expect("pas empoisonné"), None);

        // Plusieurs identités acceptées : l'une suffit (un locateur partagé).
        let (verificateur, _) = monter(&[&autre, &nous]);
        assert!(juger(&verificateur, std::slice::from_ref(&certificat)));
    }

    #[test]
    fn une_chaine_de_deux_n_est_pas_un_certificat_d_identite() {
        // Même avec la bonne clé en tête : l'identité, c'est UN maillon.
        let nous = CleSecrete::depuis_entropie([0x73; 32]);
        let certificat = asl_cle::certificat_d_identite(&nous).to_vec();
        let (verificateur, _) = monter(&[&nous]);
        assert!(!juger(&verificateur, &[certificat.clone(), certificat]));
    }

    #[test]
    fn des_octets_quelconques_sont_refuses_et_rien_a_croire_ne_se_monte_pas() {
        let nous = CleSecrete::depuis_entropie([0x74; 32]);
        let (verificateur, _) = monter(&[&nous]);
        assert!(!juger(&verificateur, &[vec![0x30, 0x00]]));
        assert!(super::configuration_cliente(&Confiance::default()).is_err());
        assert!(
            super::configuration_cliente(&Confiance::par_autorite(b"pas un PEM".to_vec())).is_err()
        );
        assert!(super::configuration_d_annuaire(None, None).is_err());
        // Les identités se relisent.
        assert_eq!(
            Confiance::par_identite(&[nous.publique()]).identites(),
            [asl_cle::identifiant_de_racine(&nous.publique())]
        );
        assert_eq!(Forme::Identite.to_string(), "TLS : identité par la clé");
        assert!(!Forme::Autorite.to_string().is_empty());
    }
}
