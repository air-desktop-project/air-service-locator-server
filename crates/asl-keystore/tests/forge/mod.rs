//! De quoi FABRIQUER une chaîne d'attestation, sous la racine du banc.
//!
//! # POURQUOI FABRIQUER, ALORS QU'UNE CHAÎNE RÉELLE EST DANS LE DÉPÔT
//!
//! La chaîne du Fairphone 5 (`tests/capture.rs`) prouve qu'un vrai TEE parle
//! bien comme la documentation le dit, et c'est l'essai qui compte. Mais elle
//! ne peut en éprouver qu'UN : le bon. Les refus — défi faux, démarrage non
//! vérifié, clé importée, autre paquet — demandent des feuilles que Google ne
//! signera jamais. On les signe donc ici, sous une racine à nous, et le
//! vérificateur prend ses racines en paramètre pour cette raison.
//!
//! # TOUT EST ÉCRIT ICI, EN RUST, ET RIEN N'EST TIRÉ AU HASARD
//!
//! Les clés sont des scalaires FIXES ; les signatures ECDSA sont
//! déterministes (RFC 6979). Deux exécutions fabriquent les mêmes octets, ce
//! qui permet de commettre une graine de fuzz et de vérifier qu'elle est bien
//! ce que la forge produit. Le DER est écrit à la main, balise par balise :
//! c'est un banc, et un banc doit pouvoir écrire ce qu'un encodeur refuserait.
//!
//! **La seule chose qui vient d'ailleurs est RSA** : `fixtures/racine-rsa.der`
//! et `fixtures/intermediaire-sous-rsa.der`, frappés par `fabriquer.py` avec
//! `openssl` et COMMITÉS, parce qu'aucune dépendance de développement ne sait
//! signer en RSA sans en tirer une nouvelle. L'intermédiaire, lui, est P-256
//! avec un scalaire connu d'ici : la forge signe des feuilles sous lui.

#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;

use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use sha2::{Digest, Sha256, Sha384};

/// Le 1er juin 2026 : dans la validité des certificats du banc.
pub const PENDANT: u64 = 1_780_272_000;

/// Notre paquet et notre empreinte, tels que le banc les écrit.
pub const PAQUET: &str = "org.airdesktop.servicelocator";
pub const EMPREINTE: [u8; 32] = [0xA5; 32];

/// Le scalaire de l'intermédiaire P-256 signé par la racine RSA du banc —
/// `fabriquer.py` l'a donné à `openssl`, et la forge signe avec.
pub const SCALAIRE_SOUS_RSA: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
];

/// Lit une pièce du banc.
pub fn piece(nom: &str) -> Vec<u8> {
    let mut chemin = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    chemin.push("tests/fixtures");
    chemin.push(nom);
    fs::read(&chemin).unwrap_or_else(|faute| panic!("pièce {chemin:?} illisible : {faute}"))
}

// ── DER, écrit à la main ────────────────────────────────────────────────────

/// Encode une longueur DER.
pub fn longueur(n: usize) -> Vec<u8> {
    match n {
        0..=0x7F => vec![u8::try_from(n).expect("court")],
        0x80..=0xFF => vec![0x81, u8::try_from(n).expect("un octet")],
        _ => {
            let mut v = vec![0x82];
            v.extend_from_slice(&u16::try_from(n).expect("deux octets").to_be_bytes());
            v
        }
    }
}

/// Un élément : balise (un ou plusieurs octets), longueur, contenu.
pub fn element(balise: &[u8], contenu: &[u8]) -> Vec<u8> {
    let mut sortie = balise.to_vec();
    sortie.extend_from_slice(&longueur(contenu.len()));
    sortie.extend_from_slice(contenu);
    sortie
}

pub fn sequence(parties: &[&[u8]]) -> Vec<u8> {
    element(&[0x30], &parties.concat())
}

pub fn ensemble(parties: &[&[u8]]) -> Vec<u8> {
    element(&[0x31], &parties.concat())
}

pub fn octets(o: &[u8]) -> Vec<u8> {
    element(&[0x04], o)
}

pub fn nul() -> Vec<u8> {
    vec![0x05, 0x00]
}

pub fn booleen(vrai: bool) -> Vec<u8> {
    vec![0x01, 0x01, if vrai { 0xFF } else { 0x00 }]
}

pub fn oid(o: &[u8]) -> Vec<u8> {
    element(&[0x06], o)
}

/// Un INTEGER non négatif, minimal.
pub fn entier(valeur: u64) -> Vec<u8> {
    element(&[0x02], &contenu_d_entier(valeur))
}

/// Un ENUMERATED.
pub fn enumere(valeur: u64) -> Vec<u8> {
    element(&[0x0A], &contenu_d_entier(valeur))
}

fn contenu_d_entier(valeur: u64) -> Vec<u8> {
    let tous = valeur.to_be_bytes();
    let premier = tous.iter().position(|o| *o != 0).unwrap_or(7);
    let mut contenu = tous[premier..].to_vec();
    if contenu[0] & 0x80 != 0 {
        contenu.insert(0, 0);
    }
    contenu
}

/// Un BIT STRING sans bit inutilisé.
pub fn bits(b: &[u8]) -> Vec<u8> {
    let mut contenu = vec![0];
    contenu.extend_from_slice(b);
    element(&[0x03], &contenu)
}

/// La balise `[n]` EXPLICIT (contextuelle, construite), forme courte ou
/// longue selon `n`.
pub fn balise_contextuelle(numero: u32) -> Vec<u8> {
    if numero < 0x1F {
        return vec![0xA0 | u8::try_from(numero).expect("petit")];
    }
    let mut suite = vec![u8::try_from(numero & 0x7F).expect("sept bits")];
    let mut reste = numero >> 7;
    while reste > 0 {
        suite.insert(0, 0x80 | u8::try_from(reste & 0x7F).expect("sept bits"));
        reste >>= 7;
    }
    let mut sortie = vec![0xBF];
    sortie.extend_from_slice(&suite);
    sortie
}

/// `[n] EXPLICIT contenu`.
pub fn champ(numero: u32, contenu: &[u8]) -> Vec<u8> {
    element(&balise_contextuelle(numero), contenu)
}

// ── La KeyDescription ───────────────────────────────────────────────────────

/// `RootOfTrust`, prêt à mettre sous `[704]`.
pub fn racine_de_confiance(verrouille: bool, etat: u64) -> Vec<u8> {
    sequence(&[
        &octets(&[0xC3; 32]),
        &booleen(verrouille),
        &enumere(etat),
        &octets(&[0x9B; 32]),
    ])
}

/// `AttestationApplicationId`, enveloppé dans son OCTET STRING, prêt à mettre
/// sous `[709]`.
pub fn application(paquets: &[(&str, u64)], empreintes: &[&[u8]]) -> Vec<u8> {
    let paquets: Vec<Vec<u8>> = paquets
        .iter()
        .map(|(nom, version)| sequence(&[&octets(nom.as_bytes()), &entier(*version)]))
        .collect();
    let empreintes: Vec<Vec<u8>> = empreintes.iter().map(|e| octets(e)).collect();
    let paquets: Vec<&[u8]> = paquets.iter().map(Vec::as_slice).collect();
    let empreintes: Vec<&[u8]> = empreintes.iter().map(Vec::as_slice).collect();
    octets(&sequence(&[&ensemble(&paquets), &ensemble(&empreintes)]))
}

/// Ce que la forge écrit dans une `KeyDescription` — modifiable champ par
/// champ, pour fabriquer chaque refus.
#[derive(Debug, Clone)]
pub struct Portrait {
    pub version: u64,
    pub niveau_attestation: u64,
    pub version_keymaster: u64,
    pub niveau_keymaster: u64,
    pub defi: Vec<u8>,
    pub identifiant_unique: Vec<u8>,
    /// Les champs de `softwareEnforced`, déjà encodés (`champ(n, …)`).
    pub logiciel: Vec<Vec<u8>>,
    /// Les champs de `teeEnforced`, déjà encodés.
    pub materiel: Vec<Vec<u8>>,
}

impl Portrait {
    /// Le portrait COHÉRENT : ce que le Fairphone 5 a dit, sous le défi du
    /// banc.
    pub fn coherent(defi: &[u8]) -> Self {
        Self {
            version: 3,
            niveau_attestation: 1,
            version_keymaster: 41,
            niveau_keymaster: 1,
            defi: defi.to_vec(),
            identifiant_unique: Vec::new(),
            logiciel: vec![
                champ(701, &entier(0x01A0_AB0A_0620)),
                champ(709, &application(&[(PAQUET, 6)], &[&EMPREINTE])),
            ],
            materiel: vec![
                champ(1, &ensemble(&[&entier(2)])),
                champ(2, &entier(3)),
                champ(3, &entier(256)),
                champ(5, &ensemble(&[&entier(4)])),
                champ(10, &entier(1)),
                champ(503, &nul()),
                champ(702, &entier(0)),
                champ(704, &racine_de_confiance(true, 0)),
                champ(705, &entier(150_000)),
                champ(706, &entier(202_608)),
                champ(718, &entier(20_260_805)),
                champ(719, &entier(20_260_805)),
            ],
        }
    }

    /// Retire de `teeEnforced` le champ `[numero]`.
    pub fn sans_materiel(mut self, numero: u32) -> Self {
        let balise = balise_contextuelle(numero);
        self.materiel.retain(|c| !c.starts_with(&balise));
        self
    }

    /// Remplace dans `teeEnforced` le champ `[numero]` par `contenu`.
    pub fn avec_materiel(self, numero: u32, contenu: &[u8]) -> Self {
        let mut sans = self.sans_materiel(numero);
        sans.materiel.push(champ(numero, contenu));
        sans
    }

    /// Retire de `softwareEnforced` le champ `[numero]`.
    pub fn sans_logiciel(mut self, numero: u32) -> Self {
        let balise = balise_contextuelle(numero);
        self.logiciel.retain(|c| !c.starts_with(&balise));
        self
    }

    /// Remplace dans `softwareEnforced` le champ `[numero]` par `contenu`.
    pub fn avec_logiciel(self, numero: u32, contenu: &[u8]) -> Self {
        let mut sans = self.sans_logiciel(numero);
        sans.logiciel.push(champ(numero, contenu));
        sans
    }

    /// La `KeyDescription` en DER.
    pub fn encoder(&self) -> Vec<u8> {
        let logiciel: Vec<&[u8]> = self.logiciel.iter().map(Vec::as_slice).collect();
        let materiel: Vec<&[u8]> = self.materiel.iter().map(Vec::as_slice).collect();
        sequence(&[
            &entier(self.version),
            &enumere(self.niveau_attestation),
            &entier(self.version_keymaster),
            &enumere(self.niveau_keymaster),
            &octets(&self.defi),
            &octets(&self.identifiant_unique),
            &sequence(&logiciel),
            &sequence(&materiel),
        ])
    }
}

// ── Les clés et les certificats ─────────────────────────────────────────────

/// Une clé du banc : sa courbe, son scalaire.
pub enum Cle {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
}

/// Le condensat d'une signature de certificat.
#[derive(Debug, Clone, Copy)]
pub enum Condensat {
    Sha256,
    Sha384,
}

const OID_EC: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
const OID_ECDSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
const OID_ECDSA_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];
const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x0F];
/// `1.3.6.1.4.1.11129.2.1.17`.
pub const OID_DESCRIPTION: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x01, 0x11];

impl Cle {
    pub fn p256(scalaire: &[u8; 32]) -> Self {
        Self::P256(p256::ecdsa::SigningKey::from_slice(scalaire).expect("un scalaire P-256"))
    }

    pub fn p384(scalaire: &[u8; 48]) -> Self {
        Self::P384(p384::ecdsa::SigningKey::from_slice(scalaire).expect("un scalaire P-384"))
    }

    /// Le point public non compressé.
    pub fn point(&self) -> Vec<u8> {
        match self {
            Self::P256(cle) => cle.verifying_key().to_sec1_point(false).as_bytes().to_vec(),
            Self::P384(cle) => cle.verifying_key().to_sec1_point(false).as_bytes().to_vec(),
        }
    }

    /// Le point public P-256 compressé, comme le fil le porte.
    pub fn compresse(&self) -> [u8; 33] {
        match self {
            Self::P256(cle) => cle
                .verifying_key()
                .to_sec1_point(true)
                .as_bytes()
                .try_into()
                .expect("33 octets"),
            Self::P384(_) => panic!("pas une clé d'appareil"),
        }
    }

    /// `SubjectPublicKeyInfo`.
    pub fn spki(&self) -> Vec<u8> {
        let courbe = match self {
            Self::P256(_) => OID_P256,
            Self::P384(_) => OID_P384,
        };
        sequence(&[
            &sequence(&[&oid(OID_EC), &oid(courbe)]),
            &bits(&self.point()),
        ])
    }

    /// Signe `tbs` et rend la signature en DER.
    pub fn signer(&self, tbs: &[u8], condensat: Condensat) -> Vec<u8> {
        let sha256;
        let sha384;
        let condense: &[u8] = match condensat {
            Condensat::Sha256 => {
                sha256 = Sha256::digest(tbs);
                &sha256
            }
            Condensat::Sha384 => {
                sha384 = Sha384::digest(tbs);
                &sha384
            }
        };
        match self {
            Self::P256(cle) => {
                let signature: p256::ecdsa::Signature =
                    cle.sign_prehash(condense).expect("une signature");
                signature.to_der().as_bytes().to_vec()
            }
            Self::P384(cle) => {
                let signature: p384::ecdsa::Signature =
                    cle.sign_prehash(condense).expect("une signature");
                signature.to_der().as_bytes().to_vec()
            }
        }
    }
}

/// `AlgorithmIdentifier` d'une signature ECDSA.
pub fn algorithme(condensat: Condensat) -> Vec<u8> {
    sequence(&[&oid(match condensat {
        Condensat::Sha256 => OID_ECDSA_SHA256,
        Condensat::Sha384 => OID_ECDSA_SHA384,
    })])
}

/// Un `Name` à un seul `commonName`.
pub fn nom(cn: &str) -> Vec<u8> {
    sequence(&[&ensemble(&[&sequence(&[
        &oid(OID_CN),
        &element(&[0x0C], cn.as_bytes()),
    ])])])
}

/// La validité du banc : du 1er janvier 2026 au 31 décembre 2049.
pub fn validite() -> Vec<u8> {
    sequence(&[
        &element(&[0x17], b"260101000000Z"),
        &element(&[0x17], b"491231235959Z"),
    ])
}

/// Les extensions d'une autorité : `basicConstraints` CA:TRUE, `keyUsage`
/// keyCertSign — critiques.
pub fn extensions_d_autorite() -> Vec<Vec<u8>> {
    vec![
        sequence(&[
            &oid(OID_BASIC_CONSTRAINTS),
            &booleen(true),
            &octets(&sequence(&[&booleen(true)])),
        ]),
        sequence(&[
            &oid(OID_KEY_USAGE),
            &booleen(true),
            &octets(&[0x03, 0x02, 0x02, 0x04]),
        ]),
    ]
}

/// Les extensions d'une feuille : `keyUsage` digitalSignature, et
/// l'attestation si on en donne une.
pub fn extensions_de_feuille(description: Option<&[u8]>) -> Vec<Vec<u8>> {
    let mut sortie = vec![sequence(&[
        &oid(OID_KEY_USAGE),
        &booleen(true),
        &octets(&[0x03, 0x02, 0x07, 0x80]),
    ])];
    if let Some(description) = description {
        sortie.push(sequence(&[&oid(OID_DESCRIPTION), &octets(description)]));
    }
    sortie
}

/// Un certificat v3 : `sujet`, sa clé, signé par `signataire` au nom
/// d'`emetteur`.
pub fn certificat(
    serie: u64,
    emetteur: &str,
    sujet: &str,
    cle_du_sujet: &Cle,
    signataire: &Cle,
    condensat: Condensat,
    extensions: &[Vec<u8>],
) -> Vec<u8> {
    certificat_depuis_spki(
        serie,
        emetteur,
        sujet,
        &cle_du_sujet.spki(),
        signataire,
        condensat,
        extensions,
    )
}

/// Comme [`certificat`], mais le SPKI du sujet est donné tel quel — pour
/// écrire une clé que personne ne tient, ou mal formée.
pub fn certificat_depuis_spki(
    serie: u64,
    emetteur: &str,
    sujet: &str,
    spki: &[u8],
    signataire: &Cle,
    condensat: Condensat,
    extensions: &[Vec<u8>],
) -> Vec<u8> {
    let extensions: Vec<&[u8]> = extensions.iter().map(Vec::as_slice).collect();
    let tbs = sequence(&[
        &champ(0, &entier(2)),
        &entier(serie),
        &algorithme(condensat),
        &nom(emetteur),
        &validite(),
        &nom(sujet),
        spki,
        &champ(3, &sequence(&extensions)),
    ]);
    let signature = signataire.signer(&tbs, condensat);
    sequence(&[&tbs, &algorithme(condensat), &bits(&signature)])
}

// ── Le banc ─────────────────────────────────────────────────────────────────

/// La chaîne canonique du banc, calquée sur celle du Fairphone 5 :
///
/// ```text
/// racine (P-256, auto-signée)
///   └─ intermédiaire (P-384), signée P-256/SHA-256
///        └─ TEE (P-256), signée P-384/SHA-256
///             └─ feuille (P-256), signée P-256/SHA-256
/// ```
///
/// La vraie est RSA-4096 → P-384 → P-256 → P-256 ; ici la racine est P-256
/// parce qu'aucune dépendance de développement ne signe en RSA, et la racine
/// RSA du banc vit dans `fixtures/`.
pub struct Banc {
    pub racine: Cle,
    pub intermediaire: Cle,
    pub tee: Cle,
    pub appareil: Cle,
    pub defi: Vec<u8>,
    pub racine_der: Vec<u8>,
    pub intermediaire_der: Vec<u8>,
    pub tee_der: Vec<u8>,
}

impl Banc {
    pub fn nouveau() -> Self {
        Self::nouveau_sous(&[0x11; 32])
    }

    /// Le même banc, sous une racine d'un autre scalaire — une AUTRE racine,
    /// étrangère à la première.
    pub fn nouveau_sous(scalaire_de_racine: &[u8; 32]) -> Self {
        let racine = Cle::p256(scalaire_de_racine);
        let intermediaire = Cle::p384(&[0x22; 48]);
        let tee = Cle::p256(&[0x33; 32]);
        let appareil = Cle::p256(&[0x44; 32]);
        let racine_der = certificat(
            1,
            "Racine du banc",
            "Racine du banc",
            &racine,
            &racine,
            Condensat::Sha256,
            &extensions_d_autorite(),
        );
        let intermediaire_der = certificat(
            2,
            "Racine du banc",
            "Intermediaire du banc",
            &intermediaire,
            &racine,
            Condensat::Sha256,
            &extensions_d_autorite(),
        );
        let tee_der = certificat(
            3,
            "Intermediaire du banc",
            "TEE du banc",
            &tee,
            &intermediaire,
            Condensat::Sha256,
            &extensions_d_autorite(),
        );
        Self {
            racine,
            intermediaire,
            tee,
            appareil,
            defi: Sha256::digest(b"le defi du banc").to_vec(),
            racine_der,
            intermediaire_der,
            tee_der,
        }
    }

    /// Une feuille pour la clé d'appareil, sous le TEE, portant ce portrait.
    pub fn feuille(&self, portrait: &Portrait) -> Vec<u8> {
        self.feuille_de(&self.appareil, Some(&portrait.encoder()))
    }

    /// Une feuille pour cette clé, avec — ou sans — description.
    pub fn feuille_de(&self, cle: &Cle, description: Option<&[u8]>) -> Vec<u8> {
        certificat(
            1,
            "TEE du banc",
            "Android Keystore Key",
            cle,
            &self.tee,
            Condensat::Sha256,
            &extensions_de_feuille(description),
        )
    }

    /// La case cohérente : feuille, TEE, intermédiaire — sans la racine.
    pub fn case(&self, portrait: &Portrait) -> Vec<u8> {
        self.case_de(&self.feuille(portrait))
    }

    /// Une case avec cette feuille, puis TEE et intermédiaire.
    pub fn case_de(&self, feuille: &[u8]) -> Vec<u8> {
        asl_keystore::case::assembler(&[feuille, &self.tee_der, &self.intermediaire_der])
            .expect("la case tient")
    }

    /// Ce que l'annuaire attend, sous la racine du banc.
    pub fn attendu<'a>(
        &'a self,
        racines: &'a [&'a [u8]],
        cle: &'a [u8; 33],
    ) -> asl_keystore::Attendu<'a> {
        asl_keystore::Attendu {
            racines,
            defi: &self.defi,
            cle,
            paquet: PAQUET,
            empreinte: &EMPREINTE,
            maintenant: PENDANT,
        }
    }
}

/// Le même certificat, sans son `[0] version` : un TBS de forme v1. La
/// signature ne vaut plus rien — le marcheur ne la regarde pas.
pub fn sans_version(cert: &[u8]) -> Vec<u8> {
    use asl_keystore::der;
    let (certificat, _) = der::attendu(cert, der::SEQUENCE).expect("un certificat");
    let (tbs, apres_tbs) = der::attendu(certificat, der::SEQUENCE).expect("un TBS");
    let (version, sans) = der::element(tbs).expect("la version");
    assert_eq!(version.balise, der::Balise::contextuelle(0));
    sequence(&[&sequence(&[sans]), apres_tbs])
}
