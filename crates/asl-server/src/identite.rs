//! La clé d'identité d'une racine : la lire, lire celle de l'autre, en frapper
//! une neuve.
//!
//! # LE FORMAT EST CELUI QU'`asl-cle` SAIT LIRE, ET RIEN D'AUTRE
//!
//! `asl_cle::CleSecrete::depuis_entropie` prend trente-deux octets ;
//! `asl_cle::ClePublique::depuis_octets` en prend trente-deux aussi. Les
//! fichiers portent donc **exactement ces octets, bruts** — ni PEM, ni
//! PKCS#8, ni hexadécimal. Un enrobage demanderait un décodeur de plus dans un
//! binaire qui n'en a pas, pour une clé que personne ne lit à l'œil : ce qu'on
//! recopie d'une racine à l'autre est un FICHIER, `<chemin>.pub`, et ce qu'on
//! vérifie à l'œil est l'identifiant `n-…` que le démarrage imprime.
//!
//! **Un fichier qui ne fait pas trente-deux octets n'est pas une clé**, et il
//! est refusé en le disant — jamais tronqué, jamais complété.
//!
//! # LA CLÉ PRIVÉE S'ÉCRIT EN 0600, ET NE S'ÉCRASE PAS
//!
//! `--new-identity-key` refuse un fichier qui existe : une clé d'identité est
//! ce que l'autre racine épingle, et l'écraser par mégarde ferait deux racines
//! qui ne se reconnaissent plus. Effacer est un geste à faire à la main.

use std::io;
use std::path::Path;

use asl_cle::{CLE_PUBLIQUE_OCTETS, CLE_SECRETE_OCTETS, ClePublique, CleSecrete};

/// Ce qui empêche de lire ou d'écrire une clé.
#[derive(Debug)]
pub enum Faute {
    /// Le fichier ne se lit ou ne s'écrit pas.
    Fichier {
        /// Lequel.
        chemin: String,
        /// Pourquoi.
        cause: io::Error,
    },
    /// Le fichier n'a pas la taille d'une clé.
    Taille {
        /// Lequel.
        chemin: String,
        /// Ce qu'il fait.
        obtenue: usize,
        /// Ce qu'une clé fait.
        attendue: usize,
    },
    /// Les octets ne forment pas une clé publique Ed25519.
    ClePubliqueInvalide {
        /// Lequel.
        chemin: String,
    },
    /// Le fichier existe déjà, et une clé d'identité ne s'écrase pas.
    Existe {
        /// Lequel.
        chemin: String,
    },
    /// Le noyau n'a pas donné d'entropie.
    Entropie(io::Error),
}

impl core::fmt::Display for Faute {
    fn fmt(&self, sortie: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Fichier { chemin, cause } => write!(sortie, "{chemin} : {cause}"),
            Self::Taille {
                chemin,
                obtenue,
                attendue,
            } => write!(
                sortie,
                "{chemin} fait {obtenue} octets, et une clé en fait {attendue} — bruts, ni PEM ni hexadécimal"
            ),
            Self::ClePubliqueInvalide { chemin } => {
                write!(sortie, "{chemin} ne porte pas un point valide d'Ed25519")
            }
            Self::Existe { chemin } => write!(
                sortie,
                "{chemin} existe déjà : une clé d'identité ne s'écrase pas, effacez-la d'abord si c'est voulu"
            ),
            Self::Entropie(cause) => write!(sortie, "le noyau n'a pas donné d'entropie : {cause}"),
        }
    }
}

impl std::error::Error for Faute {}

/// Lit exactement `N` octets de ce fichier.
fn lire_octets<const N: usize>(chemin: &Path) -> Result<[u8; N], Faute> {
    let nom = chemin.display().to_string();
    let lus = std::fs::read(chemin).map_err(|cause| Faute::Fichier {
        chemin: nom.clone(),
        cause,
    })?;
    let octets: [u8; N] = lus.as_slice().try_into().map_err(|_| Faute::Taille {
        chemin: nom,
        obtenue: lus.len(),
        attendue: N,
    })?;
    Ok(octets)
}

/// Lit la clé d'identité de cette racine — trente-deux octets bruts.
///
/// # Errors
///
/// [`Faute::Fichier`], [`Faute::Taille`].
pub fn lire_secrete(chemin: &Path) -> Result<CleSecrete, Faute> {
    Ok(CleSecrete::depuis_entropie(lire_octets::<
        CLE_SECRETE_OCTETS,
    >(chemin)?))
}

/// Lit la clé d'identité publique de l'autre racine — trente-deux octets
/// bruts, et un point valide.
///
/// # Errors
///
/// [`Faute::Fichier`], [`Faute::Taille`], [`Faute::ClePubliqueInvalide`].
pub fn lire_publique(chemin: &Path) -> Result<ClePublique, Faute> {
    ClePublique::depuis_octets(lire_octets::<CLE_PUBLIQUE_OCTETS>(chemin)?).map_err(|_| {
        Faute::ClePubliqueInvalide {
            chemin: chemin.display().to_string(),
        }
    })
}

/// Frappe une clé d'identité neuve : la privée dans `chemin` (0600), la
/// publique dans `<chemin>.pub`, et rend la publique.
///
/// **L'entropie vient du noyau** (`entropie`), comme pour un défi : une clé
/// tirée d'ailleurs serait une clé qu'on devine.
///
/// # Errors
///
/// [`Faute::Existe`] si l'un des deux fichiers existe, [`Faute::Entropie`],
/// [`Faute::Fichier`].
pub fn generer(chemin: &Path) -> Result<ClePublique, Faute> {
    let publique_chemin = chemin_public(chemin);
    for fichier in [chemin, publique_chemin.as_path()] {
        if fichier.exists() {
            return Err(Faute::Existe {
                chemin: fichier.display().to_string(),
            });
        }
    }
    let graine = crate::entropie::un_defi().map_err(Faute::Entropie)?;
    let secrete = CleSecrete::depuis_entropie(*graine.octets());
    let publique = secrete.publique();

    ecrire(chemin, graine.octets(), 0o600)?;
    ecrire(&publique_chemin, &publique.octets(), 0o644)?;
    Ok(publique)
}

/// Écrit ces octets dans un fichier NEUF, avec ces droits.
///
/// **`create_new`, et non `create`** : entre le `exists` d'au-dessus et
/// l'écriture, quelqu'un a pu poser le fichier — et une clé ne s'écrase pas.
fn ecrire(chemin: &Path, octets: &[u8], droits: u32) -> Result<(), Faute> {
    use std::io::Write as _;
    let faute = |cause: io::Error| {
        if cause.kind() == io::ErrorKind::AlreadyExists {
            Faute::Existe {
                chemin: chemin.display().to_string(),
            }
        } else {
            Faute::Fichier {
                chemin: chemin.display().to_string(),
                cause,
            }
        }
    };
    let mut ouverture = std::fs::OpenOptions::new();
    ouverture.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        ouverture.mode(droits);
    }
    #[cfg(not(unix))]
    {
        let _ = droits;
    }
    let mut fichier = ouverture.open(chemin).map_err(faute)?;
    fichier.write_all(octets).map_err(faute)?;
    fichier.sync_all().map_err(faute)
}

/// Le chemin de la clé publique frappée à côté de cette clé privée.
#[must_use]
pub fn chemin_public(chemin: &Path) -> std::path::PathBuf {
    chemin.with_extension(match chemin.extension() {
        Some(extension) => format!("{}.pub", extension.to_string_lossy()),
        None => "pub".to_owned(),
    })
}

/// Les octets d'une clé publique, en hexadécimal — pour l'œil et le journal.
#[must_use]
pub fn en_hexadecimal(octets: &[u8]) -> String {
    octets.iter().map(|octet| format!("{octet:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{Faute, chemin_public, en_hexadecimal, generer, lire_publique, lire_secrete};

    fn temporaire(quoi: &str) -> std::path::PathBuf {
        let chemin =
            std::env::temp_dir().join(format!("asl-identite-{}-{quoi}", std::process::id()));
        let _ = std::fs::remove_file(&chemin);
        let _ = std::fs::remove_file(chemin_public(&chemin));
        chemin
    }

    #[test]
    fn une_cle_frappee_se_relit_des_deux_cotes_et_ne_s_ecrase_pas() {
        let chemin = temporaire("neuve");
        let publique = generer(&chemin).expect("frappée");
        assert_eq!(
            lire_secrete(&chemin)
                .expect("la privée se relit")
                .publique(),
            publique
        );
        assert_eq!(
            lire_publique(&chemin_public(&chemin)).expect("la publique se relit"),
            publique
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let droits = std::fs::metadata(&chemin).expect("là").permissions().mode() & 0o777;
            assert_eq!(
                droits, 0o600,
                "la clé privée n'est lisible que de son propriétaire"
            );
        }
        // Une seconde frappe refuse : la clé est ce que l'autre racine épingle.
        assert!(matches!(generer(&chemin), Err(Faute::Existe { .. })));
        let _ = std::fs::remove_file(&chemin);
        // Et la publique seule suffit à refuser aussi.
        assert!(matches!(generer(&chemin), Err(Faute::Existe { .. })));
        let _ = std::fs::remove_file(chemin_public(&chemin));
    }

    #[test]
    fn un_fichier_qui_n_a_pas_la_taille_d_une_cle_est_refuse_en_le_disant() {
        let chemin = temporaire("courte");
        std::fs::write(&chemin, [0_u8; 31]).expect("écrit");
        let faute = lire_secrete(&chemin).expect_err("refusée");
        assert!(matches!(
            faute,
            Faute::Taille {
                obtenue: 31,
                attendue: 32,
                ..
            }
        ));
        assert!(faute.to_string().contains("31 octets"));
        // Trente-deux octets qui ne sont pas un point : refusés comme publique,
        // mais toute graine est une privée.
        std::fs::write(&chemin, [0x02_u8; 32]).expect("écrit");
        assert!(matches!(
            lire_publique(&chemin),
            Err(Faute::ClePubliqueInvalide { .. })
        ));
        assert!(lire_secrete(&chemin).is_ok());
        let _ = std::fs::remove_file(&chemin);
        // Un fichier absent se dit aussi.
        assert!(matches!(lire_secrete(&chemin), Err(Faute::Fichier { .. })));
    }

    #[test]
    fn le_chemin_public_suit_la_privee_et_l_hexadecimal_est_lisible() {
        assert_eq!(
            chemin_public(std::path::Path::new("/etc/asl-server/identite")),
            std::path::PathBuf::from("/etc/asl-server/identite.pub")
        );
        assert_eq!(
            chemin_public(std::path::Path::new("/etc/asl-server/identite.key")),
            std::path::PathBuf::from("/etc/asl-server/identite.key.pub")
        );
        assert_eq!(en_hexadecimal(&[0x00, 0xAB, 0xFF]), "00abff");
        for faute in [
            Faute::Existe {
                chemin: "x".to_owned(),
            },
            Faute::ClePubliqueInvalide {
                chemin: "x".to_owned(),
            },
            Faute::Entropie(std::io::Error::other("x")),
            Faute::Fichier {
                chemin: "x".to_owned(),
                cause: std::io::Error::other("x"),
            },
        ] {
            assert!(!faute.to_string().is_empty());
        }
    }
}
