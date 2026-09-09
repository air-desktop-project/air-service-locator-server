//! Ce qu'on lit sur la ligne de commande.
//!
//! # POURQUOI PAS DE BIBLIOTHÈQUE D'ARGUMENTS
//!
//! Il y a six réglages, tous de la forme `--nom valeur`. Une bibliothèque
//! apporterait une grammaire complète — sous-commandes, formes courtes,
//! complétion — dont rien ici ne se sert, et une vingtaine d'unités dans un
//! graphe que C4 borne à cent vingt.
//!
//! Le jour où il y aura des sous-commandes, la question se reposera. Elle ne se
//! pose pas aujourd'hui.
//!
//! # ET POURQUOI PAS DE FICHIER DE CONFIGURATION
//!
//! **Parce qu'un fichier de configuration est un second endroit où mettre la
//! vérité.** Un service lancé par systemd a déjà une unité qui porte sa ligne de
//! commande ; y ajouter un fichier ferait deux sources, et l'on chercherait
//! toujours dans la mauvaise.
//!
//! # LA LECTURE NE FAIT AUCUNE ENTRÉE-SORTIE, ET C'EST CE QUI LA REND ÉPROUVABLE
//!
//! [`Reglages::depuis`] prend une suite de chaînes, pas `std::env::args`. Un
//! essai lui donne donc ce qu'il veut, sans lancer de processus.

use std::path::PathBuf;

use asl_proto::PORT_PAR_DEFAUT;

/// Ce qu'un annuaire a besoin de savoir pour démarrer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reglages {
    /// Le fichier de l'entrepôt.
    pub entrepot: PathBuf,
    /// La chaîne de certificats, en PEM.
    pub certificat: PathBuf,
    /// La clé privée, en PEM.
    pub cle: PathBuf,
    /// Le port d'écoute.
    pub port: u16,
    /// Combien de connexions vivent en même temps, au plus.
    pub connexions_max: usize,
    /// L'inactivité annoncée aux pairs, en secondes.
    pub inactivite_s: u64,
    /// La rétention du journal, en jours (C18).
    pub retention_jours: u64,
}

/// Ce qui empêche de lire les réglages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Faute {
    /// Un drapeau qu'on ne connaît pas.
    Inconnu(String),
    /// Un drapeau sans sa valeur.
    SansValeur(String),
    /// Une valeur qui n'est pas un nombre, ou qui sort des bornes.
    PasUnNombre {
        /// Le drapeau concerné.
        drapeau: String,
        /// Ce qui a été donné.
        donnee: String,
    },
    /// Un réglage obligatoire qui manque.
    Manque(&'static str),
}

impl core::fmt::Display for Faute {
    fn fmt(&self, sortie: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Inconnu(quoi) => write!(sortie, "drapeau inconnu : {quoi}"),
            Self::SansValeur(quoi) => write!(sortie, "{quoi} attend une valeur"),
            Self::PasUnNombre { drapeau, donnee } => {
                write!(
                    sortie,
                    "{drapeau} : « {donnee} » n'est pas un nombre valide"
                )
            }
            Self::Manque(quoi) => write!(sortie, "il manque {quoi}"),
        }
    }
}

impl std::error::Error for Faute {}

/// Ce qu'on affiche quand on ne sait pas quoi faire.
pub const USAGE: &str = "\
asl-server — un annuaire de services air-service-locator.

  --entrepot   <chemin>   le fichier de l'entrepôt          (obligatoire)
  --certificat <chemin>   la chaîne de certificats, en PEM  (obligatoire)
  --cle        <chemin>   la clé privée, en PEM             (obligatoire)
  --port       <nombre>   le port d'écoute                  (défaut : 6630)
  --connexions <nombre>   connexions simultanées au plus    (défaut : 1024)
  --inactivite <secondes> l'inactivité annoncée aux pairs   (défaut : 45)
  --retention  <jours>    la rétention du journal           (défaut : 90)

L'écoute est en DOUBLE PILE : IPv6 d'abord, IPv4 accepté sur la même socket.
L'annuaire REFUSE de démarrer en root — il n'a besoin d'aucun privilège.

  scripts/ca.sh racine
  scripts/ca.sh serveur nitrogen nitrogen.air-desktop.org 2001:41d0:20a:900::1dd4
";

impl Reglages {
    /// Lit les réglages depuis ces arguments, le nom du programme exclu.
    ///
    /// # Errors
    ///
    /// [`Faute`] si un drapeau est inconnu, sans valeur, mal formé, ou si un
    /// réglage obligatoire manque.
    pub fn depuis<I, S>(arguments: I) -> Result<Self, Faute>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut entrepot = None;
        let mut certificat = None;
        let mut cle = None;
        let mut port = PORT_PAR_DEFAUT;
        // Mille vingt-quatre connexions : quelques dizaines de mébioctets de
        // fenêtres de réassemblage. C'est une borne de MÉMOIRE, et elle se règle.
        let mut connexions_max = 1024_usize;
        // Quarante-cinq secondes, soit trois keepalives de quinze manqués.
        // **CE N'EST PAS UNE CONCLUSION** : `modele.md` demande de la mesurer
        // sur de vrais NAT.
        let mut inactivite_s = 45_u64;
        let mut retention_jours = 90_u64;

        let mut arguments = arguments.into_iter();
        while let Some(drapeau) = arguments.next() {
            let drapeau = drapeau.as_ref();
            let mut valeur = || {
                arguments
                    .next()
                    .ok_or_else(|| Faute::SansValeur(drapeau.to_owned()))
            };
            // `valeur` emprunte `arguments` : on la consomme tout de suite,
            // branche par branche, plutôt que de la garder vivante.
            match drapeau {
                "--entrepot" => entrepot = Some(PathBuf::from(valeur()?.as_ref())),
                "--certificat" => certificat = Some(PathBuf::from(valeur()?.as_ref())),
                "--cle" => cle = Some(PathBuf::from(valeur()?.as_ref())),
                "--port" => port = nombre(drapeau, valeur()?.as_ref())?,
                "--connexions" => connexions_max = nombre(drapeau, valeur()?.as_ref())?,
                "--inactivite" => inactivite_s = nombre(drapeau, valeur()?.as_ref())?,
                "--retention" => retention_jours = nombre(drapeau, valeur()?.as_ref())?,
                autre => return Err(Faute::Inconnu(autre.to_owned())),
            }
        }

        Ok(Self {
            entrepot: entrepot.ok_or(Faute::Manque("--entrepot"))?,
            certificat: certificat.ok_or(Faute::Manque("--certificat"))?,
            cle: cle.ok_or(Faute::Manque("--cle"))?,
            port,
            connexions_max,
            inactivite_s,
            retention_jours,
        })
    }

    /// L'inactivité en microsecondes, comme la boucle la veut.
    #[must_use]
    pub const fn inactivite_us(&self) -> u64 {
        self.inactivite_s.saturating_mul(1_000_000)
    }

    /// La rétention en millisecondes, comme le journal la compte.
    #[must_use]
    pub const fn retention_ms(&self) -> u64 {
        self.retention_jours.saturating_mul(24 * 60 * 60 * 1_000)
    }
}

/// Lit un nombre, ou dit lequel n'en était pas un.
fn nombre<T: core::str::FromStr>(drapeau: &str, donnee: &str) -> Result<T, Faute> {
    donnee.parse().map_err(|_| Faute::PasUnNombre {
        drapeau: drapeau.to_owned(),
        donnee: donnee.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::{Faute, Reglages};

    /// Les trois réglages obligatoires, et rien d'autre.
    fn minimum() -> Vec<String> {
        ["--entrepot", "/a", "--certificat", "/b", "--cle", "/c"]
            .iter()
            .map(|quoi| (*quoi).to_owned())
            .collect()
    }

    #[test]
    fn le_minimum_suffit_et_les_defauts_sont_ceux_annonces() {
        let lus = Reglages::depuis(minimum()).expect("le minimum suffit");
        assert_eq!(lus.port, asl_proto::PORT_PAR_DEFAUT);
        assert_eq!(lus.connexions_max, 1024);
        assert_eq!(lus.inactivite_s, 45);
        assert_eq!(lus.retention_jours, 90);
    }

    #[test]
    fn chacun_des_trois_obligatoires_manque_avec_son_nom() {
        for (retire, attendu) in [(0_usize, "--entrepot"), (2, "--certificat"), (4, "--cle")] {
            let mut sans = minimum();
            sans.drain(retire..retire + 2);
            assert_eq!(
                Reglages::depuis(sans),
                Err(Faute::Manque(attendu)),
                "en retirant {attendu}"
            );
        }
    }

    #[test]
    fn un_drapeau_inconnu_est_nomme() {
        let mut avec = minimum();
        avec.push("--jesaispas".to_owned());
        assert_eq!(
            Reglages::depuis(avec),
            Err(Faute::Inconnu("--jesaispas".to_owned()))
        );
    }

    #[test]
    fn un_drapeau_sans_sa_valeur_est_nomme() {
        let mut avec = minimum();
        avec.push("--port".to_owned());
        assert_eq!(
            Reglages::depuis(avec),
            Err(Faute::SansValeur("--port".to_owned()))
        );
    }

    #[test]
    fn une_valeur_qui_n_est_pas_un_nombre_dit_laquelle() {
        let mut avec = minimum();
        avec.extend(["--port".to_owned(), "six-mille".to_owned()]);
        assert_eq!(
            Reglages::depuis(avec),
            Err(Faute::PasUnNombre {
                drapeau: "--port".to_owned(),
                donnee: "six-mille".to_owned(),
            })
        );
    }

    #[test]
    fn un_port_hors_bornes_est_refuse() {
        // **`65536` N'EST PAS UN PORT**, et le refus vient du type : `u16` ne le
        // contient pas. Sans lui, la valeur serait tronquée à zéro.
        let mut avec = minimum();
        avec.extend(["--port".to_owned(), "65536".to_owned()]);
        assert!(matches!(
            Reglages::depuis(avec),
            Err(Faute::PasUnNombre { .. })
        ));
    }

    #[test]
    fn les_conversions_de_temps_sont_celles_qu_on_croit() {
        let mut avec = minimum();
        avec.extend([
            "--inactivite".to_owned(),
            "45".to_owned(),
            "--retention".to_owned(),
            "90".to_owned(),
        ]);
        let lus = Reglages::depuis(avec).expect("lisible");
        assert_eq!(lus.inactivite_us(), 45_000_000);
        assert_eq!(lus.retention_ms(), 90 * 24 * 60 * 60 * 1_000);
    }

    #[test]
    fn des_valeurs_absurdes_ne_debordent_pas() {
        let mut avec = minimum();
        avec.extend([
            "--inactivite".to_owned(),
            u64::MAX.to_string(),
            "--retention".to_owned(),
            u64::MAX.to_string(),
        ]);
        let lus = Reglages::depuis(avec).expect("lisible");
        assert_eq!(lus.inactivite_us(), u64::MAX, "la saturation, pas le tour");
        assert_eq!(lus.retention_ms(), u64::MAX);
    }

    #[test]
    fn chaque_faute_se_lit_en_francais() {
        for faute in [
            Faute::Inconnu("--x".to_owned()),
            Faute::SansValeur("--port".to_owned()),
            Faute::PasUnNombre {
                drapeau: "--port".to_owned(),
                donnee: "x".to_owned(),
            },
            Faute::Manque("--cle"),
        ] {
            let dit = format!("{faute}");
            assert!(!dit.is_empty(), "{faute:?}");
        }
    }
}
