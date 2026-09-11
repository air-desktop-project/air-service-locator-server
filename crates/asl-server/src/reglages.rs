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
    /// La cadence de maintien qu'on demande aux daemons, en secondes.
    pub keepalive_s: u64,
    /// La rétention du journal, en jours (C18).
    pub retention_jours: u64,
    /// Ce que l'annuaire exige d'un appareil qui s'enrôle.
    ///
    /// **IL N'Y A PAS DE DÉFAUT, ET C'EST LE SEUL RÉGLAGE DANS CE CAS.**
    ///
    /// `protocole.md` §2.1 tranche : la v1 refuse un enrôlement sans
    /// attestation de plate-forme. **Mais la vérification n'est pas écrite** —
    /// App Attest et Play Integrity demandent les racines d'Apple et de Google,
    /// du CBOR et une chaîne à valider. Exiger l'attestation aujourd'hui, c'est
    /// donc refuser TOUS les enrôlements.
    ///
    /// Les deux postures sont défendables et aucune ne peut être le défaut :
    /// `exigee` livrerait un annuaire qui ne crée aucun compte, `facultative`
    /// livrerait en silence la posture faible. **L'exploitant dit laquelle il
    /// tient**, et l'annuaire ne démarre pas tant qu'il ne l'a pas dit.
    pub politique: asl_auth::Politique,
    /// De quoi vérifier une attestation App Attest, si l'exploitant l'a fournie.
    ///
    /// # POURQUOI OPTIONNEL, ET CE QUE SON ABSENCE VEUT DIRE
    ///
    /// Vérifier une attestation d'Apple demande deux choses que seul
    /// l'exploitant connaît : l'**identifiant de l'app** (`ABCDE12345.ch.narro.app`),
    /// dont l'empreinte doit égaler le `rpIdHash`, et l'**environnement**
    /// attendu — production, ou développement. La racine d'Apple, elle, est la
    /// même pour tous et vit dans `asl_apple::RACINE_APPLE`.
    ///
    /// **Sans ces deux réglages, aucune attestation Apple ne peut être
    /// vérifiée** : un compte qui en déclare une est alors refusé, faute de quoi
    /// la comparer. Un annuaire `facultative` sans configuration Apple crée donc
    /// des comptes sans attestation, et refuse ceux qui en présentent une.
    pub apple: Option<ReglageApple>,
}

/// De quoi vérifier une attestation Apple App Attest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReglageApple {
    /// L'identifiant de l'app : `<équipe>.<bundle>`.
    pub identifiant_app: String,
    /// L'environnement attendu.
    pub environnement: asl_apple::Environnement,
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
    /// `--attestation` a reçu autre chose que `exigee` ou `facultative`.
    AttestationInconnue(String),
    /// `--apple-environnement` a reçu autre chose que `production` ou
    /// `developpement`.
    EnvironnementInconnu(String),
    /// `--apple-app` et `--apple-environnement` ne vont pas l'un sans l'autre.
    AppleIncomplet,
}

impl core::fmt::Display for Faute {
    fn fmt(&self, sortie: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Inconnu(quoi) => write!(sortie, "drapeau inconnu : {quoi}"),
            Self::SansValeur(quoi) => write!(sortie, "{quoi} attend une valeur"),
            Self::AttestationInconnue(quoi) => {
                write!(
                    sortie,
                    "--attestation attend `exigee` ou `facultative`, et non « {quoi} »"
                )
            }
            Self::PasUnNombre { drapeau, donnee } => {
                write!(
                    sortie,
                    "{drapeau} : « {donnee} » n'est pas un nombre valide"
                )
            }
            Self::EnvironnementInconnu(quoi) => write!(
                sortie,
                "--apple-environnement attend `production` ou `developpement`, et non « {quoi} »"
            ),
            Self::AppleIncomplet => sortie.write_str(
                "--apple-app et --apple-environnement se donnent ensemble, ou pas du tout",
            ),
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
  --inactivite <secondes> l'inactivité annoncée aux pairs   (défaut : 30)
  --keepalive  <secondes> la cadence de maintien demandée   (défaut : 10)
  --retention  <jours>    la rétention du journal           (défaut : 90)
  --attestation <exigee|facultative>                        (obligatoire)
  --apple-app  <id>       l'identifiant de l'app Apple      (avec l'env.)
  --apple-environnement <production|developpement>          (avec l'app)

`--attestation` N'A PAS DE DÉFAUT, ET C'EST DÉLIBÉRÉ. La vérification de
l'attestation de plate-forme n'est pas écrite : `exigee` refuse donc TOUT
enrôlement d'appareil, et `facultative` laisse n'importe qui créer un compte.
Aucune des deux ne peut être choisie à votre place.

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
        // Trente secondes, soit trois keepalives de dix manqués — et c'est
        // aussi ce que le chemin tolère : `bancs/nat/README.md` a mesuré 28 s
        // tenus, 30 s perdus, LE MÊME CHIFFRE en IPv4 et en IPv6. La borne
        // n'est donc pas la traduction d'adresses, c'est le pare-feu à état de
        // la box — et quarante-cinq secondes promettaient une tolérance que le
        // réseau ne rend pas.
        //
        // **ELLE DOIT S'ACCORDER AVEC LE BAIL QUE L'ANNUAIRE ACCORDE**
        // (`asl_loop_tokio::h3::BAIL_PAR_DEFAUT`) : celle-ci ferme la CONNEXION,
        // celle-là fait tomber le BAIL, et `protocole.md` §1.2 promet que les
        // deux sont la même chose. Les laisser diverger ouvrirait une fenêtre où
        // un daemon est désannoncé sans être déconnecté, donc sans rien
        // apprendre.
        let mut inactivite_s = 30_u64;
        let mut retention_jours = 90_u64;
        // Dix secondes, mesurées : `bancs/nat/README.md` a trouvé qu'un chemin
        // résidentiel meurt entre 28 et 30 s de silence. À quinze, **un SEUL
        // maintien perdu faisait trente secondes de silence**, c'est-à-dire
        // exactement la borne : sur un lien qui perd un paquet de temps en
        // temps, l'annonce tombait sans que rien n'ait mal tourné. À dix, il en
        // faut deux d'affilée.
        let mut keepalive_s = 10_u64;
        let mut politique = None;
        let mut apple_app: Option<String> = None;
        let mut apple_env: Option<asl_apple::Environnement> = None;

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
                "--keepalive" => keepalive_s = nombre(drapeau, valeur()?.as_ref())?,
                "--retention" => retention_jours = nombre(drapeau, valeur()?.as_ref())?,
                "--attestation" => {
                    let donnee = valeur()?;
                    politique = Some(match donnee.as_ref() {
                        "exigee" => asl_auth::Politique::AttestationExigee,
                        "facultative" => asl_auth::Politique::AttestationFacultative,
                        autre => return Err(Faute::AttestationInconnue(autre.to_owned())),
                    });
                }
                "--apple-app" => apple_app = Some(valeur()?.as_ref().to_owned()),
                "--apple-environnement" => {
                    let donnee = valeur()?;
                    apple_env = Some(match donnee.as_ref() {
                        "production" => asl_apple::Environnement::Production,
                        "developpement" => asl_apple::Environnement::Developpement,
                        autre => return Err(Faute::EnvironnementInconnu(autre.to_owned())),
                    });
                }
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
            keepalive_s,
            retention_jours,
            politique: politique.ok_or(Faute::Manque("--attestation"))?,
            // **LES DEUX VONT ENSEMBLE, OU PAS DU TOUT.** Une app sans
            // environnement ne dit pas où l'attester ; un environnement sans app
            // ne dit pas quoi comparer au `rpIdHash`.
            apple: match (apple_app, apple_env) {
                (Some(identifiant_app), Some(environnement)) => Some(ReglageApple {
                    identifiant_app,
                    environnement,
                }),
                (None, None) => None,
                _ => return Err(Faute::AppleIncomplet),
            },
        })
    }

    /// L'inactivité en microsecondes, comme la boucle la veut.
    #[must_use]
    pub const fn inactivite_us(&self) -> u64 {
        self.inactivite_s.saturating_mul(1_000_000)
    }

    /// Le bail qu'on accordera aux annonces.
    ///
    /// # LES DEUX INACTIVITÉS NE PEUVENT PLUS DIVERGER
    ///
    /// Il y en a deux dans ce produit : `--inactivite` ferme la CONNEXION, et le
    /// bail fait tomber l'ANNONCE. `protocole.md` §1.2 promet que les deux sont
    /// la même chose — « la connexion EST le bail ». Les laisser se régler
    /// séparément ouvrirait une fenêtre où un daemon est désannoncé sans être
    /// déconnecté, donc sans rien apprendre.
    ///
    /// **Ici, le bail est DÉRIVÉ de l'inactivité**, et non posé à côté d'elle.
    ///
    /// # Erreurs
    ///
    /// [`asl_proto::Erreur`] si la cadence est nulle, trop longue, ou si
    /// l'inactivité vaut moins de deux cadences — auquel cas la première perte
    /// de paquet tuerait un daemon parfaitement sain.
    pub fn bail(&self) -> Result<asl_proto::Bail, asl_proto::Erreur> {
        let borne = |secondes: u64| u16::try_from(secondes).unwrap_or(u16::MAX);
        asl_proto::Bail::nouveau(borne(self.keepalive_s), borne(self.inactivite_s))
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
    use super::{Faute, ReglageApple, Reglages};

    /// Les quatre réglages obligatoires, et rien d'autre.
    fn minimum() -> Vec<String> {
        [
            "--entrepot",
            "/a",
            "--certificat",
            "/b",
            "--cle",
            "/c",
            "--attestation",
            "facultative",
        ]
        .iter()
        .map(|quoi| (*quoi).to_owned())
        .collect()
    }

    fn avec(ajouts: &[&str]) -> Vec<String> {
        let mut args = minimum();
        args.extend(ajouts.iter().map(|quoi| (*quoi).to_owned()));
        args
    }

    #[test]
    fn sans_reglage_apple_il_n_y_en_a_pas() {
        let lus = Reglages::depuis(minimum()).expect("le minimum suffit");
        assert_eq!(lus.apple, None);
    }

    #[test]
    fn les_deux_reglages_apple_forment_une_configuration() {
        let lus = Reglages::depuis(avec(&[
            "--apple-app",
            "ABCDE12345.ch.narro.essai",
            "--apple-environnement",
            "production",
        ]))
        .expect("une configuration complète");
        assert_eq!(
            lus.apple,
            Some(ReglageApple {
                identifiant_app: "ABCDE12345.ch.narro.essai".to_owned(),
                environnement: asl_apple::Environnement::Production,
            })
        );

        // Et `developpement` aussi.
        let dev = Reglages::depuis(avec(&[
            "--apple-app",
            "ABCDE12345.ch.narro.essai",
            "--apple-environnement",
            "developpement",
        ]))
        .expect("développement est un environnement");
        assert_eq!(
            dev.apple.map(|a| a.environnement),
            Some(asl_apple::Environnement::Developpement)
        );
    }

    #[test]
    fn une_app_sans_environnement_ou_l_inverse_est_refusee() {
        assert_eq!(
            Reglages::depuis(avec(&["--apple-app", "X.y"])).map(|_| ()),
            Err(Faute::AppleIncomplet)
        );
        assert_eq!(
            Reglages::depuis(avec(&["--apple-environnement", "production"])).map(|_| ()),
            Err(Faute::AppleIncomplet)
        );
    }

    #[test]
    fn un_environnement_inconnu_est_refuse() {
        let faute = Reglages::depuis(avec(&[
            "--apple-app",
            "X.y",
            "--apple-environnement",
            "bac-a-sable",
        ]))
        .map(|_| ());
        assert_eq!(
            faute,
            Err(Faute::EnvironnementInconnu("bac-a-sable".to_owned()))
        );
        // Et la faute a sa phrase.
        assert!(
            !Faute::EnvironnementInconnu("x".to_owned())
                .to_string()
                .is_empty()
        );
        assert!(!Faute::AppleIncomplet.to_string().is_empty());
    }

    #[test]
    fn l_attestation_n_a_pas_de_defaut() {
        // **AUCUNE DES DEUX POSTURES NE PEUT ÊTRE CHOISIE À LA PLACE DE
        // L'EXPLOITANT** : `exigee` livre un annuaire qui ne crée aucun compte,
        // `facultative` livre en silence la posture faible.
        let sans: Vec<String> = ["--entrepot", "/a", "--certificat", "/b", "--cle", "/c"]
            .iter()
            .map(|quoi| (*quoi).to_owned())
            .collect();
        assert_eq!(
            Reglages::depuis(sans).map(|_| ()),
            Err(Faute::Manque("--attestation"))
        );
    }

    #[test]
    fn les_deux_postures_se_lisent_et_les_autres_mots_sont_refuses() {
        for (mot, attendue) in [
            ("exigee", asl_auth::Politique::AttestationExigee),
            ("facultative", asl_auth::Politique::AttestationFacultative),
        ] {
            let mut arguments = minimum();
            arguments.pop();
            arguments.push(mot.to_owned());
            let lus = Reglages::depuis(arguments).expect("une posture connue");
            assert_eq!(lus.politique, attendue, "{mot}");
        }

        let mut arguments = minimum();
        arguments.pop();
        arguments.push("peut-etre".to_owned());
        assert_eq!(
            Reglages::depuis(arguments).map(|_| ()),
            Err(Faute::AttestationInconnue("peut-etre".to_owned()))
        );
        // Et la faute se dit à l'humain qui l'a commise.
        assert!(
            Faute::AttestationInconnue("peut-etre".to_owned())
                .to_string()
                .contains("facultative")
        );
    }

    #[test]
    fn le_minimum_suffit_et_les_defauts_sont_ceux_annonces() {
        let lus = Reglages::depuis(minimum()).expect("le minimum suffit");
        assert_eq!(lus.port, asl_proto::PORT_PAR_DEFAUT);
        assert_eq!(lus.connexions_max, 1024);
        assert_eq!(lus.inactivite_s, 30);
        assert_eq!(lus.keepalive_s, 10);
        let bail = lus.bail().expect("dix et trente forment un bail");
        assert_eq!(bail.keepalive_secondes(), 10);
        assert_eq!(bail.inactivite_secondes(), 30);
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
