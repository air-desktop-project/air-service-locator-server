//! Les corps de l'API mobile : des octets vers des demandes, et retour.
//!
//! # CE MODULE N'A PAS SON PROPRE ANALYSEUR JSON, ET C'EST DÉLIBÉRÉ
//!
//! Il emprunte celui d'[`asl_proto::cadrage`] — même dialecte, mêmes blancs,
//! mêmes refus, mêmes fautes. **Deux analyseurs finissent par diverger**, et
//! c'est celui qu'on oublie de corriger qui accepte ce que l'autre refuse.
//!
//! # DEUX CORPS SEULEMENT, ET LES AUTRES SONT DES OCTETS BRUTS
//!
//! Les corps qui portent des CLÉS et des SIGNATURES ne passent pas par ici :
//! ils sont des champs de longueur fixe, sans cadrage, et `asl-session` les lit
//! directement. C'est l'argument d'`asl_cle::message_a_signer`, et il vaut aussi
//! pour le transport d'une preuve : un cadrage JSON demanderait un encodage des
//! octets de la signature, donc deux écritures possibles du même contenu — sur
//! un chemin cryptographique, trois occasions de se tromper pour zéro gain.
//!
//! Restent ceux qui portent des NOMS et des IDENTIFIANTS. Ceux-là se débogueront
//! avec `curl`, et JSON est ce qu'il faut pour cela.

use crate::Alias;
use asl_id::{Genre, Identifiant};
use asl_proto::Erreur;
use asl_proto::cadrage::Lecteur;

/// La longueur maximale d'un corps de cette API, en octets.
///
/// Le plus long tient dans deux cents octets : un nom de soixante-quatre, un
/// identifiant de vingt-huit, et de la ponctuation.
pub const CORPS_MAX: usize = 512;

/// La longueur maximale du nom d'une machine, en octets.
///
/// **Elle DOIT valoir `asl_registre::NOM_OCTETS_MAX`**, faute de quoi un nom
/// accepté ici serait refusé au rangement — une requête bien formée échouerait
/// en `500`. Les deux crates ne se connaissent pas ; c'est `asl-session`, qui
/// connaît les deux, qui tient l'égalité par une assertion de compilation.
///
/// **En OCTETS, et non en caractères.** `modele.md` §2.3 dit « 1 à 64
/// caractères » ; le stockage, lui, compte des octets, et un nom en japonais y
/// tient trois fois moins de caractères qu'un nom en anglais. C'est la borne du
/// stockage qui décide, parce que c'est elle qui peut refuser.
pub const NOM_MACHINE_MAX: usize = 64;

// ── Déclarer une machine ────────────────────────────────────────────────────

/// Les champs de `POST /v1/machines`, dans l'ordre où l'encodeur les écrit.
const CHAMPS_MACHINE: [&str; 2] = ["nom", "capacites"];

/// Les capacités demandées pour une machine.
///
/// **Rien n'est coché d'avance** (`docs/modele.md` §2.3) : les deux capacités ne
/// se cumulent pas par défaut, et le rayon de dégât dit pourquoi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Capacites {
    /// Les daemons de cette machine pourront-ils annoncer ?
    pub annonce: bool,
    /// Cette machine pourra-t-elle interroger l'annuaire ?
    pub lecture: bool,
}

/// Ce que `POST /v1/machines` demande.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclarationMachine<'a> {
    /// Le nom que l'humain lui donne.
    pub nom: &'a str,
    /// Ce qu'elle aura le droit de faire.
    pub capacites: Capacites,
}

impl<'a> DeclarationMachine<'a> {
    /// Décode la déclaration d'une machine.
    ///
    /// ```jsonc
    /// {"nom": "grenier", "capacites": ["annonce"]}
    /// ```
    ///
    /// **Le nom passe par [`Lecteur::texte_libre`]**, et non par le lecteur de
    /// chaînes ordinaire : c'est un texte d'affichage, il porte les accents et
    /// les idéogrammes de qui l'écrit. L'en-tête de `texte_libre` dit ce qui
    /// reste refusé, et pourquoi chaque refus.
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage, plus [`Erreur::NomVide`] et [`Erreur::NomTropLong`].
    pub fn decoder(octets: &'a [u8]) -> Result<Self, Erreur> {
        if octets.len() > CORPS_MAX {
            return Err(Erreur::MessageTropLong {
                obtenue: octets.len(),
            });
        }
        let mut lecteur = Lecteur::nouveau(octets);
        lecteur.attendre(b'{', "un objet")?;

        let mut vus = 0_u8;
        let mut nom: Option<&'a str> = None;
        let mut capacites = Capacites::default();

        loop {
            let position_cle = lecteur.position();
            let cle = lecteur.chaine()?;
            let rang = CHAMPS_MACHINE
                .iter()
                .position(|champ| *champ == cle)
                .ok_or(Erreur::ChampInconnu {
                    position: position_cle,
                })?;
            let bit = 1_u8 << rang;
            if vus & bit != 0 {
                return Err(Erreur::ChampEnDouble {
                    position: position_cle,
                });
            }
            vus |= bit;

            lecteur.attendre(b':', "deux-points")?;
            if rang == 0 {
                let texte = lecteur.texte_libre()?;
                if texte.is_empty() {
                    return Err(Erreur::NomVide);
                }
                if texte.len() > NOM_MACHINE_MAX {
                    return Err(Erreur::NomTropLong {
                        obtenue: texte.len(),
                    });
                }
                nom = Some(texte);
            } else {
                capacites = decoder_capacites(&mut lecteur)?;
            }

            lecteur.sauter_blancs();
            match lecteur.regarder() {
                Some(b',') => lecteur.avancer(),
                Some(b'}') => {
                    lecteur.avancer();
                    break;
                }
                _ => {
                    return Err(Erreur::JsonAttendu {
                        position: lecteur.position(),
                        attendu: "une virgule ou la fin de l'objet",
                    });
                }
            }
        }
        lecteur.fin()?;

        let nom = nom.ok_or(Erreur::ChampManquant {
            nom: CHAMPS_MACHINE[0],
        })?;
        if vus & 0b10 == 0 {
            return Err(Erreur::ChampManquant {
                nom: CHAMPS_MACHINE[1],
            });
        }
        Ok(Self { nom, capacites })
    }

    /// Encode cette déclaration, et rend le nombre d'octets écrits.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`].
    pub fn encoder(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        let mut ecrivain = asl_proto::cadrage::Ecrivain::nouveau(sortie);
        ecrivain.pousser(b"{\"nom\":\"");
        ecrivain.pousser(self.nom.as_bytes());
        ecrivain.pousser(b"\",\"capacites\":[");
        let mut deja = false;
        if self.capacites.annonce {
            ecrivain.pousser(b"\"annonce\"");
            deja = true;
        }
        if self.capacites.lecture {
            if deja {
                ecrivain.pousser(b",");
            }
            ecrivain.pousser(b"\"lecture\"");
        }
        ecrivain.pousser(b"]}");
        ecrivain.achever()
    }
}

/// Décode le tableau des capacités.
///
/// **Une capacité en double est refusée**, comme un champ en double : deux
/// lecteurs qui ne trancheraient pas pareil liraient deux demandes dans les
/// mêmes octets. Le tableau vide est ACCEPTÉ — une machine sans capacité est
/// une machine déclarée et qui ne peut rien, ce qui est un état légitime.
fn decoder_capacites(lecteur: &mut Lecteur<'_>) -> Result<Capacites, Erreur> {
    lecteur.attendre(b'[', "un tableau")?;
    let mut capacites = Capacites::default();

    lecteur.sauter_blancs();
    if lecteur.regarder() == Some(b']') {
        lecteur.avancer();
        return Ok(capacites);
    }

    loop {
        let position = lecteur.position();
        match lecteur.chaine()? {
            "annonce" if !capacites.annonce => capacites.annonce = true,
            "lecture" if !capacites.lecture => capacites.lecture = true,
            _ => return Err(Erreur::ChampInconnu { position }),
        }
        lecteur.sauter_blancs();
        match lecteur.regarder() {
            Some(b',') => lecteur.avancer(),
            Some(b']') => {
                lecteur.avancer();
                break;
            }
            _ => {
                return Err(Erreur::JsonAttendu {
                    position: lecteur.position(),
                    attendu: "une virgule ou la fin du tableau",
                });
            }
        }
    }
    Ok(capacites)
}

// ── Accorder une autorisation ───────────────────────────────────────────────

/// Les champs de `POST /v1/autorisations`.
const CHAMPS_AUTORISATION: [&str; 2] = ["a", "portee"];

/// Le mot qui désigne la portée la plus large.
const TOUT: &str = "tout";

/// Jusqu'où une autorisation demandée porte.
///
/// **C'est le troisième `Portee` du produit, et il faut dire pourquoi.**
/// `asl_auth::Portee` DÉCIDE, `asl_registre::Portee` RANGE, celui-ci LIT ce qui
/// arrive du réseau. Les fondre ferait dépendre une grammaire d'une machine à
/// états, ou l'inverse — c'est la même raison qui sépare déjà les deux autres.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Portee {
    /// Tout ce que le compte possède, présent et à venir.
    ToutLeCompte,
    /// Cette machine, et tous ses services.
    UneMachine(Identifiant),
    /// Ce service, et lui seul.
    UnService(Identifiant),
}

/// Ce que `POST /v1/autorisations` demande.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DemandeAutorisation {
    /// Le compte qui en bénéficiera.
    pub a: Identifiant,
    /// Jusqu'où elle porte.
    pub portee: Portee,
}

impl DemandeAutorisation {
    /// Décode une demande d'autorisation.
    ///
    /// ```jsonc
    /// {"a": "u-…", "portee": "tout"}
    /// {"a": "u-…", "portee": "m-…"}
    /// ```
    ///
    /// # LA PORTÉE EST UN SEUL CHAMP, ET SON GENRE LA DÉSIGNE
    ///
    /// Un objet `{"sorte":"machine","cible":"m-…"}` aurait rendu représentable
    /// `{"sorte":"machine","cible":"s-…"}` — une demande incohérente qu'il
    /// faudrait refuser à la main. Ici, le genre de l'identifiant EST la sorte :
    /// il n'y a pas deux champs à faire concorder. Et `tout` ne se confond avec
    /// aucun identifiant, qui en fait vingt-huit caractères.
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage, plus [`Erreur::IdentifiantInvalide`].
    pub fn decoder(octets: &[u8]) -> Result<Self, Erreur> {
        if octets.len() > CORPS_MAX {
            return Err(Erreur::MessageTropLong {
                obtenue: octets.len(),
            });
        }
        let mut lecteur = Lecteur::nouveau(octets);
        lecteur.attendre(b'{', "un objet")?;

        let mut vus = 0_u8;
        let mut a: Option<Identifiant> = None;
        let mut portee: Option<Portee> = None;

        loop {
            let position_cle = lecteur.position();
            let cle = lecteur.chaine()?;
            let rang = CHAMPS_AUTORISATION
                .iter()
                .position(|champ| *champ == cle)
                .ok_or(Erreur::ChampInconnu {
                    position: position_cle,
                })?;
            let bit = 1_u8 << rang;
            if vus & bit != 0 {
                return Err(Erreur::ChampEnDouble {
                    position: position_cle,
                });
            }
            vus |= bit;

            lecteur.attendre(b':', "deux-points")?;
            let position = lecteur.position();
            let texte = lecteur.chaine()?;
            if rang == 0 {
                a = Some(
                    Identifiant::analyser_genre(Genre::Utilisateur, texte)
                        .map_err(|_| Erreur::IdentifiantInvalide { position })?,
                );
            } else {
                portee = Some(lire_portee(texte, position)?);
            }

            lecteur.sauter_blancs();
            match lecteur.regarder() {
                Some(b',') => lecteur.avancer(),
                Some(b'}') => {
                    lecteur.avancer();
                    break;
                }
                _ => {
                    return Err(Erreur::JsonAttendu {
                        position: lecteur.position(),
                        attendu: "une virgule ou la fin de l'objet",
                    });
                }
            }
        }
        lecteur.fin()?;

        Ok(Self {
            a: a.ok_or(Erreur::ChampManquant {
                nom: CHAMPS_AUTORISATION[0],
            })?,
            portee: portee.ok_or(Erreur::ChampManquant {
                nom: CHAMPS_AUTORISATION[1],
            })?,
        })
    }

    /// Encode cette demande, et rend le nombre d'octets écrits.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`].
    pub fn encoder(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        let mut ecrivain = asl_proto::cadrage::Ecrivain::nouveau(sortie);
        ecrivain.pousser(b"{\"a\":\"");
        ecrivain.pousser(self.a.texte().as_str().as_bytes());
        ecrivain.pousser(b"\",\"portee\":\"");
        match self.portee {
            Portee::ToutLeCompte => ecrivain.pousser(TOUT.as_bytes()),
            Portee::UneMachine(quoi) | Portee::UnService(quoi) => {
                ecrivain.pousser(quoi.texte().as_str().as_bytes());
            }
        }
        ecrivain.pousser(b"\"}");
        ecrivain.achever()
    }
}

/// Lit une portée : le mot `tout`, ou un identifiant dont le genre la désigne.
fn lire_portee(texte: &str, position: usize) -> Result<Portee, Erreur> {
    if texte == TOUT {
        return Ok(Portee::ToutLeCompte);
    }
    let quoi =
        Identifiant::analyser(texte).map_err(|_| Erreur::IdentifiantInvalide { position })?;
    match quoi.genre() {
        Genre::Machine => Ok(Portee::UneMachine(quoi)),
        Genre::Service => Ok(Portee::UnService(quoi)),
        // Un compte, un appareil, une autorisation, un annuaire : aucun de ceux-là
        // ne délimite ce qu'une autorisation couvre.
        _ => Err(Erreur::IdentifiantInvalide { position }),
    }
}

// ── Poser un alias ──────────────────────────────────────────────────────────

/// Le champ de `PUT /v1/alias`.
const CHAMP_ALIAS: &str = "alias";

/// Ce que `PUT /v1/alias` demande.
///
/// # UN SEUL CHAMP, ET C'EST LA SEULE DONNÉE PERSONNELLE DU PRODUIT
///
/// C13 : rien d'autre n'est hébergé de l'utilisateur. Cet alias est **public par
/// construction** (`docs/modele.md` §2.1) — il est la seule surface énumérable
/// de l'annuaire, et c'est son emploi autant que son coût.
///
/// Il reste **facultatif**, et le rester est une position tenable : un compte
/// sans alias n'est trouvable que par son identifiant, transmis de la main à la
/// main.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DemandeAlias<'a> {
    /// L'alias demandé, déjà validé.
    pub alias: Alias<'a>,
}

impl<'a> DemandeAlias<'a> {
    /// Décode une demande d'alias.
    ///
    /// ```jsonc
    /// {"alias": "thierry"}
    /// ```
    ///
    /// **Il passe par [`Lecteur::chaine`], et non par `texte_libre`.** Un alias
    /// est une CLÉ — on le cherche, on le compare, il doit être unique. C'est
    /// exactement le cas où l'équivalence Unicode ferait qu'un même alias
    /// s'écrirait de deux façons, et que deux comptes croiraient chacun le
    /// posséder.
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage, plus [`Erreur::IdentifiantInvalide`] quand l'alias ne
    /// suit pas sa grammaire — voir [`Alias::analyser`]. **Cette faute-là ne dit
    /// PAS laquelle des quatre règles a été enfreinte** : longueur, alphabet,
    /// bord, ou ressemblance avec un identifiant. Le détail appartient à
    /// [`crate::Erreur`], que le routage rend ; ce cadrage-ci ne fait que
    /// refuser.
    pub fn decoder(octets: &'a [u8]) -> Result<Self, Erreur> {
        if octets.len() > CORPS_MAX {
            return Err(Erreur::MessageTropLong {
                obtenue: octets.len(),
            });
        }
        let mut lecteur = Lecteur::nouveau(octets);
        lecteur.attendre(b'{', "un objet")?;

        let position = lecteur.position();
        if lecteur.chaine()? != CHAMP_ALIAS {
            return Err(Erreur::ChampInconnu { position });
        }
        lecteur.attendre(b':', "deux-points")?;
        let position = lecteur.position();
        let texte = lecteur.chaine()?;
        let alias = Alias::analyser(texte).map_err(|_| Erreur::IdentifiantInvalide { position })?;

        lecteur.attendre(b'}', "la fin de l'objet")?;
        lecteur.fin()?;
        Ok(Self { alias })
    }

    /// Encode cette demande, et rend le nombre d'octets écrits.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`].
    pub fn encoder(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        let mut ecrivain = asl_proto::cadrage::Ecrivain::nouveau(sortie);
        ecrivain.pousser(b"{\"alias\":\"");
        ecrivain.pousser(self.alias.as_str().as_bytes());
        ecrivain.pousser(b"\"}");
        ecrivain.achever()
    }
}
