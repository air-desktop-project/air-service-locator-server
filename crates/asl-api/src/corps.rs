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

/// Ce qu'un jeton de poussée peut faire. Égal à `asl_registre::JETON_OCTETS_MAX`.
///
/// **RECOPIÉ PLUTÔT QU'IMPORTÉ** : `asl-api` est une grammaire, et dépendre du
/// magasin pour connaître une borne ferait remonter une décision de rangement
/// dans un décodeur. Les deux nombres sont comparés par un essai.
pub const JETON_MAX: usize = 255;

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
        let (nom, capacites) = lire_les_champs_de_machine(octets)?;
        let nom = nom.ok_or(Erreur::ChampManquant {
            nom: CHAMPS_MACHINE[0],
        })?;
        let capacites = capacites.ok_or(Erreur::ChampManquant {
            nom: CHAMPS_MACHINE[1],
        })?;
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

/// Lit les champs d'un objet machine, **sans exiger qu'ils soient tous là**.
///
/// # POURQUOI LA DÉCLARATION ET LA MODIFICATION PARTAGENT CETTE BOUCLE
///
/// `POST /v1/machines` et `PATCH /v1/machines/{m}` lisent les MÊMES champs, avec
/// les mêmes bornes et les mêmes refus ; seule l'exigence diffère — l'un veut les
/// deux, l'autre en veut au moins un. Deux boucles auraient divergé au premier
/// champ ajouté, et c'est le `PATCH`, moins souvent relu, qui aurait gardé la
/// vieille borne.
///
/// **Un objet VIDE se lit ici sans faute**, et rend deux `None` : c'est à
/// l'appelant de dire si l'absence est une faute, et laquelle.
fn lire_les_champs_de_machine(octets: &[u8]) -> Result<(Option<&str>, Option<Capacites>), Erreur> {
    if octets.len() > CORPS_MAX {
        return Err(Erreur::MessageTropLong {
            obtenue: octets.len(),
        });
    }
    let mut lecteur = Lecteur::nouveau(octets);
    lecteur.attendre(b'{', "un objet")?;

    let mut vus = 0_u8;
    let mut nom: Option<&str> = None;
    let mut capacites: Option<Capacites> = None;

    lecteur.sauter_blancs();
    if lecteur.regarder() == Some(b'}') {
        lecteur.avancer();
        lecteur.fin()?;
        return Ok((None, None));
    }

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
            capacites = Some(decoder_capacites(&mut lecteur)?);
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
    Ok((nom, capacites))
}

// ── Modifier une machine ────────────────────────────────────────────────────

/// Ce que `PATCH /v1/machines/{m}` demande.
///
/// # CE QUI EST ABSENT NE CHANGE PAS
///
/// C'est la sémantique de `PATCH`, et elle a une conséquence qu'il faut nommer :
/// **`{"capacites": []}` RETIRE les deux capacités**, alors que l'absence du
/// champ les laisse telles quelles. Le tableau vide n'est pas « je ne dis rien »,
/// il est « aucune » — et c'est un état légitime, celui d'une machine déclarée
/// qui ne peut plus rien.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModificationMachine<'a> {
    /// Le nouveau nom, ou `None` pour le laisser.
    pub nom: Option<&'a str>,
    /// Les nouvelles capacités, ou `None` pour les laisser.
    pub capacites: Option<Capacites>,
}

impl<'a> ModificationMachine<'a> {
    /// Décode la modification d'une machine.
    ///
    /// ```jsonc
    /// {"nom": "grenier"}                       // le nom seul
    /// {"capacites": ["lecture"]}               // les capacités seules
    /// {"nom": "grenier", "capacites": []}      // les deux
    /// ```
    ///
    /// # Erreurs
    ///
    /// Celles de [`DeclarationMachine::decoder`], plus [`Erreur::RienAChanger`]
    /// si l'objet ne porte aucun des deux champs.
    pub fn decoder(octets: &'a [u8]) -> Result<Self, Erreur> {
        let (nom, capacites) = lire_les_champs_de_machine(octets)?;
        if nom.is_none() && capacites.is_none() {
            return Err(Erreur::RienAChanger);
        }
        Ok(Self { nom, capacites })
    }

    /// Encode cette modification, et rend le nombre d'octets écrits.
    ///
    /// **Ce qui est `None` n'est pas écrit** — et non écrit à `null` : un `null`
    /// serait un troisième sens, à mi-chemin entre « laisse » et « vide », qu'il
    /// faudrait ensuite trancher partout.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`].
    pub fn encoder(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        let mut ecrivain = asl_proto::cadrage::Ecrivain::nouveau(sortie);
        ecrivain.pousser(b"{");
        if let Some(nom) = self.nom {
            ecrivain.pousser(b"\"nom\":\"");
            ecrivain.pousser(nom.as_bytes());
            ecrivain.pousser(b"\"");
        }
        if let Some(capacites) = self.capacites {
            if self.nom.is_some() {
                ecrivain.pousser(b",");
            }
            ecrivain.pousser(b"\"capacites\":[");
            let mut deja = false;
            if capacites.annonce {
                ecrivain.pousser(b"\"annonce\"");
                deja = true;
            }
            if capacites.lecture {
                if deja {
                    ecrivain.pousser(b",");
                }
                ecrivain.pousser(b"\"lecture\"");
            }
            ecrivain.pousser(b"]");
        }
        ecrivain.pousser(b"}");
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

/// Ce que `GET /v1/autorisations` rend, une par élément.
///
/// # ELLE VIT À CÔTÉ DE [`DemandeAutorisation`], ET NON DANS `asl-proto`
///
/// Elle emploie le MÊME vocabulaire de portée — le mot `tout`, ou un identifiant
/// dont le genre la désigne. Un `Portee` écrit dans un fichier et relu dans un
/// autre finirait par diverger : la demande accepterait ce que la réponse
/// n'écrit plus.
///
/// # LES DEUX SENS SONT DANS LE MÊME TABLEAU
///
/// `protocole.md` §2.2 : « les deux sens — ce que j'ai accordé, ce qu'on m'a
/// accordé ». Deux tableaux séparés auraient obligé l'application à savoir dans
/// lequel chercher ; `par` et `a` le disent déjà, et un lecteur qui connaît son
/// propre identifiant sait de quel côté il est.
///
/// # LES RÉVOQUÉES SONT RENDUES, ET MARQUÉES
///
/// Même raison qu'un appareil révoqué (`protocole.md` §2.2) : **l'écran qu'on
/// regarde après avoir retiré un accès doit montrer ce qu'on a retiré.** Les
/// taire ferait douter d'avoir cliqué.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutorisationRendue {
    /// L'identifiant de l'autorisation elle-même.
    ///
    /// **C'est lui qu'on passe à `DELETE /v1/autorisations/{g}`.** Une liste
    /// dont les éléments ne se désignent pas est une liste qu'on ne peut que
    /// regarder.
    pub autorisation: Identifiant,
    /// Le compte qui accorde.
    pub par: Identifiant,
    /// Le compte qui en bénéficie.
    pub a: Identifiant,
    /// Jusqu'où elle porte.
    pub portee: Portee,
    /// A-t-elle été retirée ?
    pub revoquee: bool,
}

impl AutorisationRendue {
    /// Encode une autorisation.
    ///
    /// ```jsonc
    /// {"autorisation":"g-…","par":"u-…","a":"u-…","portee":"tout","revoquee":false}
    /// ```
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`].
    pub fn encoder(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        let mut ecrivain = asl_proto::cadrage::Ecrivain::nouveau(sortie);
        ecrivain.pousser(b"{\"autorisation\":\"");
        ecrivain.pousser(self.autorisation.texte().as_str().as_bytes());
        ecrivain.pousser(b"\",\"par\":\"");
        ecrivain.pousser(self.par.texte().as_str().as_bytes());
        ecrivain.pousser(b"\",\"a\":\"");
        ecrivain.pousser(self.a.texte().as_str().as_bytes());
        ecrivain.pousser(b"\",\"portee\":\"");
        match self.portee {
            Portee::ToutLeCompte => ecrivain.pousser(TOUT.as_bytes()),
            Portee::UneMachine(quoi) | Portee::UnService(quoi) => {
                ecrivain.pousser(quoi.texte().as_str().as_bytes());
            }
        }
        ecrivain.pousser(b"\",\"revoquee\":");
        ecrivain.pousser(if self.revoquee { b"true" } else { b"false" });
        ecrivain.pousser(b"}");
        ecrivain.achever()
    }

    /// Décode une autorisation rendue.
    ///
    /// **ELLE EXISTE POUR LES ESSAIS ET POUR LES LIAISONS**, pas pour le
    /// serveur : celui-ci n'a qu'à écrire. Un encodeur sans décodeur ne se
    /// vérifie que par comparaison de chaînes, et une comparaison de chaînes ne
    /// dit pas qu'un lecteur saura relire.
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage.
    pub fn decoder(octets: &[u8]) -> Result<Self, Erreur> {
        let mut lecteur = asl_proto::cadrage::Lecteur::nouveau(octets);
        lecteur.attendre(b'{', "un objet")?;

        let mut autorisation = None;
        let mut par = None;
        let mut a = None;
        let mut portee = None;
        let mut revoquee = None;

        loop {
            lecteur.sauter_blancs();
            let position = lecteur.position();
            let champ = lecteur.chaine()?;
            lecteur.attendre(b':', "deux-points")?;

            match champ {
                "autorisation" => {
                    poser(
                        &mut autorisation,
                        lire_genre(&mut lecteur, Genre::Autorisation)?,
                        position,
                    )?;
                }
                "par" => poser(
                    &mut par,
                    lire_genre(&mut lecteur, Genre::Utilisateur)?,
                    position,
                )?,
                "a" => poser(
                    &mut a,
                    lire_genre(&mut lecteur, Genre::Utilisateur)?,
                    position,
                )?,
                "portee" => {
                    let ou = lecteur.position();
                    let texte = lecteur.chaine()?;
                    poser(&mut portee, lire_portee(texte, ou)?, position)?;
                }
                "revoquee" => poser(&mut revoquee, lire_booleen(&mut lecteur)?, position)?,
                _ => return Err(Erreur::ChampInconnu { position }),
            }

            lecteur.sauter_blancs();
            match lecteur.regarder() {
                Some(b',') => lecteur.avancer(),
                _ => break,
            }
        }

        lecteur.attendre(b'}', "la fin de l'objet")?;
        lecteur.fin()?;

        Ok(Self {
            autorisation: autorisation.ok_or(Erreur::ChampManquant {
                nom: "autorisation",
            })?,
            par: par.ok_or(Erreur::ChampManquant { nom: "par" })?,
            a: a.ok_or(Erreur::ChampManquant { nom: "a" })?,
            portee: portee.ok_or(Erreur::ChampManquant { nom: "portee" })?,
            revoquee: revoquee.ok_or(Erreur::ChampManquant { nom: "revoquee" })?,
        })
    }
}

/// Pose une valeur, ou refuse le champ en double.
///
/// **UN CHAMP EN DOUBLE EST UN REFUS, ET NON UN DERNIER-GAGNE.** Deux lecteurs
/// qui choisiraient différemment liraient deux messages dans un seul.
fn poser<T>(place: &mut Option<T>, valeur: T, position: usize) -> Result<(), Erreur> {
    if place.is_some() {
        return Err(Erreur::ChampEnDouble { position });
    }
    *place = Some(valeur);
    Ok(())
}

/// Lit un identifiant, et exige son genre.
fn lire_genre(
    lecteur: &mut asl_proto::cadrage::Lecteur<'_>,
    attendu: Genre,
) -> Result<Identifiant, Erreur> {
    let position = lecteur.position();
    let texte = lecteur.chaine()?;
    Identifiant::analyser_genre(attendu, texte)
        .map_err(|_| Erreur::IdentifiantInvalide { position })
}

/// Lit `true` ou `false`, et rien d'autre.
fn lire_booleen(lecteur: &mut asl_proto::cadrage::Lecteur<'_>) -> Result<bool, Erreur> {
    lecteur.sauter_blancs();
    let position = lecteur.position();
    for (mot, valeur) in [("true", true), ("false", false)] {
        if lecteur.mot(mot) {
            return Ok(valeur);
        }
    }
    Err(Erreur::JsonAttendu {
        position,
        attendu: "true ou false",
    })
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

// ── Déposer un jeton de poussée ─────────────────────────────────────────────

/// Les champs de `PUT /v1/appareils/{a}/poussee`.
const CHAMPS_JETON: [&str; 2] = ["plateforme", "jeton"];

/// La plate-forme qui délivrera la notification.
///
/// **DEUX, ET C'EST UNE LISTE FERMÉE.** Un jeton ne veut rien dire hors du
/// service qui l'a émis, et l'annuaire doit savoir à qui le présenter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plateforme {
    /// Apple Push Notification service.
    Apns,
    /// Firebase Cloud Messaging.
    Fcm,
}

impl Plateforme {
    /// Le mot qui la désigne sur le fil.
    #[must_use]
    pub const fn mot(self) -> &'static str {
        match self {
            Self::Apns => "apns",
            Self::Fcm => "fcm",
        }
    }

    /// Ce que ce mot désigne, s'il désigne quelque chose.
    #[must_use]
    pub fn depuis_le_mot(mot: &str) -> Option<Self> {
        match mot {
            "apns" => Some(Self::Apns),
            "fcm" => Some(Self::Fcm),
            _ => None,
        }
    }
}

/// Ce que `PUT /v1/appareils/{a}/poussee` dépose.
///
/// # L'ANNUAIRE NE LIT PAS LE JETON, ET N'A PAS À LE FAIRE
///
/// Il ne vérifie ni sa forme, ni sa longueur attendue, ni qu'il ressemble à ce
/// qu'Apple ou Google émettent aujourd'hui. **Un jeton est une chaîne opaque**,
/// et le seul juge de sa validité est le service qui l'a émis.
///
/// Ce qui EST exigé tient en deux points, et aucun ne porte sur le sens : il
/// s'écrit en ASCII imprimable — ce que [`Lecteur::chaine`] impose déjà —, et il
/// n'est pas vide. Un jeton vide n'est pas un dépôt, c'est un champ qu'on a
/// oublié de remplir ; **le retrait, lui, n'a pas de verbe** et n'est pas un
/// jeton vide déguisé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepotJeton<'a> {
    /// À qui présenter ce jeton.
    pub plateforme: Plateforme,
    /// Le jeton, tel que la plate-forme l'a donné.
    pub jeton: &'a str,
}

impl<'a> DepotJeton<'a> {
    /// Décode un dépôt de jeton.
    ///
    /// ```jsonc
    /// {"plateforme": "apns", "jeton": "c0ffee…"}
    /// ```
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage, plus [`Erreur::ChampManquant`], [`Erreur::NomVide`]
    /// pour un jeton vide et [`Erreur::NomTropLong`] au-delà de [`JETON_MAX`].
    pub fn decoder(octets: &'a [u8]) -> Result<Self, Erreur> {
        if octets.len() > CORPS_MAX {
            return Err(Erreur::MessageTropLong {
                obtenue: octets.len(),
            });
        }
        let mut lecteur = Lecteur::nouveau(octets);
        lecteur.attendre(b'{', "un objet")?;

        let mut vus = 0_u8;
        let mut plateforme: Option<Plateforme> = None;
        let mut jeton: Option<&'a str> = None;

        loop {
            let position_cle = lecteur.position();
            let cle = lecteur.chaine()?;
            let rang = CHAMPS_JETON.iter().position(|champ| *champ == cle).ok_or(
                Erreur::ChampInconnu {
                    position: position_cle,
                },
            )?;
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
                plateforme = Some(
                    Plateforme::depuis_le_mot(texte).ok_or(Erreur::ChampInconnu { position })?,
                );
            } else {
                if texte.is_empty() {
                    return Err(Erreur::NomVide);
                }
                if texte.len() > JETON_MAX {
                    return Err(Erreur::NomTropLong {
                        obtenue: texte.len(),
                    });
                }
                jeton = Some(texte);
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

        let plateforme = plateforme.ok_or(Erreur::ChampManquant {
            nom: CHAMPS_JETON[0],
        })?;
        let jeton = jeton.ok_or(Erreur::ChampManquant {
            nom: CHAMPS_JETON[1],
        })?;
        Ok(Self { plateforme, jeton })
    }

    /// Encode ce dépôt, et rend le nombre d'octets écrits.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`].
    pub fn encoder(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        let mut ecrivain = asl_proto::cadrage::Ecrivain::nouveau(sortie);
        ecrivain.pousser(b"{\"plateforme\":\"");
        ecrivain.pousser(self.plateforme.mot().as_bytes());
        ecrivain.pousser(b"\",\"jeton\":\"");
        ecrivain.pousser(self.jeton.as_bytes());
        ecrivain.pousser(b"\"}");
        ecrivain.achever()
    }
}
