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

// ── Créer un compte, avec preuve et attestation ─────────────────────────────

/// Ce qu'occupe une clé publique d'appareil : un point P-256, SEC1 compressé.
///
/// **RECOPIÉ PLUTÔT QU'IMPORTÉ**, comme [`JETON_MAX`] : `asl-api` est une
/// grammaire, et `asl_cle` est à l'étage 2. Égal à `asl_cle::CLE_APPAREIL_OCTETS`,
/// et `asl-session` — qui connaît les deux — tient l'égalité.
pub const CLE_APPAREIL_OCTETS: usize = 33;

/// Ce qu'occupe une preuve de possession d'appareil : `r ‖ s` d'un ECDSA P-256.
/// Égal à `asl_cle::SIGNATURE_APPAREIL_OCTETS`.
pub const PREUVE_APPAREIL_OCTETS: usize = 64;

/// Ce que fait la partie de LONGUEUR FIXE du corps : la plate-forme, la clé,
/// la preuve. L'attestation, variable, vient après.
pub const COMPTE_PREFIXE_OCTETS: usize = 1 + CLE_APPAREIL_OCTETS + PREUVE_APPAREIL_OCTETS;

/// Ce qu'une attestation peut faire, au plus.
///
/// # POURQUOI 8 Kio, ET NON LA BORNE D'`asl-attest`
///
/// `asl_attest::LONGUEUR_MAX` borne une CHAÎNE dans l'objet ; celle-ci borne
/// l'objet ENTIER. Une attestation App Attest réelle tient dans un à deux Kio
/// (deux certificats et un reçu). Huit laisse la marge d'un reçu inhabituel
/// sans laisser un corps se déployer sans fin sur le chemin qui crée un compte,
/// avant toute authentification.
pub const ATTESTATION_MAX: usize = 8192;

/// Le plus long corps de `POST /v1/comptes` : le préfixe, puis l'attestation.
pub const COMPTE_CORPS_MAX: usize = COMPTE_PREFIXE_OCTETS + ATTESTATION_MAX;

/// Sous quelle plate-forme un appareil s'atteste, tel que le FIL le porte.
///
/// # TROIS VALEURS, ET LES ÉTIQUETTES DU FIL NE SONT PAS CELLES DU STOCKAGE
///
/// Ici, `0` désigne « aucune » : c'est ce qu'écrit une application qui
/// n'atteste rien, et c'est un choix explicite de sa part, pas un octet oublié.
/// Au rangement (`asl_registre::Attestation`), zéro ne désigne personne, pour
/// qu'un enregistrement à demi écrit ne se relise pas comme non attesté. Chaque
/// couche tient son encodage ; c'est `asl-session` qui traduit de l'un à
/// l'autre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlateformeAttestation {
    /// Aucune attestation : l'application ne fournit rien à cautionner.
    Aucune,
    /// Apple App Attest.
    Apple,
    /// Google Play Integrity.
    Google,
}

impl PlateformeAttestation {
    /// Son étiquette sur le fil.
    #[must_use]
    pub const fn etiquette(self) -> u8 {
        match self {
            Self::Aucune => 0,
            Self::Apple => 1,
            Self::Google => 2,
        }
    }

    /// Relit une étiquette du fil.
    const fn depuis(octet: u8) -> Result<Self, Erreur> {
        match octet {
            0 => Ok(Self::Aucune),
            1 => Ok(Self::Apple),
            2 => Ok(Self::Google),
            octet => Err(Erreur::PlateformeInconnue { octet }),
        }
    }

    /// Une attestation doit-elle accompagner cette plate-forme ?
    const fn attend_une_attestation(self) -> bool {
        !matches!(self, Self::Aucune)
    }
}

/// Le corps de `POST /v1/comptes`, tel qu'il arrive sur le fil.
///
/// # LA RÈGLE DES LONGUEURS FIXES PLIE ICI, ET SEULEMENT ICI
///
/// Partout ailleurs, un corps binaire de ce produit fait une taille connue
/// (`protocole.md` §2.1 bis). Une chaîne de certificats n'en fait pas : c'est
/// le seul champ variable de toute l'API. Le corps est donc un PRÉFIXE de
/// longueur fixe — plate-forme, clé, preuve — suivi de l'attestation, qui est
/// tout le reste.
///
/// **Aucune longueur n'est pour autant LUE des octets.** Il n'y a pas de champ
/// de longueur qu'un émetteur choisirait : l'attestation finit là où le corps
/// finit. Ce qui la délimite ensuite est sa propre grammaire CBOR
/// (`asl-attest`), qui refuse le moindre octet en trop — mais cela se vérifie à
/// l'étage au-dessus, sur les octets que cette grammaire-ci se contente
/// d'isoler.
///
/// # CE QUE CE CODEC NE FAIT PAS
///
/// Il n'interprète NI la clé, NI la preuve, NI l'attestation : il rend trois
/// tranches d'octets. `asl-api` est une grammaire sans cryptographie, et
/// `asl_cle`/`asl_apple` (étage 2) lisent ces tranches. Ce module dit seulement
/// OÙ commence chacune, et refuse ce qui n'a pas la forme d'un corps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreationDeCompte<'a> {
    /// La plate-forme d'attestation déclarée.
    pub plateforme: PlateformeAttestation,
    /// La clé publique de l'appareil, [`CLE_APPAREIL_OCTETS`] octets, non
    /// interprétée.
    pub cle: &'a [u8],
    /// La preuve de possession, [`PREUVE_APPAREIL_OCTETS`] octets, non
    /// interprétée.
    pub preuve: &'a [u8],
    /// L'attestation, telle quelle : l'objet CBOR d'App Attest, ou vide quand
    /// la plate-forme est [`PlateformeAttestation::Aucune`].
    pub attestation: &'a [u8],
}

impl<'a> CreationDeCompte<'a> {
    /// Décode le corps de `POST /v1/comptes`.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::CorpsTropCourt`] sous le préfixe, [`Erreur::CorpsTropLong`]
    /// au-delà de [`COMPTE_CORPS_MAX`], [`Erreur::PlateformeInconnue`] pour un
    /// premier octet hors de {0, 1, 2}, [`Erreur::AttestationInattendue`] si
    /// des octets suivent une plate-forme `Aucune`, [`Erreur::AttestationManquante`]
    /// si une plate-forme déclarée n'est suivie de rien.
    pub fn decoder(octets: &'a [u8]) -> Result<Self, Erreur> {
        if octets.len() < COMPTE_PREFIXE_OCTETS {
            return Err(Erreur::CorpsTropCourt {
                obtenue: octets.len(),
                attendue: COMPTE_PREFIXE_OCTETS,
            });
        }
        if octets.len() > COMPTE_CORPS_MAX {
            return Err(Erreur::CorpsTropLong {
                obtenue: octets.len(),
                maximum: COMPTE_CORPS_MAX,
            });
        }
        // Le préfixe étant garanti présent, ces bornes tiennent : les tranches
        // existent, et rien n'est lu d'une longueur venue des octets.
        let apres_cle = 1 + CLE_APPAREIL_OCTETS;
        let plateforme = PlateformeAttestation::depuis(octets[0])?;
        let cle = &octets[1..apres_cle];
        let preuve = &octets[apres_cle..COMPTE_PREFIXE_OCTETS];
        let attestation = &octets[COMPTE_PREFIXE_OCTETS..];

        if plateforme.attend_une_attestation() {
            if attestation.is_empty() {
                return Err(Erreur::AttestationManquante);
            }
        } else if !attestation.is_empty() {
            return Err(Erreur::AttestationInattendue {
                obtenue: attestation.len(),
            });
        }

        Ok(Self {
            plateforme,
            cle,
            preuve,
            attestation,
        })
    }

    /// Encode ce corps, et rend le nombre d'octets écrits.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`] si `sortie` ne suffit pas, et les mêmes
    /// fautes de cohérence que [`Self::decoder`] : ce qui ne se décoderait pas
    /// ne s'encode pas non plus.
    pub fn encoder(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        if self.cle.len() != CLE_APPAREIL_OCTETS || self.preuve.len() != PREUVE_APPAREIL_OCTETS {
            return Err(Erreur::CorpsTropCourt {
                obtenue: self.cle.len().saturating_add(self.preuve.len()),
                attendue: CLE_APPAREIL_OCTETS + PREUVE_APPAREIL_OCTETS,
            });
        }
        if self.plateforme.attend_une_attestation() == self.attestation.is_empty() {
            return Err(if self.attestation.is_empty() {
                Erreur::AttestationManquante
            } else {
                Erreur::AttestationInattendue {
                    obtenue: self.attestation.len(),
                }
            });
        }
        let total = COMPTE_PREFIXE_OCTETS.saturating_add(self.attestation.len());
        if total > COMPTE_CORPS_MAX {
            return Err(Erreur::CorpsTropLong {
                obtenue: total,
                maximum: COMPTE_CORPS_MAX,
            });
        }
        let place = sortie.get_mut(..total).ok_or(Erreur::TamponTropPetit)?;
        place[0] = self.plateforme.etiquette();
        let apres_cle = 1 + CLE_APPAREIL_OCTETS;
        place[1..apres_cle].copy_from_slice(self.cle);
        place[apres_cle..COMPTE_PREFIXE_OCTETS].copy_from_slice(self.preuve);
        place[COMPTE_PREFIXE_OCTETS..].copy_from_slice(self.attestation);
        Ok(total)
    }
}

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

// ── Ce qu'une liste de machines rend ────────────────────────────────────────

/// Le mot qui dit qu'une machine a une clé.
const CLE_ENROLEE: &str = "enrolee";
/// Le mot qui dit qu'une machine attend encore la sienne.
const CLE_ATTENDUE: &str = "attendue";

/// Une machine, telle que `GET /v1/machines` la rend à l'application.
///
/// # UN SOUS-ENSEMBLE, ET COMPATIBLE EN AVANT
///
/// `docs/protocole.md` §2.2 décrit une forme plus riche — la date d'enrôlement,
/// le code en cours et son expiration, la distinction d'une clé RÉVOQUÉE d'une
/// clé jamais posée. **Le serveur ne les sert pas encore, et deux d'entre eux ne
/// le pourront jamais tels quels** : il ne RANGE aucun horodatage (une
/// `asl_registre::Provenance` ne porte pas de date, et les étages 1 et 2 n'ont
/// pas d'horloge), et le code d'enrôlement ne se garde que par son empreinte
/// (C14) — on ne peut donc pas le RE-rendre dans une liste. Ce qui est ici est
/// donc un sous-ensemble ; un lecteur qui attend les autres champs les trouve
/// absents, jamais faux. L'objet reste un objet, et un champ ajouté plus tard ne
/// casse pas celui qui lit ceux d'aujourd'hui.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachineRendue<'a> {
    /// L'identifiant de la machine. **C'est lui qu'on passe à
    /// `PATCH /v1/machines/{m}` ou à `DELETE /v1/machines/{m}/cle`.**
    pub machine: Identifiant,
    /// Le nom que son propriétaire lui a donné — du texte libre.
    pub nom: &'a str,
    /// Ce qu'elle a le droit de faire.
    pub capacites: Capacites,
    /// A-t-elle une clé ? `true` la rend « enrolee », `false` « attendue ».
    ///
    /// # DEUX ÉTATS, ET NON TROIS
    ///
    /// Une clé révoquée et une clé jamais posée sont toutes deux « pas de clé »
    /// dans ce qui est rangé (`asl_registre::Machine::cle` vaut `None` dans les
    /// deux cas). Les distinguer demanderait un état que le serveur ne garde pas
    /// encore ; on rend donc « attendue » pour l'une comme pour l'autre, plutôt
    /// qu'une distinction qu'on inventerait.
    pub enrolee: bool,
}

impl<'a> MachineRendue<'a> {
    /// Encode une machine rendue.
    ///
    /// ```jsonc
    /// {"machine":"m-…","nom":"grenier","capacites":["annonce"],"cle":"enrolee"}
    /// ```
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`].
    pub fn encoder(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        let mut ecrivain = asl_proto::cadrage::Ecrivain::nouveau(sortie);
        ecrivain.pousser(b"{\"machine\":\"");
        ecrivain.pousser(self.machine.texte().as_str().as_bytes());
        ecrivain.pousser(b"\",\"nom\":\"");
        // **LE NOM SE RÉÉMET SANS ÉCHAPPEMENT, ET C'EST SÛR.** Le seul texte
        // libre du produit est entré par [`Lecteur::texte_libre`], qui a déjà
        // refusé `"`, `\`, les contrôles et les forceurs bidi — précisément les
        // caractères qu'un encodeur JSON aurait à échapper. Ce cadrage n'a donc
        // pas d'échappeur, exactement comme [`DeclarationMachine::encoder`].
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
        ecrivain.pousser(b"],\"cle\":\"");
        ecrivain.pousser(
            if self.enrolee {
                CLE_ENROLEE
            } else {
                CLE_ATTENDUE
            }
            .as_bytes(),
        );
        ecrivain.pousser(b"\"}");
        ecrivain.achever()
    }

    /// Décode une machine rendue.
    ///
    /// **ELLE EXISTE POUR LES ESSAIS ET POUR LES LIAISONS**, pas pour le
    /// serveur : celui-ci n'a qu'à écrire. Voir [`AutorisationRendue::decoder`].
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage, plus [`Erreur::NomVide`] et [`Erreur::NomTropLong`].
    pub fn decoder(octets: &'a [u8]) -> Result<Self, Erreur> {
        let mut lecteur = asl_proto::cadrage::Lecteur::nouveau(octets);
        lecteur.attendre(b'{', "un objet")?;

        let mut machine = None;
        let mut nom: Option<&str> = None;
        let mut capacites = None;
        let mut enrolee = None;

        loop {
            lecteur.sauter_blancs();
            let position = lecteur.position();
            let champ = lecteur.chaine()?;
            lecteur.attendre(b':', "deux-points")?;

            match champ {
                "machine" => poser(
                    &mut machine,
                    lire_genre(&mut lecteur, Genre::Machine)?,
                    position,
                )?,
                "nom" => {
                    let texte = lecteur.texte_libre()?;
                    if texte.is_empty() {
                        return Err(Erreur::NomVide);
                    }
                    if texte.len() > NOM_MACHINE_MAX {
                        return Err(Erreur::NomTropLong {
                            obtenue: texte.len(),
                        });
                    }
                    poser(&mut nom, texte, position)?;
                }
                "capacites" => poser(&mut capacites, decoder_capacites(&mut lecteur)?, position)?,
                "cle" => {
                    let ou = lecteur.position();
                    let etat = match lecteur.chaine()? {
                        CLE_ENROLEE => true,
                        CLE_ATTENDUE => false,
                        _ => {
                            return Err(Erreur::JsonAttendu {
                                position: ou,
                                attendu: "enrolee ou attendue",
                            });
                        }
                    };
                    poser(&mut enrolee, etat, position)?;
                }
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
            machine: machine.ok_or(Erreur::ChampManquant { nom: "machine" })?,
            nom: nom.ok_or(Erreur::ChampManquant { nom: "nom" })?,
            capacites: capacites.ok_or(Erreur::ChampManquant { nom: "capacites" })?,
            enrolee: enrolee.ok_or(Erreur::ChampManquant { nom: "cle" })?,
        })
    }
}

// ── Ce qu'une liste d'appareils rend ────────────────────────────────────────

/// Le mot JSON d'une attestation, tel qu'une liste le rend.
const fn mot_d_attestation(plateforme: PlateformeAttestation) -> &'static str {
    match plateforme {
        PlateformeAttestation::Aucune => "aucune",
        PlateformeAttestation::Apple => "apple",
        PlateformeAttestation::Google => "google",
    }
}

/// L'attestation que ce mot désigne, ou un refus.
fn attestation_du_mot(texte: &str, position: usize) -> Result<PlateformeAttestation, Erreur> {
    match texte {
        "aucune" => Ok(PlateformeAttestation::Aucune),
        "apple" => Ok(PlateformeAttestation::Apple),
        "google" => Ok(PlateformeAttestation::Google),
        _ => Err(Erreur::JsonAttendu {
            position,
            attendu: "aucune, apple ou google",
        }),
    }
}

/// Un appareil, tel que `GET /v1/appareils` le rend à l'application.
///
/// # UN SOUS-ENSEMBLE, POUR LA MÊME RAISON QUE [`MachineRendue`]
///
/// `docs/protocole.md` §2.2 décrit aussi une date d'enrôlement et une date de
/// révocation. Le serveur ne RANGE aucune date ; ce qui est ici — l'identifiant,
/// l'attestation sous laquelle il est entré, et s'il est révoqué — est tout ce
/// qu'il garde de lui.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppareilRendu {
    /// L'identifiant de l'appareil. **C'est lui qu'on passe à
    /// `DELETE /v1/appareils/{a}`.**
    pub appareil: Identifiant,
    /// Sous quelle attestation il est entré (`docs/modele.md` §2.2 : ce qu'on
    /// regarde le jour où l'on resserre la posture).
    pub attestation: PlateformeAttestation,
    /// A-t-il été révoqué ? **Un appareil révoqué reste rendu** — c'est l'écran
    /// qu'on regarde après avoir perdu un téléphone, et une ligne disparue n'y
    /// dirait rien.
    pub revoque: bool,
}

impl AppareilRendu {
    /// Encode un appareil rendu.
    ///
    /// ```jsonc
    /// {"appareil":"a-…","attestation":"apple","revoque":false}
    /// ```
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`].
    pub fn encoder(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        let mut ecrivain = asl_proto::cadrage::Ecrivain::nouveau(sortie);
        ecrivain.pousser(b"{\"appareil\":\"");
        ecrivain.pousser(self.appareil.texte().as_str().as_bytes());
        ecrivain.pousser(b"\",\"attestation\":\"");
        ecrivain.pousser(mot_d_attestation(self.attestation).as_bytes());
        ecrivain.pousser(b"\",\"revoque\":");
        ecrivain.pousser(if self.revoque { b"true" } else { b"false" });
        ecrivain.pousser(b"}");
        ecrivain.achever()
    }

    /// Décode un appareil rendu.
    ///
    /// **ELLE EXISTE POUR LES ESSAIS ET POUR LES LIAISONS**, comme
    /// [`AutorisationRendue::decoder`].
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage.
    pub fn decoder(octets: &[u8]) -> Result<Self, Erreur> {
        let mut lecteur = asl_proto::cadrage::Lecteur::nouveau(octets);
        lecteur.attendre(b'{', "un objet")?;

        let mut appareil = None;
        let mut attestation = None;
        let mut revoque = None;

        loop {
            lecteur.sauter_blancs();
            let position = lecteur.position();
            let champ = lecteur.chaine()?;
            lecteur.attendre(b':', "deux-points")?;

            match champ {
                "appareil" => poser(
                    &mut appareil,
                    lire_genre(&mut lecteur, Genre::Appareil)?,
                    position,
                )?,
                "attestation" => {
                    let ou = lecteur.position();
                    let texte = lecteur.chaine()?;
                    poser(&mut attestation, attestation_du_mot(texte, ou)?, position)?;
                }
                "revoque" => poser(&mut revoque, lire_booleen(&mut lecteur)?, position)?,
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
            appareil: appareil.ok_or(Erreur::ChampManquant { nom: "appareil" })?,
            attestation: attestation.ok_or(Erreur::ChampManquant { nom: "attestation" })?,
            revoque: revoque.ok_or(Erreur::ChampManquant { nom: "revoque" })?,
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
