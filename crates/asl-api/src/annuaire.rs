//! Les corps de l'inscription des annuaires locaux (`docs/protocole.md` §2.2,
//! §3 ter ; `docs/annuaires.md` §2 ter, §4.1) : ce qu'une application
//! déclare, ce qu'un administrateur tranche, où un domaine est confié — et ce
//! que l'annuaire en rend.
//!
//! La preuve qu'un annuaire local apporte en se présentant — code, clé,
//! signature — n'est pas du JSON : elle a la forme de celle d'un enrôlement,
//! et `asl-session` la lit comme elle.

use asl_id::{Genre, Identifiant};
use asl_proto::Erreur;
use asl_proto::cadrage::{Ecrivain, Lecteur};

use crate::corps::CORPS_MAX;

/// Le champ qui porte une adresse déclarée.
const CHAMP_ADRESSE: &str = "adresse";

/// Le champ qui porte une décision.
const CHAMP_ACCEPTE: &str = "accepte";

/// Le champ qui porte un annuaire.
const CHAMP_ANNUAIRE: &str = "annuaire";

/// Le champ qui porte des locateurs.
const CHAMP_LOCATEURS: &str = "locateurs";

/// Combien de locateurs un membre publie, au plus (décision 57).
///
/// **Quatre** : une IPv6, une IPv4, un nom, et une de réserve — ce qu'un
/// annuaire à la maison a. Une paire en publie donc huit au plus, et c'est ce
/// que le client lit dans un `421` (`asl-client`, huit adresses au plus).
pub const LOCATEURS_MAX: usize = 4;

/// Ce qu'un corps de `PUT /v1/federation/locateurs` peut occuper : quatre
/// locateurs de la plus grande longueur qu'une adresse admet, leurs
/// guillemets et leurs virgules, et l'objet autour.
pub const LOCATEURS_CORPS_MAX: usize = 32 + LOCATEURS_MAX * (255 + 3);

/// Combien de racines une liste de `GET /v1/racines` porte, au plus.
pub const RACINES_MAX: usize = 4;

/// Combien de locateurs une racine porte, au plus, dans cette liste.
pub const LOCATEURS_DE_RACINE_MAX: usize = 8;

/// Refuse un corps plus long que `maximum`.
const fn borner(octets: &[u8], maximum: usize) -> Result<(), Erreur> {
    if octets.len() > maximum {
        return Err(Erreur::MessageTropLong {
            obtenue: octets.len(),
        });
    }
    Ok(())
}

/// Lit `"<champ>":` à la position du lecteur.
fn champ(lecteur: &mut Lecteur<'_>, nom: &str) -> Result<(), Erreur> {
    lecteur.sauter_blancs();
    let position = lecteur.position();
    if lecteur.chaine()? != nom {
        return Err(Erreur::ChampInconnu { position });
    }
    lecteur.attendre(b':', "deux-points")
}

/// Lit `{"<champ>": ` et rend le lecteur placé sur la valeur — d'un corps
/// d'au plus `maximum` octets.
fn ouvrir_jusqu_a<'a>(octets: &'a [u8], nom: &str, maximum: usize) -> Result<Lecteur<'a>, Erreur> {
    borner(octets, maximum)?;
    let mut lecteur = Lecteur::nouveau(octets);
    lecteur.attendre(b'{', "un objet")?;
    champ(&mut lecteur, nom)?;
    Ok(lecteur)
}

/// Lit `{"<champ>": ` et rend le lecteur placé sur la valeur.
fn ouvrir<'a>(octets: &'a [u8], nom: &str) -> Result<Lecteur<'a>, Erreur> {
    ouvrir_jusqu_a(octets, nom, CORPS_MAX)
}

/// Lit `[`, puis zéro ou plusieurs chaînes séparées de virgules, puis `]` —
/// dans `places`, et rend combien. **Une de trop refuse le tableau** :
/// [`Erreur::TropDElements`].
fn tableau_de_chaines<'a, const N: usize>(
    lecteur: &mut Lecteur<'a>,
    places: &mut [&'a str; N],
) -> Result<usize, Erreur> {
    lecteur.attendre(b'[', "un tableau")?;
    lecteur.sauter_blancs();
    if lecteur.regarder() == Some(b']') {
        lecteur.avancer();
        return Ok(0);
    }
    let mut combien = 0_usize;
    loop {
        let chaine = lecteur.chaine()?;
        let place = places.get_mut(combien).ok_or(Erreur::TropDElements {
            obtenu: combien.saturating_add(1),
        })?;
        *place = chaine;
        combien = combien.saturating_add(1);
        lecteur.sauter_blancs();
        match lecteur.regarder() {
            Some(b',') => lecteur.avancer(),
            Some(b']') => {
                lecteur.avancer();
                return Ok(combien);
            }
            _ => {
                return Err(Erreur::JsonAttendu {
                    position: lecteur.position(),
                    attendu: "une virgule ou la fin du tableau",
                });
            }
        }
    }
}

/// Lit `}` et la fin du corps.
fn fermer(lecteur: &mut Lecteur<'_>) -> Result<(), Erreur> {
    lecteur.attendre(b'}', "la fin de l'objet")?;
    lecteur.fin()
}

// ── Déclarer un annuaire, ou son second membre ──────────────────────────────

/// Le corps de `POST /v1/annuaires` et de `POST /v1/annuaires/{n}/membres` :
/// `{"adresse": "hôte:port"}`. **La forme de l'adresse** se juge dans
/// `asl-registre` (`Adresse::nouvelle`) ; ici, une chaîne ASCII sans
/// échappement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclarationDAnnuaire<'a> {
    /// L'adresse déclarée, telle que reçue.
    pub adresse: &'a str,
}

impl<'a> DeclarationDAnnuaire<'a> {
    /// Décode une déclaration.
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage.
    pub fn decoder(octets: &'a [u8]) -> Result<Self, Erreur> {
        let mut lecteur = ouvrir(octets, CHAMP_ADRESSE)?;
        let adresse = lecteur.chaine()?;
        fermer(&mut lecteur)?;
        Ok(Self { adresse })
    }
}

// ── Publier ses locateurs ───────────────────────────────────────────────────

/// Le corps de `PUT /v1/federation/locateurs` (décision 57) :
/// `{"locateurs": ["[IPv6]:port", "IPv4:port", …]}`, de zéro à
/// [`LOCATEURS_MAX`]. **Vide, il retire ce qui était publié** : l'adresse
/// déclarée à l'inscription sert de nouveau. La forme de chacun se juge dans
/// `asl-registre` (`Adresse::nouvelle`), comme l'adresse déclarée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicationDeLocateurs<'a> {
    /// Les locateurs, tels que reçus.
    locateurs: [&'a str; LOCATEURS_MAX],
    /// Combien portent quelque chose.
    combien: usize,
}

impl<'a> PublicationDeLocateurs<'a> {
    /// Décode une publication.
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage, plus [`Erreur::TropDElements`] au-delà de
    /// [`LOCATEURS_MAX`].
    pub fn decoder(octets: &'a [u8]) -> Result<Self, Erreur> {
        let mut lecteur = ouvrir_jusqu_a(octets, CHAMP_LOCATEURS, LOCATEURS_CORPS_MAX)?;
        let mut locateurs = [""; LOCATEURS_MAX];
        let combien = tableau_de_chaines(&mut lecteur, &mut locateurs)?;
        fermer(&mut lecteur)?;
        Ok(Self { locateurs, combien })
    }

    /// Les locateurs publiés.
    #[must_use]
    pub fn locateurs(&self) -> &[&'a str] {
        self.locateurs.get(..self.combien).unwrap_or_default()
    }
}

// ── Trancher une inscription ────────────────────────────────────────────────

/// Le corps de `POST /v1/inscriptions/{n}/decision` : `{"accepte": true}` ou
/// `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionDInscription {
    /// Accepter, ou refuser.
    pub accepte: bool,
}

impl DecisionDInscription {
    /// Décode une décision.
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage, plus [`Erreur::JsonAttendu`] quand la valeur n'est
    /// ni `true` ni `false`.
    pub fn decoder(octets: &[u8]) -> Result<Self, Erreur> {
        let mut lecteur = ouvrir(octets, CHAMP_ACCEPTE)?;
        lecteur.sauter_blancs();
        let position = lecteur.position();
        let accepte = if lecteur.mot("true") {
            true
        } else if lecteur.mot("false") {
            false
        } else {
            return Err(Erreur::JsonAttendu {
                position,
                attendu: "true ou false",
            });
        };
        fermer(&mut lecteur)?;
        Ok(Self { accepte })
    }
}

// ── Confier un domaine ──────────────────────────────────────────────────────

/// Le corps de `PUT /v1/domaines/{d}/hebergeur` : `{"annuaire": "n-…"}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hebergeur {
    /// L'annuaire — son titulaire.
    pub annuaire: Identifiant,
}

impl Hebergeur {
    /// Décode un hébergeur.
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage, plus [`Erreur::IdentifiantInvalide`] quand ce n'est
    /// pas un `n-…`.
    pub fn decoder(octets: &[u8]) -> Result<Self, Erreur> {
        let mut lecteur = ouvrir(octets, CHAMP_ANNUAIRE)?;
        let position = lecteur.position();
        let annuaire = Identifiant::analyser_genre(Genre::Annuaire, lecteur.chaine()?)
            .map_err(|_| Erreur::IdentifiantInvalide { position })?;
        fermer(&mut lecteur)?;
        Ok(Self { annuaire })
    }
}

// ── Ce que l'annuaire rend ──────────────────────────────────────────────────

/// Une inscription telle que l'annuaire la rend — à son propriétaire
/// (`GET /v1/annuaires`), aux administrateurs (`GET /v1/inscriptions`), à
/// l'annuaire qui se présente (`POST /v1/annuaires/inscription`,
/// `POST /v1/annuaires/etat`).
///
/// **Les champs absents ne s'écrivent pas** : une déclaration dont le code
/// attend n'a pas de membre, un membre titulaire n'a pas d'autre annuaire que
/// lui-même — il l'écrit quand même, pour qu'un lecteur n'ait pas à le
/// déduire.
///
/// L'adresse se réémet sans échappement : elle est de l'ASCII imprimable sans
/// `"` ni `\` — `asl-registre` le vérifie à la pose et à la relecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InscriptionRendue<'a> {
    /// Le membre, s'il s'est présenté.
    pub membre: Option<Identifiant>,
    /// L'annuaire — son titulaire —, s'il est connu.
    pub annuaire: Option<Identifiant>,
    /// Le propriétaire, pour les administrateurs.
    pub proprietaire: Option<Identifiant>,
    /// L'état : `attendue`, `en attente`, `acceptée`, `refusée`, `retirée`.
    pub etat: &'a str,
    /// L'adresse déclarée.
    pub adresse: &'a str,
    /// Les locateurs que le membre a publiés (décision 57) — rien s'il n'en a
    /// pas publié : l'adresse déclarée sert alors.
    pub locateurs: &'a [&'a str],
    /// Jusqu'à quand le code se présente, pour une déclaration attendue.
    pub expire_a: Option<u64>,
    /// Ce que ce membre a conclu de sa paire, s'il l'a dit à cette racine
    /// depuis qu'elle tourne (0.36.0, décision 70) : l'un des mots
    /// d'[`EtatDePaire`].
    pub paire: Option<EtatDePaire>,
    /// La voie de fédération de ce membre vers la racine qui répond
    /// (0.38.0, décision 86) — absente tant qu'il ne lui a pas parlé depuis
    /// qu'elle tourne, et pour toute inscription qui n'est pas acceptée.
    pub voie: Option<EtatDeVoie>,
}

impl InscriptionRendue<'_> {
    /// Encode l'inscription en JSON.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`] si `sortie` ne suffit pas.
    pub fn encoder(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        let mut ecrivain = Ecrivain::nouveau(sortie);
        ecrivain.pousser(b"{");
        let mut premier = true;
        for (champ, valeur) in [
            ("membre", self.membre),
            ("annuaire", self.annuaire),
            ("proprietaire", self.proprietaire),
        ] {
            if let Some(quel) = valeur {
                if !premier {
                    ecrivain.pousser(b",");
                }
                premier = false;
                ecrivain.pousser(b"\"");
                ecrivain.pousser(champ.as_bytes());
                ecrivain.pousser(b"\":\"");
                ecrivain.pousser(quel.texte().as_str().as_bytes());
                ecrivain.pousser(b"\"");
            }
        }
        if !premier {
            ecrivain.pousser(b",");
        }
        ecrivain.pousser(b"\"etat\":\"");
        ecrivain.pousser(self.etat.as_bytes());
        ecrivain.pousser(b"\",\"adresse\":\"");
        ecrivain.pousser(self.adresse.as_bytes());
        ecrivain.pousser(b"\"");
        if !self.locateurs.is_empty() {
            ecrivain.pousser(b",\"locateurs\":");
            ecrire_des_chaines(&mut ecrivain, self.locateurs);
        }
        if let Some(quand) = self.expire_a {
            let mut chiffres = [0_u8; 20];
            ecrivain.pousser(b",\"expire_a\":");
            ecrivain.pousser(ecrire_un_entier(quand, &mut chiffres));
        }
        if let Some(paire) = self.paire {
            ecrivain.pousser(b",\"paire\":\"");
            ecrivain.pousser(paire.mot().as_bytes());
            ecrivain.pousser(b"\"");
        }
        if let Some(voie) = self.voie {
            ecrivain.pousser(b",\"voie\":\"");
            ecrivain.pousser(voie.mot().as_bytes());
            ecrivain.pousser(b"\"");
        }
        ecrivain.pousser(b"}");
        ecrivain.achever()
    }
}

/// Écrit `["…","…"]` : des chaînes sans échappement — ASCII imprimable sans
/// `"` ni `\\`, ce que `asl-registre` vérifie de toute adresse rangée.
fn ecrire_des_chaines(ecrivain: &mut Ecrivain<'_>, chaines: &[&str]) {
    ecrivain.pousser(b"[");
    for (rang, chaine) in chaines.iter().enumerate() {
        if rang > 0 {
            ecrivain.pousser(b",");
        }
        ecrivain.pousser(b"\"");
        ecrivain.pousser(chaine.as_bytes());
        ecrivain.pousser(b"\"");
    }
    ecrivain.pousser(b"]");
}

// ── Le renvoi (`421`, décisions 52, 57 et 59) ──────────────────────────────

/// Le corps d'un `421` : l'annuaire local d'un domaine confié, et où joindre
/// chacun de ses membres acceptés — **avec son identité** (décision 59).
///
/// ```jsonc
/// {"annuaire":"n-titulaire","adresses":["[2001:db8::51]:6630","192.0.2.52:6630"],
///  "identites":"n-titulaire n-second"}
/// ```
///
/// # POURQUOI `identites` EST UNE CHAÎNE, ET PAS UNE LISTE D'OBJETS
///
/// Un membre d'une paire a SA clé (décision 49) : sous la forme nouvelle
/// (décision 53), un client qui joint le second membre doit attendre le `n-…`
/// du second, pas celui du titulaire — que seul `annuaire` portait jusqu'à la
/// 0.30.0. Mais le lecteur d'hier (client 0.16/0.17, `asl-client::renvoi`)
/// **ne saute une clé inconnue que si sa valeur est une chaîne** : une liste
/// `"membres":[{…}]` lui ferait refuser le renvoi entier. D'où une chaîne,
/// **positionnelle** : le `i`-ème identifiant est celui de la `i`-ème adresse,
/// séparés par une espace. Le lecteur d'hier l'ignore et suit comme avant ;
/// le lecteur de demain attend, pour chaque adresse, l'identité écrite en face.
///
/// `annuaire` et `adresses` ne changent pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenvoiRendu<'a> {
    /// L'annuaire : son titulaire.
    pub annuaire: Identifiant,
    /// Chaque adresse, et l'identité du membre qu'on doit trouver au bout.
    pub adresses: &'a [(&'a str, Identifiant)],
}

impl RenvoiRendu<'_> {
    /// Encode le renvoi en JSON.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`] si `sortie` ne suffit pas.
    pub fn encoder(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        let mut ecrivain = Ecrivain::nouveau(sortie);
        ecrivain.pousser(b"{");
        ecrire_le_renvoi(&mut ecrivain, self.annuaire, Some(self.adresses));
        ecrivain.pousser(b"}");
        ecrivain.achever()
    }
}

/// `"annuaire":"n-…"`, puis — s'il y en a à dire — `"adresses":[…]` et
/// `"identites":"n-… n-…"` : le corps du `421` sans ses accolades, que
/// [`RenvoiRendu`] et [`AnnuaireResolu`] partagent.
fn ecrire_le_renvoi(
    ecrivain: &mut Ecrivain<'_>,
    annuaire: Identifiant,
    adresses: Option<&[(&str, Identifiant)]>,
) {
    ecrivain.pousser(b"\"annuaire\":\"");
    ecrivain.pousser(annuaire.texte().as_str().as_bytes());
    ecrivain.pousser(b"\"");
    let Some(adresses) = adresses else {
        return;
    };
    ecrivain.pousser(b",\"adresses\":[");
    for (rang, (adresse, _)) in adresses.iter().enumerate() {
        if rang > 0 {
            ecrivain.pousser(b",");
        }
        ecrivain.pousser(b"\"");
        ecrivain.pousser(adresse.as_bytes());
        ecrivain.pousser(b"\"");
    }
    ecrivain.pousser(b"],\"identites\":\"");
    for (rang, (_, identite)) in adresses.iter().enumerate() {
        if rang > 0 {
            ecrivain.pousser(b" ");
        }
        ecrivain.pousser(identite.texte().as_str().as_bytes());
    }
    ecrivain.pousser(b"\"");
}

// ── L'`asl-directory` (décisions 73 à 87, 0.38.0) ───────────────────────────

/// Le corps de `GET /v1/ou/{n-…}/asl-directory` : **celui du `421`, plus
/// `service`** (décision 75).
///
/// ```jsonc
/// // avec `localiser` :
/// {"service":"s-…","annuaire":"n-titulaire",
///  "adresses":["[2001:db8::51]:6630","192.0.2.52:6630"],
///  "identites":"n-titulaire n-second"}
/// // avec `voir` seul (ou `administrer`, décision 87) :
/// {"service":"s-…","annuaire":"n-titulaire"}
/// ```
///
/// - **`service` est une chaîne**, et vient en tête : le lecteur de renvoi
///   d'aujourd'hui (`asl-client::renvoi`) saute une clé inconnue dont la
///   valeur est une chaîne, et lit donc ce corps comme un `421`.
/// - **Seuls les membres vivants** y sont — leurs locateurs publiés, sinon
///   leur adresse déclarée (décisions 75 et 81) ; au même rang de
///   `identites`, le `n-…` qu'on doit trouver au bout.
/// - **La forme réduite omet `adresses` et `identites`**, elle ne les vide
///   pas (décision 80) : `[]` dirait « personne ne répond », contre le `200`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnnuaireResolu<'a> {
    /// Le `s-…` dérivé sous le titulaire (`asl_registre::asl_directory_derive`).
    pub service: Identifiant,
    /// L'annuaire : son titulaire.
    pub annuaire: Identifiant,
    /// Chaque adresse et l'identité de son membre — `None` pour la forme
    /// réduite.
    pub adresses: Option<&'a [(&'a str, Identifiant)]>,
}

impl AnnuaireResolu<'_> {
    /// Encode la réponse en JSON.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`] si `sortie` ne suffit pas.
    pub fn encoder(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        let mut ecrivain = Ecrivain::nouveau(sortie);
        ecrivain.pousser(b"{\"service\":\"");
        ecrivain.pousser(self.service.texte().as_str().as_bytes());
        ecrivain.pousser(b"\",");
        ecrire_le_renvoi(&mut ecrivain, self.annuaire, self.adresses);
        ecrivain.pousser(b"}");
        ecrivain.achever()
    }
}

// ── Les racines (décision 56) ───────────────────────────────────────────────

/// Une racine telle que `GET /v1/racines` la rend : son identité, sa clé, ses
/// locateurs.
///
/// ```jsonc
/// {"annuaire": "n-…", "cle": "<64 chiffres hexadécimaux>", "locateurs": ["[2001:db8::1]:6630", …]}
/// ```
///
/// **La clé voyage avec l'identifiant**, et le client vérifie que l'un se
/// déduit de l'autre avant de croire quoi que ce soit : une liste qui dirait un
/// `n-…` sous une autre clé est une liste fausse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RacineRendue<'a> {
    /// L'identité de la racine.
    pub annuaire: Identifiant,
    /// Sa clé d'identité Ed25519.
    pub cle: [u8; 32],
    /// Où la joindre — sans valeur de confiance.
    pub locateurs: &'a [&'a str],
}

impl RacineRendue<'_> {
    /// Encode la racine en JSON.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`] si `sortie` ne suffit pas.
    pub fn encoder(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        const HEXA: &[u8; 16] = b"0123456789abcdef";
        let mut ecrivain = Ecrivain::nouveau(sortie);
        ecrivain.pousser(b"{\"annuaire\":\"");
        ecrivain.pousser(self.annuaire.texte().as_str().as_bytes());
        ecrivain.pousser(b"\",\"cle\":\"");
        for octet in self.cle {
            ecrivain.pousser(&[
                HEXA[usize::from(octet >> 4)],
                HEXA[usize::from(octet & 0x0f)],
            ]);
        }
        ecrivain.pousser(b"\",\"locateurs\":");
        ecrire_des_chaines(&mut ecrivain, self.locateurs);
        ecrivain.pousser(b"}");
        ecrivain.achever()
    }
}

/// Une racine lue dans une liste de `GET /v1/racines` — **ce qu'elle DIT**.
/// Que la clé se déduise en l'identifiant, c'est au lecteur de le vérifier
/// (`asl_cle::identifiant_de_racine`) : cette crate ne calcule pas de clé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RacineLue<'a> {
    /// L'identité dite.
    pub annuaire: Identifiant,
    /// La clé dite.
    pub cle: [u8; 32],
    /// Les locateurs, les `combien` premiers.
    locateurs: [&'a str; LOCATEURS_DE_RACINE_MAX],
    /// Combien portent quelque chose.
    combien: usize,
}

impl<'a> RacineLue<'a> {
    /// Ses locateurs.
    #[must_use]
    pub fn locateurs(&self) -> &[&'a str] {
        self.locateurs.get(..self.combien).unwrap_or_default()
    }

    /// Lit `{"annuaire":…,"cle":…,"locateurs":[…]}`, dans cet ordre.
    fn lire(lecteur: &mut Lecteur<'a>) -> Result<Self, Erreur> {
        lecteur.attendre(b'{', "un objet")?;
        champ(lecteur, CHAMP_ANNUAIRE)?;
        let position = lecteur.position();
        let annuaire = Identifiant::analyser_genre(Genre::Annuaire, lecteur.chaine()?)
            .map_err(|_| Erreur::IdentifiantInvalide { position })?;
        lecteur.attendre(b',', "une virgule")?;
        champ(lecteur, "cle")?;
        let position = lecteur.position();
        let hexa = lecteur.chaine()?;
        let cle = hexadecimal(hexa).ok_or(Erreur::JsonAttendu {
            position,
            attendu: "64 chiffres hexadécimaux",
        })?;
        lecteur.attendre(b',', "une virgule")?;
        champ(lecteur, CHAMP_LOCATEURS)?;
        let mut locateurs = [""; LOCATEURS_DE_RACINE_MAX];
        let combien = tableau_de_chaines(lecteur, &mut locateurs)?;
        lecteur.attendre(b'}', "la fin de l'objet")?;
        Ok(Self {
            annuaire,
            cle,
            locateurs,
            combien,
        })
    }
}

/// Trente-deux octets écrits en 64 chiffres hexadécimaux, minuscules ou
/// majuscules.
fn hexadecimal(texte: &str) -> Option<[u8; 32]> {
    let chiffres = texte.as_bytes();
    if chiffres.len() != 64 || !chiffres.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    // Un chiffre déjà reconnu : `0-9`, `a-f` ou `A-F`.
    let valeur = |chiffre: u8| match chiffre {
        b'0'..=b'9' => chiffre.wrapping_sub(b'0'),
        _ => (chiffre | 0x20).wrapping_sub(b'a').wrapping_add(10),
    };
    let hauts = chiffres.iter().step_by(2);
    let bas = chiffres.iter().skip(1).step_by(2);
    let mut cle = [0_u8; 32];
    for (place, (haut, bas)) in cle.iter_mut().zip(hauts.zip(bas)) {
        *place = valeur(*haut).wrapping_mul(16) | valeur(*bas);
    }
    Some(cle)
}

/// La liste que `GET /v1/racines` rend : `[{racine}, …]`, de une à
/// [`RACINES_MAX`] (décision 56).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListeDeRacines<'a> {
    /// Les racines, les `combien` premières.
    racines: [Option<RacineLue<'a>>; RACINES_MAX],
}

impl<'a> ListeDeRacines<'a> {
    /// Décode une liste.
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage ; [`Erreur::TropDElements`] au-delà de
    /// [`RACINES_MAX`] racines ou de [`LOCATEURS_DE_RACINE_MAX`] locateurs ;
    /// [`Erreur::IdentifiantInvalide`] pour un identifiant qui n'est pas un
    /// `n-…` ; une liste vide aussi — il y a toujours une racine.
    pub fn decoder(octets: &'a [u8]) -> Result<Self, Erreur> {
        borner(octets, asl_proto::cadrage::MESSAGE_MAX)?;
        let mut lecteur = Lecteur::nouveau(octets);
        lecteur.attendre(b'[', "un tableau")?;
        let mut racines = [None; RACINES_MAX];
        let mut combien = 0_usize;
        loop {
            let racine = RacineLue::lire(&mut lecteur)?;
            let place = racines.get_mut(combien).ok_or(Erreur::TropDElements {
                obtenu: combien.saturating_add(1),
            })?;
            *place = Some(racine);
            combien = combien.saturating_add(1);
            lecteur.sauter_blancs();
            match lecteur.regarder() {
                Some(b',') => lecteur.avancer(),
                _ => break,
            }
        }
        lecteur.attendre(b']', "la fin du tableau")?;
        lecteur.fin()?;
        Ok(Self { racines })
    }

    /// Les racines, dans l'ordre de la liste.
    pub fn racines(&self) -> impl Iterator<Item = &RacineLue<'a>> {
        self.racines.iter().flatten()
    }
}

// ── La paire, vue par un membre (0.36.0, décision 70) ───────────────────────

/// Le champ qui porte le pair qu'un membre a réglé.
const CHAMP_PAIR: &str = "pair";

/// Combien de membres un annuaire local a, au plus : un titulaire, un second
/// (décision 49).
pub const MEMBRES_MAX: usize = 2;

/// Ce qu'un membre d'annuaire local conclut de sa paire : ce que les racines
/// lui disent des membres acceptés de son annuaire, comparé à son `--peer`.
///
/// # LES QUATRE MOTS, ET CE QU'ILS DISENT
///
/// | Mot | Quand | Grave ? |
/// |---|---|---|
/// | `seul` | Aucun autre membre accepté, et pas de `--peer`. | Non : un annuaire à un membre. |
/// | `reglee` | `--peer` désigne l'autre membre accepté. | Non : la paire se réplique. |
/// | `sans-peer` | Un autre membre est accepté, et ce membre tourne sans `--peer`. | **Oui** : les deux ne se répliquent pas, chacun frappe ses `s-…`. |
/// | `peer-inconnu` | `--peer` désigne une clé qui n'est celle d'aucun autre membre accepté. | **Oui** : on réplique avec qui n'est pas de l'annuaire, ou avec personne. |
///
/// **Des mots, et non un booléen** : le lecteur d'hier d'une réponse JSON
/// (`asl` 0.16, les applications) ne saute un champ inconnu que si sa valeur
/// est une chaîne ou un nombre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtatDePaire {
    /// Un annuaire à un membre, sans `--peer`.
    Seul,
    /// `--peer` désigne l'autre membre accepté.
    Reglee,
    /// Un autre membre est accepté, et ce membre tourne sans `--peer`.
    SansPeer,
    /// `--peer` ne désigne aucun autre membre accepté.
    PeerInconnu,
}

impl EtatDePaire {
    /// Juge : `moi`, le `n-…` que `--peer-key` donne (s'il est réglé), et les
    /// membres acceptés de l'annuaire, tels que les racines les disent.
    #[must_use]
    pub fn juger(moi: Identifiant, pair: Option<Identifiant>, membres: &[Identifiant]) -> Self {
        let autre = membres.iter().any(|membre| *membre != moi);
        match pair {
            None if autre => Self::SansPeer,
            None => Self::Seul,
            Some(pair) if pair != moi && membres.contains(&pair) => Self::Reglee,
            Some(_) => Self::PeerInconnu,
        }
    }

    /// Le mot, tel qu'il sort dans `GET /v1/version` et `GET /v1/annuaires`.
    #[must_use]
    pub const fn mot(self) -> &'static str {
        match self {
            Self::Seul => "seul",
            Self::Reglee => "reglee",
            Self::SansPeer => "sans-peer",
            Self::PeerInconnu => "peer-inconnu",
        }
    }

    /// Est-ce une erreur de déploiement, à dire fort ?
    #[must_use]
    pub const fn alerte(self) -> bool {
        matches!(self, Self::SansPeer | Self::PeerInconnu)
    }
}

/// La voie de fédération d'un membre vers la racine qui répond, telle que
/// `GET /v1/annuaires` et `GET /v1/inscriptions` la disent (0.38.0,
/// décision 86).
///
/// | Mot | Ce que la racine a constaté |
/// |---|---|
/// | `ouverte` | Le membre a prouvé sa clé et parlé depuis moins de l'expiration d'un rapport (trente secondes). C'est ce qui rend l'`asl-directory` vivant. |
/// | `tombee` | Elle a tenu depuis que la racine tourne, et s'est tue au-delà, ou s'est fermée. |
///
/// **Absente** (`None` dans [`InscriptionRendue`]) tant que le membre n'a
/// pas parlé à cette racine depuis son démarrage : l'état vivant ne s'écrit
/// pas, et une racine qui redémarre n'affirme pas ce qu'elle n'a pas vu (C6).
/// **Des mots ASCII, et non un booléen**, pour la raison d'[`EtatDePaire`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtatDeVoie {
    /// La voie tient.
    Ouverte,
    /// Elle a tenu, et s'est tue ou fermée.
    Tombee,
}

impl EtatDeVoie {
    /// Le mot, tel qu'il sort dans `GET /v1/annuaires`.
    #[must_use]
    pub const fn mot(self) -> &'static str {
        match self {
            Self::Ouverte => "ouverte",
            Self::Tombee => "tombee",
        }
    }
}

/// Le corps de `PUT /v1/federation/paire` : le pair qu'un membre a réglé,
/// `{"pair":"n-…"}`, ou `{"pair":null}` sans `--peer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclarationDePair {
    /// Le `n-…` que la clé de `--peer-key` donne, s'il y en a une.
    pub pair: Option<Identifiant>,
}

impl DeclarationDePair {
    /// Décode une déclaration.
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage, plus [`Erreur::IdentifiantInvalide`] quand ce n'est
    /// ni `null` ni un `n-…`.
    pub fn decoder(octets: &[u8]) -> Result<Self, Erreur> {
        let mut lecteur = ouvrir(octets, CHAMP_PAIR)?;
        lecteur.sauter_blancs();
        let pair = if lecteur.mot("null") {
            None
        } else {
            let position = lecteur.position();
            Some(
                Identifiant::analyser_genre(Genre::Annuaire, lecteur.chaine()?)
                    .map_err(|_| Erreur::IdentifiantInvalide { position })?,
            )
        };
        fermer(&mut lecteur)?;
        Ok(Self { pair })
    }

    /// Encode la déclaration en JSON.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`] si `sortie` ne suffit pas.
    pub fn encoder(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        let mut ecrivain = Ecrivain::nouveau(sortie);
        ecrivain.pousser(b"{\"pair\":");
        match self.pair {
            Some(pair) => {
                ecrivain.pousser(b"\"");
                ecrivain.pousser(pair.texte().as_str().as_bytes());
                ecrivain.pousser(b"\"");
            }
            None => ecrivain.pousser(b"null"),
        }
        ecrivain.pousser(b"}");
        ecrivain.achever()
    }
}

/// La réponse de `PUT /v1/federation/paire` : l'annuaire du membre qui
/// demande — son titulaire — et ses membres acceptés, lui compris.
///
/// ```jsonc
/// {"annuaire":"n-titulaire","membres":["n-titulaire","n-second"]}
/// ```
///
/// C'est ce que les racines disent au membre ; c'est **lui** qui en conclut
/// ([`EtatDePaire::juger`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaireRendue {
    /// L'annuaire : son titulaire.
    pub annuaire: Identifiant,
    /// Ses membres acceptés — un ou deux —, les `combien` premiers.
    membres: [Option<Identifiant>; MEMBRES_MAX],
}

impl PaireRendue {
    /// Une paire, de ces membres — au-delà de [`MEMBRES_MAX`], ils ne sont pas
    /// pris.
    #[must_use]
    pub fn nouvelle(annuaire: Identifiant, membres: &[Identifiant]) -> Self {
        let mut places = [None; MEMBRES_MAX];
        for (place, membre) in places.iter_mut().zip(membres) {
            *place = Some(*membre);
        }
        Self {
            annuaire,
            membres: places,
        }
    }

    /// Les membres acceptés.
    pub fn membres(&self) -> impl Iterator<Item = Identifiant> + '_ {
        self.membres.iter().flatten().copied()
    }

    /// Encode la paire en JSON.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`] si `sortie` ne suffit pas.
    pub fn encoder(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        let mut ecrivain = Ecrivain::nouveau(sortie);
        ecrivain.pousser(b"{\"annuaire\":\"");
        ecrivain.pousser(self.annuaire.texte().as_str().as_bytes());
        ecrivain.pousser(b"\",\"membres\":[");
        for (rang, membre) in self.membres.iter().flatten().enumerate() {
            if rang > 0 {
                ecrivain.pousser(b",");
            }
            ecrivain.pousser(b"\"");
            ecrivain.pousser(membre.texte().as_str().as_bytes());
            ecrivain.pousser(b"\"");
        }
        ecrivain.pousser(b"]}");
        ecrivain.achever()
    }

    /// Décode une paire.
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage ; [`Erreur::IdentifiantInvalide`] pour ce qui n'est
    /// pas un `n-…` ; [`Erreur::TropDElements`] au-delà de [`MEMBRES_MAX`].
    pub fn decoder(octets: &[u8]) -> Result<Self, Erreur> {
        let mut lecteur = ouvrir(octets, CHAMP_ANNUAIRE)?;
        let annuaire = n_de(&mut lecteur)?;
        lecteur.attendre(b',', "une virgule")?;
        champ(&mut lecteur, "membres")?;
        let mut textes = [""; MEMBRES_MAX];
        let combien = tableau_de_chaines(&mut lecteur, &mut textes)?;
        let mut membres = [None; MEMBRES_MAX];
        for (place, texte) in membres.iter_mut().zip(textes.iter().take(combien)) {
            *place = Some(
                Identifiant::analyser_genre(Genre::Annuaire, texte).map_err(|_| {
                    Erreur::IdentifiantInvalide {
                        position: lecteur.position(),
                    }
                })?,
            );
        }
        fermer(&mut lecteur)?;
        Ok(Self { annuaire, membres })
    }
}

/// Lit une chaîne qui doit être un `n-…`.
fn n_de(lecteur: &mut Lecteur<'_>) -> Result<Identifiant, Erreur> {
    let position = lecteur.position();
    Identifiant::analyser_genre(Genre::Annuaire, lecteur.chaine()?)
        .map_err(|_| Erreur::IdentifiantInvalide { position })
}

/// Écrit un entier en décimal, sans allocation : vingt chiffres suffisent à
/// un `u64`.
fn ecrire_un_entier(valeur: u64, tampon: &mut [u8; 20]) -> &[u8] {
    let mut reste = valeur;
    let mut debut = tampon.len();
    for place in tampon.iter_mut().rev() {
        *place = b'0'.saturating_add(u8::try_from(reste % 10).unwrap_or(0));
        reste /= 10;
        debut = debut.saturating_sub(1);
        if reste == 0 {
            break;
        }
    }
    tampon.get(debut..).unwrap_or_default()
}
