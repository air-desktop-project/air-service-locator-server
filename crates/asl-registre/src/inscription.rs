//! L'inscription d'un annuaire local (`docs/annuaires.md` §2 ter, §4.1 ;
//! `docs/replication.md` décisions 32, 48, 49, 57) : ce que les racines rangent
//! quand un propriétaire déclare son annuaire, quand l'annuaire se présente
//! avec sa clé, quand un administrateur tranche, et quand un domaine lui est
//! confié.
//!
//! # CINQ FAITS, ET AUCUN N'EST UN ÉTAT
//!
//! L'état d'une inscription — attendue, en attente, acceptée, refusée,
//! retirée — **ne s'écrit nulle part** : il se LIT, depuis cinq faits qui ont
//! chacun leur règle de convergence (la discipline des décisions 42 et 43) :
//!
//! | Fait | Rangé sous | Règle |
//! |---|---|---|
//! | [`Inscription`] — la déclaration, avec le code émis | l'empreinte du code | insérer si absente |
//! | [`Presentation`] — la clé qui a présenté ce code | l'empreinte du code | la plus petite estampille |
//! | l'acceptation d'un membre ([`MarqueDInscription`]) | le `n-…` du membre | la plus petite estampille |
//! | le refus d'un membre ([`MarqueDInscription`]) | le `n-…` du membre | la plus petite estampille |
//! | le retrait d'un membre ([`MarqueDInscription`]) | le `n-…` du membre | la plus petite estampille |
//!
//! Un refus l'emporte sur une acceptation, un retrait sur tout le reste — et
//! ce n'est pas une règle d'écriture, c'est la lecture qui le dit. Deux
//! racines qui ont reçu les mêmes faits dans deux ordres lisent la même chose.
//!
//! L'hébergement d'un domaine ([`Hebergement`]) est le cinquième : le plus
//! récent gagne, et il ne VAUT que si l'annuaire nommé est accepté et
//! appartient au propriétaire du domaine — encore une lecture.
//!
//! Les locateurs d'un membre ([`Locateurs`], décision 57, 0.30.0) sont le
//! dernier : publiés par le membre lui-même, le plus récent gagne, et vides
//! ils rendent la parole à l'adresse déclarée — encore une lecture.

use asl_id::{Genre, Identifiant};

use crate::{
    CLE_OCTETS, ESTAMPILLE_OCTETS, Estampille, Faute, IDENTIFIANT_OCTETS, PROVENANCE_OCTETS,
    Provenance, bourrage_nul, ecrire_identifiant, lire_identifiant, poser, poser_un,
};

// ── L'adresse déclarée ──────────────────────────────────────────────────────

/// La longueur maximale d'une adresse déclarée : `hôte:port`.
///
/// Deux cent cinquante-cinq octets : un nom DNS en fait au plus deux cent
/// cinquante-trois, et la longueur tient sur un octet.
pub const ADRESSE_OCTETS_MAX: usize = 255;

/// Ce qu'une adresse occupe rangée : sa longueur, puis ses octets.
pub const ADRESSE_OCTETS: usize = 1 + ADRESSE_OCTETS_MAX;

/// L'adresse qu'un propriétaire déclare pour son annuaire local — `hôte:port`.
///
/// # CE QU'ELLE EST, ET CE QU'ELLE N'EST PAS
///
/// C'est l'adresse **que les daemons de ses domaines emploient** pour joindre
/// l'annuaire (`docs/annuaires.md` §7, question 9). Les racines ne s'en servent
/// jamais pour ouvrir : c'est l'annuaire qui ouvre vers elles. Elles la
/// rangent pour la dire — à son propriétaire, aux administrateurs qui
/// tranchent l'inscription.
///
/// # LA RÈGLE, ET POURQUOI SI PEU
///
/// De l'ASCII imprimable, sans espace ; un `:` dont ce qui suit est un port de
/// 1 à 65 535 écrit sans zéro en tête ; un hôte non vide avant lui, entre
/// crochets s'il en porte. **Ni résolution, ni vérification d'appartenance** :
/// l'adresse est une déclaration, pas une preuve, et un annuaire à la maison
/// peut n'avoir qu'une adresse privée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Adresse {
    /// Combien d'octets portent quelque chose.
    longueur: u8,
    /// Les octets, bourrés de zéros.
    octets: [u8; ADRESSE_OCTETS_MAX],
}

impl Adresse {
    /// Lit une adresse déclarée.
    ///
    /// # Errors
    ///
    /// [`Faute::Vide`] pour une adresse vide, [`Faute::Longueur`] au-delà de
    /// [`ADRESSE_OCTETS_MAX`], [`Faute::NonImprimable`] pour un octet hors de
    /// l'ASCII imprimable sans espace — ni `"` ni `\` —, [`Faute::Forme`]
    /// sans port ou sans hôte.
    pub fn nouvelle(texte: &str) -> Result<Self, Faute> {
        let octets = texte.as_bytes();
        if octets.is_empty() {
            return Err(Faute::Vide);
        }
        if octets.len() > ADRESSE_OCTETS_MAX {
            return Err(Faute::Longueur {
                annoncee: octets.len(),
                maximum: ADRESSE_OCTETS_MAX,
            });
        }
        // Ni `"` ni `\` : l'adresse se réémet en JSON sans échappement.
        if let Some(position) = octets
            .iter()
            .position(|octet| !octet.is_ascii_graphic() || matches!(octet, b'"' | b'\\'))
        {
            return Err(Faute::NonImprimable { position });
        }
        if !forme_hote_port(texte) {
            return Err(Faute::Forme);
        }
        let mut rangee = [0_u8; ADRESSE_OCTETS_MAX];
        poser(&mut rangee, octets);
        Ok(Self {
            longueur: u8::try_from(octets.len()).unwrap_or(u8::MAX),
            octets: rangee,
        })
    }

    /// Le texte.
    #[must_use]
    pub fn texte(&self) -> &str {
        let utiles = self
            .octets
            .get(..usize::from(self.longueur))
            .unwrap_or_default();
        core::str::from_utf8(utiles).unwrap_or("")
    }

    /// Écrit cette adresse. Occupe [`ADRESSE_OCTETS`].
    fn ecrire(&self, sortie: &mut [u8]) {
        sortie.fill(0);
        poser_un(sortie, self.longueur);
        poser(
            sortie.get_mut(1..).unwrap_or_default(),
            self.octets
                .get(..usize::from(self.longueur))
                .unwrap_or_default(),
        );
    }

    /// Relit une adresse, et EXIGE sa forme : un disque ou un pair ne fait
    /// pas entrer ce que [`Adresse::nouvelle`] aurait refusé.
    fn lire(octets: &[u8]) -> Result<Self, Faute> {
        let longueur = usize::from(octets.first().copied().unwrap_or(0));
        let corps = octets.get(1..).unwrap_or_default();
        if !bourrage_nul(corps.get(longueur..).unwrap_or_default()) {
            return Err(Faute::Bourrage);
        }
        let utiles = corps.get(..longueur).unwrap_or_default();
        let texte = core::str::from_utf8(utiles).map_err(|_| Faute::NonNormalise)?;
        Self::nouvelle(texte)
    }
}

/// `hôte:port` : un hôte non vide, puis un port de 1 à 65 535, sans zéro en
/// tête. Un hôte qui commence par `[` doit finir par `]`, et réciproquement.
fn forme_hote_port(texte: &str) -> bool {
    let Some((hote, port)) = texte.rsplit_once(':') else {
        return false;
    };
    let crochets = hote.starts_with('[') || hote.ends_with(']');
    let hote_valide = if crochets {
        hote.len() > 2 && hote.starts_with('[') && hote.ends_with(']')
    } else {
        !hote.is_empty() && !hote.contains(':')
    };
    let port_valide = !port.starts_with('0')
        && port.bytes().all(|octet| octet.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|valeur| valeur > 0);
    hote_valide && port_valide
}

// ── La déclaration ──────────────────────────────────────────────────────────

/// Ce qu'une déclaration occupe rangée.
pub const INSCRIPTION_OCTETS: usize = PROVENANCE_OCTETS
    + ESTAMPILLE_OCTETS
    + IDENTIFIANT_OCTETS
    + 1
    + IDENTIFIANT_OCTETS
    + 8
    + ADRESSE_OCTETS;

/// Une déclaration d'annuaire local — ou de second membre — et le code émis
/// pour elle, rangée sous l'empreinte de ce code (`protocole.md` §2.2,
/// `POST /v1/annuaires` et `POST /v1/annuaires/{n}/membres`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inscription {
    /// D'où vient cet enregistrement.
    pub provenance: Provenance,
    /// La déclaration.
    pub estampille: Estampille,
    /// Le compte qui déclare — celui à qui l'annuaire appartient (décision 48).
    pub proprietaire: Identifiant,
    /// Rien pour un annuaire neuf ; le `n-…` de son titulaire pour un second
    /// membre (décision 49).
    pub annuaire: Option<Identifiant>,
    /// Jusqu'à quand le code se présente, en millisecondes d'époque.
    pub expire_a: u64,
    /// L'adresse déclarée.
    pub adresse: Adresse,
}

impl Inscription {
    /// Écrit cette déclaration.
    pub fn ecrire(&self, sortie: &mut [u8; INSCRIPTION_OCTETS]) {
        sortie.fill(0);
        let mut place = 0_usize;
        self.provenance
            .ecrire(sortie.get_mut(place..).unwrap_or_default());
        place = place.saturating_add(PROVENANCE_OCTETS);
        self.estampille
            .ecrire(sortie.get_mut(place..).unwrap_or_default());
        place = place.saturating_add(ESTAMPILLE_OCTETS);
        ecrire_identifiant(
            self.proprietaire,
            sortie.get_mut(place..).unwrap_or_default(),
        );
        place = place.saturating_add(IDENTIFIANT_OCTETS);
        if let Some(annuaire) = self.annuaire {
            let reste = sortie.get_mut(place..).unwrap_or_default();
            poser_un(reste, 1);
            ecrire_identifiant(annuaire, reste.get_mut(1..).unwrap_or_default());
        }
        place = place.saturating_add(1 + IDENTIFIANT_OCTETS);
        poser(
            sortie.get_mut(place..).unwrap_or_default(),
            &self.expire_a.to_be_bytes(),
        );
        place = place.saturating_add(8);
        self.adresse
            .ecrire(sortie.get_mut(place..).unwrap_or_default());
    }

    /// Relit une déclaration.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas une déclaration.
    pub fn lire(octets: &[u8; INSCRIPTION_OCTETS]) -> Result<Self, Faute> {
        let mut place = 0_usize;
        let provenance = Provenance::lire(
            octets
                .get(place..place.saturating_add(PROVENANCE_OCTETS))
                .unwrap_or_default(),
        )?;
        place = place.saturating_add(PROVENANCE_OCTETS);
        let estampille = Estampille::lire(
            octets
                .get(place..place.saturating_add(ESTAMPILLE_OCTETS))
                .unwrap_or_default(),
        )?;
        place = place.saturating_add(ESTAMPILLE_OCTETS);
        let proprietaire =
            lire_identifiant(octets.get(place..).unwrap_or_default(), Genre::Utilisateur)?;
        place = place.saturating_add(IDENTIFIANT_OCTETS);
        let zone = octets
            .get(place..place.saturating_add(1 + IDENTIFIANT_OCTETS))
            .unwrap_or_default();
        let annuaire = lire_une_option(zone, Genre::Annuaire)?;
        place = place.saturating_add(1 + IDENTIFIANT_OCTETS);
        let mut quand = [0_u8; 8];
        poser(&mut quand, octets.get(place..).unwrap_or_default());
        place = place.saturating_add(8);
        let adresse = Adresse::lire(octets.get(place..).unwrap_or_default())?;
        Ok(Self {
            provenance,
            estampille,
            proprietaire,
            annuaire,
            expire_a: u64::from_be_bytes(quand),
            adresse,
        })
    }
}

/// Relit `drapeau ‖ identifiant` : rien, ou un identifiant de ce genre.
fn lire_une_option(zone: &[u8], genre: Genre) -> Result<Option<Identifiant>, Faute> {
    match zone.first().copied().unwrap_or(0) {
        0 => {
            if bourrage_nul(zone.get(1..).unwrap_or_default()) {
                Ok(None)
            } else {
                Err(Faute::Bourrage)
            }
        }
        1 => Ok(Some(lire_identifiant(
            zone.get(1..).unwrap_or_default(),
            genre,
        )?)),
        lue => Err(Faute::Etiquette { lue }),
    }
}

// ── La présentation ─────────────────────────────────────────────────────────

/// Ce qu'une présentation occupe rangée.
pub const PRESENTATION_OCTETS: usize =
    PROVENANCE_OCTETS + ESTAMPILLE_OCTETS + IDENTIFIANT_OCTETS + CLE_OCTETS;

/// La clé d'identité qui a présenté un code — `POST /v1/annuaires/inscription`
/// —, rangée sous l'empreinte de ce code.
///
/// **Le `n-…` se déduit de la clé** (`asl_cle::identifiant_de_racine`) ;
/// l'écrire à côté ne sert qu'à le chercher sans la recalculer. Deux clés qui
/// présenteraient le même code sur deux racines dans la même fenêtre : **la
/// plus petite estampille** tient — la seule règle qui ne dépende pas de
/// l'ordre d'arrivée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Presentation {
    /// D'où vient cet enregistrement.
    pub provenance: Provenance,
    /// La présentation.
    pub estampille: Estampille,
    /// Le membre : le `n-…` de la clé.
    pub membre: Identifiant,
    /// La clé publique d'identité.
    pub cle: [u8; CLE_OCTETS],
}

impl Presentation {
    /// Écrit cette présentation.
    pub fn ecrire(&self, sortie: &mut [u8; PRESENTATION_OCTETS]) {
        sortie.fill(0);
        self.provenance
            .ecrire(sortie.get_mut(..PROVENANCE_OCTETS).unwrap_or_default());
        let apres_estampille = PROVENANCE_OCTETS.saturating_add(ESTAMPILLE_OCTETS);
        self.estampille.ecrire(
            sortie
                .get_mut(PROVENANCE_OCTETS..apres_estampille)
                .unwrap_or_default(),
        );
        ecrire_identifiant(
            self.membre,
            sortie.get_mut(apres_estampille..).unwrap_or_default(),
        );
        poser(
            sortie
                .get_mut(apres_estampille.saturating_add(IDENTIFIANT_OCTETS)..)
                .unwrap_or_default(),
            &self.cle,
        );
    }

    /// Relit une présentation.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas une présentation.
    pub fn lire(octets: &[u8; PRESENTATION_OCTETS]) -> Result<Self, Faute> {
        let provenance = Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?;
        let apres_estampille = PROVENANCE_OCTETS.saturating_add(ESTAMPILLE_OCTETS);
        let estampille = Estampille::lire(
            octets
                .get(PROVENANCE_OCTETS..apres_estampille)
                .unwrap_or_default(),
        )?;
        let membre = lire_identifiant(
            octets.get(apres_estampille..).unwrap_or_default(),
            Genre::Annuaire,
        )?;
        let mut cle = [0_u8; CLE_OCTETS];
        poser(
            &mut cle,
            octets
                .get(apres_estampille.saturating_add(IDENTIFIANT_OCTETS)..)
                .unwrap_or_default(),
        );
        Ok(Self {
            provenance,
            estampille,
            membre,
            cle,
        })
    }
}

// ── Les marques : acceptation, refus, retrait ───────────────────────────────

/// Ce qu'une marque occupe rangée.
pub const MARQUE_D_INSCRIPTION_OCTETS: usize = ESTAMPILLE_OCTETS + IDENTIFIANT_OCTETS;

/// L'acceptation, le refus ou le retrait d'un membre : quand, et par qui.
///
/// **La plus petite estampille tient** (`replication.md` §3.2) : deux
/// administrateurs qui acceptent le même membre sur les deux racines, ou deux
/// retraits qui se croisent, laissent la même marque quel que soit l'ordre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarqueDInscription {
    /// Le geste.
    pub estampille: Estampille,
    /// Le compte qui l'a fait — un administrateur des racines pour une
    /// décision, le propriétaire ou un administrateur pour un retrait.
    pub par: Identifiant,
}

impl MarqueDInscription {
    /// Écrit cette marque.
    pub fn ecrire(&self, sortie: &mut [u8; MARQUE_D_INSCRIPTION_OCTETS]) {
        sortie.fill(0);
        self.estampille
            .ecrire(sortie.get_mut(..ESTAMPILLE_OCTETS).unwrap_or_default());
        ecrire_identifiant(
            self.par,
            sortie.get_mut(ESTAMPILLE_OCTETS..).unwrap_or_default(),
        );
    }

    /// Relit une marque.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas une marque.
    pub fn lire(octets: &[u8; MARQUE_D_INSCRIPTION_OCTETS]) -> Result<Self, Faute> {
        Ok(Self {
            estampille: Estampille::lire(octets.get(..ESTAMPILLE_OCTETS).unwrap_or_default())?,
            par: lire_identifiant(
                octets.get(ESTAMPILLE_OCTETS..).unwrap_or_default(),
                Genre::Utilisateur,
            )?,
        })
    }
}

// ── L'hébergement d'un domaine ──────────────────────────────────────────────

/// Ce qu'un hébergement occupe rangé.
pub const HEBERGEMENT_OCTETS: usize =
    PROVENANCE_OCTETS + ESTAMPILLE_OCTETS + 1 + IDENTIFIANT_OCTETS;

/// À quel annuaire local un domaine est confié — ou rendu aux racines, avec
/// `annuaire: None`. **Le plus récent gagne**, et un retour aux racines garde
/// son estampille pour qu'un hébergement plus ancien arrivé en retard ne le
/// défasse pas.
///
/// Il ne VAUT que si l'annuaire nommé est accepté, vivant, et appartient au
/// propriétaire du domaine (décision 48) : c'est la lecture qui le dit, et un
/// hébergement qui ne vaut plus se lit « racines » sans rien réécrire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hebergement {
    /// D'où vient cet enregistrement.
    pub provenance: Provenance,
    /// Le dernier geste.
    pub estampille: Estampille,
    /// L'annuaire — son titulaire —, ou rien : les racines.
    pub annuaire: Option<Identifiant>,
}

impl Hebergement {
    /// Écrit cet hébergement.
    pub fn ecrire(&self, sortie: &mut [u8; HEBERGEMENT_OCTETS]) {
        sortie.fill(0);
        self.provenance
            .ecrire(sortie.get_mut(..PROVENANCE_OCTETS).unwrap_or_default());
        let apres_estampille = PROVENANCE_OCTETS.saturating_add(ESTAMPILLE_OCTETS);
        self.estampille.ecrire(
            sortie
                .get_mut(PROVENANCE_OCTETS..apres_estampille)
                .unwrap_or_default(),
        );
        if let Some(annuaire) = self.annuaire {
            let reste = sortie.get_mut(apres_estampille..).unwrap_or_default();
            poser_un(reste, 1);
            ecrire_identifiant(annuaire, reste.get_mut(1..).unwrap_or_default());
        }
    }

    /// Relit un hébergement.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas un hébergement.
    pub fn lire(octets: &[u8; HEBERGEMENT_OCTETS]) -> Result<Self, Faute> {
        let provenance = Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?;
        let apres_estampille = PROVENANCE_OCTETS.saturating_add(ESTAMPILLE_OCTETS);
        let estampille = Estampille::lire(
            octets
                .get(PROVENANCE_OCTETS..apres_estampille)
                .unwrap_or_default(),
        )?;
        let annuaire = lire_une_option(
            octets.get(apres_estampille..).unwrap_or_default(),
            Genre::Annuaire,
        )?;
        Ok(Self {
            provenance,
            estampille,
            annuaire,
        })
    }
}

// ── Les locateurs d'un membre (décision 57) ─────────────────────────────────

/// Combien de locateurs un membre publie, au plus — le même nombre que
/// `asl_api::annuaire::LOCATEURS_MAX`, que le corps ne dépasse pas.
pub const LOCATEURS_MAX: usize = 4;

/// Ce que des locateurs occupent rangés.
pub const LOCATEURS_OCTETS: usize =
    PROVENANCE_OCTETS + ESTAMPILLE_OCTETS + 1 + LOCATEURS_MAX * ADRESSE_OCTETS;

/// Où joindre un membre d'annuaire local, tel qu'il l'a publié lui-même
/// (décision 57) — **le plus récent gagne**, par membre.
///
/// Aucune valeur de confiance : on joint un locateur, on attend une identité
/// (`protocole.md` §0). **Vide, c'est un retrait** : l'adresse déclarée à
/// l'inscription sert de nouveau, et le retrait garde son estampille pour
/// qu'une publication plus ancienne, arrivée en retard, ne le défasse pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Locateurs {
    /// D'où vient cet enregistrement.
    pub provenance: Provenance,
    /// La publication.
    pub estampille: Estampille,
    /// Les locateurs, les `combien` premiers.
    adresses: [Option<Adresse>; LOCATEURS_MAX],
}

impl Locateurs {
    /// Des locateurs publiés — de zéro à [`LOCATEURS_MAX`].
    ///
    /// # Errors
    ///
    /// [`Faute::Longueur`] au-delà de [`LOCATEURS_MAX`].
    pub fn nouveaux(
        provenance: Provenance,
        estampille: Estampille,
        publies: &[Adresse],
    ) -> Result<Self, Faute> {
        if publies.len() > LOCATEURS_MAX {
            return Err(Faute::Longueur {
                annoncee: publies.len(),
                maximum: LOCATEURS_MAX,
            });
        }
        let mut adresses = [None; LOCATEURS_MAX];
        for (place, adresse) in adresses.iter_mut().zip(publies) {
            *place = Some(*adresse);
        }
        Ok(Self {
            provenance,
            estampille,
            adresses,
        })
    }

    /// Les locateurs, dans l'ordre publié.
    pub fn adresses(&self) -> impl Iterator<Item = &Adresse> {
        self.adresses.iter().flatten()
    }

    /// Écrit ces locateurs.
    pub fn ecrire(&self, sortie: &mut [u8; LOCATEURS_OCTETS]) {
        sortie.fill(0);
        self.provenance
            .ecrire(sortie.get_mut(..PROVENANCE_OCTETS).unwrap_or_default());
        let apres_estampille = PROVENANCE_OCTETS.saturating_add(ESTAMPILLE_OCTETS);
        self.estampille.ecrire(
            sortie
                .get_mut(PROVENANCE_OCTETS..apres_estampille)
                .unwrap_or_default(),
        );
        let combien = self.adresses().count();
        poser_un(
            sortie.get_mut(apres_estampille..).unwrap_or_default(),
            u8::try_from(combien).unwrap_or(0),
        );
        for (rang, adresse) in self.adresses().enumerate() {
            let debut = apres_estampille
                .saturating_add(1)
                .saturating_add(rang.saturating_mul(ADRESSE_OCTETS));
            adresse.ecrire(
                sortie
                    .get_mut(debut..debut.saturating_add(ADRESSE_OCTETS))
                    .unwrap_or_default(),
            );
        }
    }

    /// Relit des locateurs, et EXIGE leur forme : un compte au plus de
    /// [`LOCATEURS_MAX`], des emplacements inutilisés nuls.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas des locateurs.
    pub fn lire(octets: &[u8; LOCATEURS_OCTETS]) -> Result<Self, Faute> {
        let provenance = Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?;
        let apres_estampille = PROVENANCE_OCTETS.saturating_add(ESTAMPILLE_OCTETS);
        let estampille = Estampille::lire(
            octets
                .get(PROVENANCE_OCTETS..apres_estampille)
                .unwrap_or_default(),
        )?;
        let combien = usize::from(octets.get(apres_estampille).copied().unwrap_or(0));
        if combien > LOCATEURS_MAX {
            return Err(Faute::Longueur {
                annoncee: combien,
                maximum: LOCATEURS_MAX,
            });
        }
        let mut adresses = [None; LOCATEURS_MAX];
        for (rang, place) in adresses.iter_mut().enumerate() {
            let debut = apres_estampille
                .saturating_add(1)
                .saturating_add(rang.saturating_mul(ADRESSE_OCTETS));
            let tranche = octets
                .get(debut..debut.saturating_add(ADRESSE_OCTETS))
                .unwrap_or_default();
            if rang < combien {
                *place = Some(Adresse::lire(tranche)?);
            } else if !bourrage_nul(tranche) {
                return Err(Faute::Bourrage);
            }
        }
        Ok(Self {
            provenance,
            estampille,
            adresses,
        })
    }
}

#[cfg(test)]
mod tests {
    use asl_id::{Genre, Identifiant};

    use super::{
        ADRESSE_OCTETS, ADRESSE_OCTETS_MAX, Adresse, HEBERGEMENT_OCTETS, Hebergement,
        INSCRIPTION_OCTETS, Inscription, MARQUE_D_INSCRIPTION_OCTETS, MarqueDInscription,
        PRESENTATION_OCTETS, Presentation, lire_une_option,
    };
    use crate::{
        ESTAMPILLE_OCTETS, Estampille, Faute, IDENTIFIANT_OCTETS, PROVENANCE_OCTETS, Provenance,
    };

    fn un(genre: Genre, graine: u8) -> Identifiant {
        Identifiant::depuis_entropie(genre, [graine; 16])
    }

    fn e(compteur: u64) -> Estampille {
        Estampille {
            compteur,
            racine: un(Genre::Annuaire, 0xEE),
        }
    }

    #[test]
    fn une_adresse_est_hote_port_et_rien_d_autre() {
        for bonne in [
            "speedy.maison:6630",
            "[2001:db8::1]:6630",
            "192.168.1.102:1",
            "a:65535",
        ] {
            assert_eq!(Adresse::nouvelle(bonne).unwrap().texte(), bonne, "{bonne}");
        }
        assert_eq!(Adresse::nouvelle(""), Err(Faute::Vide));
        let longue = "a".repeat(ADRESSE_OCTETS_MAX + 1);
        assert_eq!(
            Adresse::nouvelle(&longue),
            Err(Faute::Longueur {
                annoncee: ADRESSE_OCTETS_MAX + 1,
                maximum: ADRESSE_OCTETS_MAX
            })
        );
        assert_eq!(
            Adresse::nouvelle("a b:1"),
            Err(Faute::NonImprimable { position: 1 })
        );
        assert_eq!(
            Adresse::nouvelle("a\"b:1"),
            Err(Faute::NonImprimable { position: 1 })
        );
        assert_eq!(
            Adresse::nouvelle("a\\b:1"),
            Err(Faute::NonImprimable { position: 1 })
        );
        for mauvaise in [
            "sansport",
            ":6630",
            "hote:",
            "hote:0",
            "hote:06630",
            "hote:65536",
            "hote:66a",
            "[2001:db8::1:6630",
            "2001:db8::1]:6630",
            "[]:6630",
            "2001:db8::1:6630",
        ] {
            assert_eq!(Adresse::nouvelle(mauvaise), Err(Faute::Forme), "{mauvaise}");
        }
    }

    #[test]
    fn une_adresse_relue_exige_sa_forme() {
        let adresse = Adresse::nouvelle("speedy:6630").unwrap();
        let mut octets = [0_u8; ADRESSE_OCTETS];
        adresse.ecrire(&mut octets);
        assert_eq!(Adresse::lire(&octets), Ok(adresse));
        let mut bourree = octets;
        bourree[ADRESSE_OCTETS - 1] = 1;
        assert_eq!(Adresse::lire(&bourree), Err(Faute::Bourrage));
        let mut non_utf8 = [0_u8; ADRESSE_OCTETS];
        non_utf8[0] = 1;
        non_utf8[1] = 0xFF;
        assert_eq!(Adresse::lire(&non_utf8), Err(Faute::NonNormalise));
        let mut sans_port = [0_u8; ADRESSE_OCTETS];
        sans_port[0] = 3;
        sans_port[1..4].copy_from_slice(b"abc");
        assert_eq!(Adresse::lire(&sans_port), Err(Faute::Forme));
    }

    #[test]
    fn une_declaration_fait_l_aller_retour_avec_ou_sans_titulaire() {
        for annuaire in [None, Some(un(Genre::Annuaire, 7))] {
            let declaree = Inscription {
                provenance: Provenance::Annuaire(un(Genre::Annuaire, 9)),
                estampille: e(4),
                proprietaire: un(Genre::Utilisateur, 1),
                annuaire,
                expire_a: 1_790_000_000_000,
                adresse: Adresse::nouvelle("speedy:6630").unwrap(),
            };
            let mut octets = [0_u8; INSCRIPTION_OCTETS];
            declaree.ecrire(&mut octets);
            assert_eq!(Inscription::lire(&octets), Ok(declaree));
        }
    }

    #[test]
    fn une_declaration_corrompue_ne_se_relit_pas() {
        let declaree = Inscription {
            provenance: Provenance::Ici,
            estampille: e(4),
            proprietaire: un(Genre::Utilisateur, 1),
            annuaire: None,
            expire_a: 1,
            adresse: Adresse::nouvelle("speedy:6630").unwrap(),
        };
        let mut octets = [0_u8; INSCRIPTION_OCTETS];
        declaree.ecrire(&mut octets);
        let place_proprio = PROVENANCE_OCTETS + ESTAMPILLE_OCTETS;
        let place_option = place_proprio + IDENTIFIANT_OCTETS;

        let mut provenance = octets;
        provenance[0] = 9;
        assert!(Inscription::lire(&provenance).is_err());
        let mut estampille = octets;
        estampille[PROVENANCE_OCTETS + 8] = b'u';
        assert!(Inscription::lire(&estampille).is_err());
        let mut proprio = octets;
        proprio[place_proprio] = b'm';
        assert!(Inscription::lire(&proprio).is_err());
        let mut option = octets;
        option[place_option] = 2;
        assert_eq!(Inscription::lire(&option), Err(Faute::Etiquette { lue: 2 }));
        let mut adresse = octets;
        let fin = INSCRIPTION_OCTETS - 1;
        adresse[fin] = 1;
        assert_eq!(Inscription::lire(&adresse), Err(Faute::Bourrage));
    }

    #[test]
    fn une_option_se_relit_rien_ou_un_identifiant() {
        let mut zone = [0_u8; 1 + IDENTIFIANT_OCTETS];
        assert_eq!(lire_une_option(&zone, Genre::Annuaire), Ok(None));
        zone[3] = 1;
        assert_eq!(
            lire_une_option(&zone, Genre::Annuaire),
            Err(Faute::Bourrage)
        );
        zone[0] = 1;
        zone[1] = b'u';
        assert_eq!(
            lire_une_option(&zone, Genre::Annuaire),
            Err(Faute::Genre {
                attendu: Genre::Annuaire
            })
        );
    }

    #[test]
    fn une_presentation_fait_l_aller_retour() {
        let presentee = Presentation {
            provenance: Provenance::Ici,
            estampille: e(5),
            membre: un(Genre::Annuaire, 3),
            cle: [0x42; 32],
        };
        let mut octets = [0_u8; PRESENTATION_OCTETS];
        presentee.ecrire(&mut octets);
        assert_eq!(Presentation::lire(&octets), Ok(presentee));
        let mut provenance = octets;
        provenance[0] = 9;
        assert!(Presentation::lire(&provenance).is_err());
        let mut estampille = octets;
        estampille[PROVENANCE_OCTETS + 8] = b'u';
        assert!(Presentation::lire(&estampille).is_err());
        let mut membre = octets;
        membre[PROVENANCE_OCTETS + ESTAMPILLE_OCTETS] = b'm';
        assert!(Presentation::lire(&membre).is_err());
    }

    #[test]
    fn une_marque_fait_l_aller_retour() {
        let marque = MarqueDInscription {
            estampille: e(6),
            par: un(Genre::Utilisateur, 2),
        };
        let mut octets = [0_u8; MARQUE_D_INSCRIPTION_OCTETS];
        marque.ecrire(&mut octets);
        assert_eq!(MarqueDInscription::lire(&octets), Ok(marque));
        let mut estampille = octets;
        estampille[8] = b'u';
        assert!(MarqueDInscription::lire(&estampille).is_err());
        let mut par = octets;
        par[ESTAMPILLE_OCTETS] = b'n';
        assert!(MarqueDInscription::lire(&par).is_err());
    }

    #[test]
    fn un_hebergement_fait_l_aller_retour() {
        for annuaire in [None, Some(un(Genre::Annuaire, 8))] {
            let heberge = Hebergement {
                provenance: Provenance::Ici,
                estampille: e(7),
                annuaire,
            };
            let mut octets = [0_u8; HEBERGEMENT_OCTETS];
            heberge.ecrire(&mut octets);
            assert_eq!(Hebergement::lire(&octets), Ok(heberge));
        }
        let mut provenance = [0_u8; HEBERGEMENT_OCTETS];
        provenance[0] = 9;
        assert!(Hebergement::lire(&provenance).is_err());
        let heberge = Hebergement {
            provenance: Provenance::Ici,
            estampille: e(7),
            annuaire: None,
        };
        let mut octets = [0_u8; HEBERGEMENT_OCTETS];
        heberge.ecrire(&mut octets);
        let mut estampille = octets;
        estampille[PROVENANCE_OCTETS + 8] = b'u';
        assert!(Hebergement::lire(&estampille).is_err());
        let mut drapeau = octets;
        drapeau[HEBERGEMENT_OCTETS - 1 - IDENTIFIANT_OCTETS] = 2;
        assert_eq!(
            Hebergement::lire(&drapeau),
            Err(Faute::Etiquette { lue: 2 })
        );
    }

    #[test]
    fn des_locateurs_font_l_aller_retour_et_exigent_leur_forme() {
        use super::{LOCATEURS_MAX, LOCATEURS_OCTETS, Locateurs};
        let adresses = [
            Adresse::nouvelle("[2001:db8::7]:6630").unwrap(),
            Adresse::nouvelle("192.0.2.7:6630").unwrap(),
        ];
        for publies in [&adresses[..], &[]] {
            let locateurs = Locateurs::nouveaux(Provenance::Ici, e(9), publies).unwrap();
            assert_eq!(locateurs.adresses().count(), publies.len());
            let mut octets = [0_u8; LOCATEURS_OCTETS];
            locateurs.ecrire(&mut octets);
            assert_eq!(Locateurs::lire(&octets), Ok(locateurs));
        }
        let trop = [adresses[0]; LOCATEURS_MAX + 1];
        assert_eq!(
            Locateurs::nouveaux(Provenance::Ici, e(9), &trop),
            Err(Faute::Longueur {
                annoncee: LOCATEURS_MAX + 1,
                maximum: LOCATEURS_MAX
            })
        );
        let mut octets = [0_u8; LOCATEURS_OCTETS];
        Locateurs::nouveaux(Provenance::Ici, e(9), &adresses)
            .unwrap()
            .ecrire(&mut octets);
        let compte = PROVENANCE_OCTETS + ESTAMPILLE_OCTETS;
        let mut trop_annonce = octets;
        trop_annonce[compte] = 5;
        assert_eq!(
            Locateurs::lire(&trop_annonce),
            Err(Faute::Longueur {
                annoncee: 5,
                maximum: LOCATEURS_MAX
            })
        );
        let mut bourre = octets;
        bourre[LOCATEURS_OCTETS - 1] = 1;
        assert_eq!(Locateurs::lire(&bourre), Err(Faute::Bourrage));
        let mut adresse_fausse = octets;
        adresse_fausse[compte + 1] = 0;
        assert!(Locateurs::lire(&adresse_fausse).is_err());
        let mut provenance = octets;
        provenance[0] = 9;
        assert!(Locateurs::lire(&provenance).is_err());
        let mut estampille = octets;
        estampille[PROVENANCE_OCTETS + 8] = b'u';
        assert!(Locateurs::lire(&estampille).is_err());
    }
}
