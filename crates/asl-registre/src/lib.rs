//! Le format des enregistrements durables, **sans entrée-sortie**.
//!
//! # POURQUOI UNE CRATE, ET PAS DU CODE DANS `asl-store`
//!
//! C'est le partage qu'`air-mail-server` fait entre `ams-store` et `ams-index` :
//! **le format est une grammaire, le fichier est une exécution.** Les loger
//! ensemble mettrait l'encodage hors du régime de couverture au prétexte que le
//! voisin ouvre un fichier.
//!
//! Et ici l'enjeu est plus grand qu'ailleurs : **une faute d'encodage ne se voit
//! pas.** Un octet mal placé n'arrête rien, ne lève rien — il rend simplement un
//! enregistrement faux, et le rend faux DURABLEMENT. Un codec réseau se rattrape
//! à la connexion suivante ; celui-ci écrit sur un disque.
//!
//! # DES CHAMPS DE LONGUEUR FIXE, ET AUCUNE ALLOCATION
//!
//! Chaque enregistrement occupe un nombre d'octets connu à la compilation, et
//! s'écrit dans un tableau de cette taille exacte. Il n'y a donc **aucune
//! longueur venue de l'extérieur** qui puisse servir à indexer ou à réserver :
//! la forme du type est la borne.
//!
//! Les deux textes bornés — un alias, un nom de service — portent une longueur,
//! et c'est inévitable. Elle est bornée par le tableau qui la suit, donc elle ne
//! peut jamais faire lire au-delà.
//!
//! # CE QUI N'EST PAS REVALIDÉ ICI, ET POURQUOI
//!
//! **L'alphabet d'un alias et celui d'un nom de service ne sont pas revérifiés.**
//! `asl_api::Alias::analyser` et `asl_proto::NomService::analyser` les tiennent
//! déjà, et une seconde écriture de ces règles finirait par diverger de la
//! première — c'est la faute que ce dépôt refuse partout ailleurs.
//!
//! Ce qui EST vérifié ici est la structure : les longueurs, les genres
//! d'identifiant, les étiquettes. Un enregistrement corrompu est donc détecté
//! comme tel, et non propagé.

#![no_std]

use asl_id::{Genre, Identifiant};

// ── Les tailles ─────────────────────────────────────────────────────────────

/// Ce qu'un identifiant occupe : son genre, puis ses seize octets.
pub const IDENTIFIANT_OCTETS: usize = 17;

/// Ce qu'une provenance occupe.
pub const PROVENANCE_OCTETS: usize = 1 + IDENTIFIANT_OCTETS;

/// Ce qu'un alias peut faire, en octets. Égal à `asl_api::ALIAS_MAX`.
pub const ALIAS_OCTETS_MAX: usize = 32;

/// Ce qu'un nom de service peut faire. Égal à `asl_proto::NOM_MAX`.
pub const NOM_OCTETS_MAX: usize = 64;

/// Ce qu'une clé publique Ed25519 occupe.
pub const CLE_OCTETS: usize = 32;

// ── Les fautes ──────────────────────────────────────────────────────────────

/// Ce qui empêche de relire un enregistrement.
///
/// **Aucune ne devrait jamais arriver sur des octets que nous avons écrits.**
/// Elles arrivent sur des octets CORROMPUS — un disque qui ment, un fichier
/// tronqué, une version future relue par une version ancienne. C'est pour cela
/// qu'elles existent : pour que la corruption se voie au lieu de se propager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Faute {
    /// Une étiquette qui ne désigne aucune variante.
    Etiquette {
        /// Ce qui a été lu.
        lue: u8,
    },
    /// Un identifiant dont le genre n'est pas celui attendu à cette place.
    Genre {
        /// Le genre attendu.
        attendu: Genre,
    },
    /// Du bourrage qui n'est pas à zéro.
    ///
    /// **CE N'EST PAS UN EXCÈS DE ZÈLE, C'EST CE QUI REND L'ENCODAGE CANONIQUE.**
    /// Voir [`bourrage_nul`].
    Bourrage,
    /// Une longueur de texte au-delà de ce que son tableau peut contenir.
    Longueur {
        /// Ce qui a été annoncé.
        annoncee: usize,
        /// Ce que le tableau peut faire.
        maximum: usize,
    },
}

// ── Écrire sans ouvrir de branche ───────────────────────────────────────────
//
// # POURQUOI CES DEUX AIDES EXISTENT
//
// Toutes les tranches de ce module sont prélevées dans des tableaux de taille
// FIXE, à des décalages connus à la compilation : `get_mut` n'y échoue jamais.
// Le compilateur ne le sait pas, et un `if let Some(…)` laisse donc une branche
// qu'aucun essai ne peut prendre — la mesure de couverture en a signalé cinq.
//
// **Une branche qu'aucun essai ne peut prendre est du code mort.** Ces deux
// fonctions font le même travail sans en ouvrir aucune : `zip` s'arrête sur le
// plus court, `fill` sur une tranche vide ne fait rien.

/// Ce bourrage est-il bien nul ?
///
/// # POURQUOI IL DOIT L'ÊTRE, ET C'EST LE FUZZ QUI L'A ÉTABLI
///
/// Plusieurs enregistrements ont des octets qui ne portent rien : le corps d'une
/// provenance locale, la queue d'un texte plus court que son tableau, la zone
/// d'alias d'un compte qui n'en a pas. L'écriture les met à zéro. **La lecture
/// les ignorait**, et cela coûtait trois choses :
///
///   1. **L'encodage n'était pas canonique.** Deux suites d'octets différentes
///      rendaient la même valeur, donc relire puis réécrire changeait le
///      fichier — sur une base, une réécriture qui bouge est une réécriture
///      qu'on ne peut pas comparer.
///   2. **Le bourrage était un canal.** Ce qu'on y glisse survit à un
///      aller-retour sans qu'aucune couche ne le voie.
///   3. **UNE VERSION FUTURE AURAIT ÉTÉ MAL RELUE.** C'est le cas qui compte :
///      il arrive à chaque retour arrière de déploiement. Un champ ajouté demain
///      dans ces octets serait silencieusement ignoré par le binaire d'hier, qui
///      rendrait alors un enregistrement AMPUTÉ en le croyant entier. Le refuser
///      transforme une corruption invisible en une erreur qui se lit.
fn bourrage_nul(octets: &[u8]) -> bool {
    octets.iter().all(|octet| *octet == 0)
}

/// Écrit ces octets au début de cette tranche, autant qu'il y tient.
fn poser(sortie: &mut [u8], source: &[u8]) {
    for (place, octet) in sortie.iter_mut().zip(source.iter()) {
        *place = *octet;
    }
}

/// Écrit cet octet en tête de cette tranche, si elle en a une.
fn poser_un(sortie: &mut [u8], valeur: u8) {
    sortie.get_mut(..1).unwrap_or_default().fill(valeur);
}

// ── Un texte court et borné ─────────────────────────────────────────────────

/// Un texte de longueur bornée, rangé sans allocation.
///
/// `N` est la borne, et elle vient du type qui possède la grammaire de ce texte
/// — `asl_api::ALIAS_MAX` pour un alias, `asl_proto::NOM_MAX` pour un nom de
/// service. Le tableau fait toujours `N` octets ; seuls les `longueur` premiers
/// portent du sens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Court<const N: usize> {
    /// Les octets, dont seuls les premiers comptent.
    octets: [u8; N],
    /// Combien en comptent.
    longueur: usize,
}

impl<const N: usize> Court<N> {
    /// Range ce texte, ou refuse s'il est trop long.
    ///
    /// # Errors
    ///
    /// [`Faute::Longueur`] si le texte dépasse `N`.
    pub fn nouveau(texte: &str) -> Result<Self, Faute> {
        let source = texte.as_bytes();
        if source.len() > N {
            return Err(Faute::Longueur {
                annoncee: source.len(),
                maximum: N,
            });
        }
        let mut octets = [0_u8; N];
        poser(&mut octets, source);
        Ok(Self {
            octets,
            longueur: source.len(),
        })
    }

    /// Ce qu'il porte.
    #[must_use]
    pub fn octets(&self) -> &[u8] {
        self.octets.get(..self.longueur).unwrap_or_default()
    }

    /// Sa longueur.
    #[must_use]
    pub const fn longueur(&self) -> usize {
        self.longueur
    }

    /// Écrit la longueur puis les octets. Occupe `1 + N`.
    fn ecrire(&self, sortie: &mut [u8]) {
        // La longueur tient sur un octet : `N` vaut au plus 64 dans ce module,
        // et `nouveau` a déjà refusé au-delà.
        #[expect(
            clippy::cast_possible_truncation,
            reason = "la longueur est bornée par N, au plus 64"
        )]
        poser_un(sortie, self.longueur as u8);
        poser(sortie.get_mut(1..).unwrap_or_default(), &self.octets);
    }

    /// Relit ce qu'[`Court::ecrire`] a écrit.
    fn lire(octets: &[u8]) -> Result<Self, Faute> {
        let annoncee = usize::from(octets.first().copied().unwrap_or(0));
        if annoncee > N {
            return Err(Faute::Longueur {
                annoncee,
                maximum: N,
            });
        }
        let corps = octets.get(1..).unwrap_or_default();
        // Ce qui suit le texte ne porte rien, et doit donc être nul.
        if !bourrage_nul(corps.get(annoncee..).unwrap_or_default()) {
            return Err(Faute::Bourrage);
        }
        let mut rangees = [0_u8; N];
        poser(&mut rangees, corps);
        Ok(Self {
            octets: rangees,
            longueur: annoncee,
        })
    }
}

/// Un alias rangé.
pub type AliasRange = Court<ALIAS_OCTETS_MAX>;

/// Un nom de service rangé.
pub type NomRange = Court<NOM_OCTETS_MAX>;

// ── L'identifiant, en octets ────────────────────────────────────────────────

/// Écrit un identifiant : son genre, puis ses seize octets.
fn ecrire_identifiant(quoi: Identifiant, sortie: &mut [u8]) {
    poser_un(sortie, quoi.genre().prefixe());
    poser(sortie.get_mut(1..).unwrap_or_default(), quoi.octets());
}

/// Relit un identifiant, et EXIGE son genre.
///
/// # POURQUOI EXIGER LE GENRE PLUTÔT QUE LE LIRE
///
/// Le genre d'un champ est connu à l'écriture : le propriétaire d'une machine
/// est un utilisateur, la provenance est un annuaire. Le relire sans l'exiger
/// laisserait un enregistrement corrompu désigner un objet d'un autre genre —
/// et une machine dont le propriétaire serait un service ne se verrait nulle
/// part ailleurs.
fn lire_identifiant(octets: &[u8], attendu: Genre) -> Result<Identifiant, Faute> {
    // **L'OCTET EXACT, ET NON `Genre::depuis_prefixe`.** Cette fonction-là
    // accepte les deux casses, et elle a raison : un identifiant se recopie à la
    // main, et refuser un `M` parce qu'on attendait un `m` serait cruel.
    //
    // Ici, rien ne se recopie à la main : ces octets viennent d'un disque, et
    // nous les y avons écrits. Accepter la majuscule rendrait l'encodage NON
    // CANONIQUE — un enregistrement relu se réécrirait différemment de
    // lui-même —, et c'est le fuzz qui l'a montré.
    let lu = octets.first().copied().unwrap_or(0);
    if lu != attendu.prefixe() {
        return Err(Faute::Genre { attendu });
    }
    let mut entropie = [0_u8; 16];
    poser(&mut entropie, octets.get(1..).unwrap_or_default());
    Ok(Identifiant::depuis_entropie(attendu, entropie))
}

// ── La provenance (C17) ─────────────────────────────────────────────────────

/// D'où vient un enregistrement.
///
/// # C'EST C17, ET CE N'EST PAS L'`Origine` D'`asl-proto`
///
/// Les deux mots se ressemblent et ne disent pas la même chose. `asl_proto::
/// Origine` dit **comment une adresse a été apprise** — vue par l'annuaire, ou
/// annoncée par le daemon. Celle-ci dit **de quel annuaire un ENREGISTREMENT
/// provient**, et c'est ce qui rend une rupture de confiance exécutable : quand
/// une relation tombe, tout ce qui en vient disparaît.
///
/// Sans ce champ, rompre une relation demanderait de deviner ce qu'elle avait
/// apporté — et l'on garderait donc tout, ce qui reviendrait à ne pas rompre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Écrit ici, par son propriétaire.
    Ici,
    /// Répliqué depuis cet annuaire.
    Annuaire(Identifiant),
}

impl Provenance {
    /// L'étiquette d'un enregistrement local.
    const ICI: u8 = 0;
    /// L'étiquette d'un enregistrement répliqué.
    const AILLEURS: u8 = 1;

    /// Écrit cette provenance. Occupe [`PROVENANCE_OCTETS`].
    fn ecrire(self, sortie: &mut [u8]) {
        match self {
            Self::Ici => {
                poser_un(sortie, Self::ICI);
                // **LE RESTE EST MIS À ZÉRO, ET C'EST DÉLIBÉRÉ** : un tampon
                // réemployé garderait sinon l'identifiant de l'enregistrement
                // précédent, invisible mais présent sur le disque.
                sortie.get_mut(1..).unwrap_or_default().fill(0);
            }
            Self::Annuaire(annuaire) => {
                poser_un(sortie, Self::AILLEURS);
                ecrire_identifiant(annuaire, sortie.get_mut(1..).unwrap_or_default());
            }
        }
    }

    /// Relit une provenance.
    fn lire(octets: &[u8]) -> Result<Self, Faute> {
        match octets.first().copied().unwrap_or(0) {
            Self::ICI => {
                if bourrage_nul(octets.get(1..).unwrap_or_default()) {
                    Ok(Self::Ici)
                } else {
                    Err(Faute::Bourrage)
                }
            }
            Self::AILLEURS => {
                let annuaire =
                    lire_identifiant(octets.get(1..).unwrap_or_default(), Genre::Annuaire)?;
                Ok(Self::Annuaire(annuaire))
            }
            lue => Err(Faute::Etiquette { lue }),
        }
    }

    /// Cet enregistrement vient-il de cet annuaire ?
    ///
    /// **C'est la question que pose une rupture de confiance** (C17) : ce qui
    /// vient de l'annuaire qu'on cesse de croire s'efface, et rien d'autre.
    #[must_use]
    pub fn vient_de(self, annuaire: Identifiant) -> bool {
        matches!(self, Self::Annuaire(quel) if quel == annuaire)
    }
}

// ── Le compte ───────────────────────────────────────────────────────────────

/// Ce qu'un compte occupe.
pub const COMPTE_OCTETS: usize = PROVENANCE_OCTETS + 1 + 1 + ALIAS_OCTETS_MAX;

/// Un compte d'utilisateur.
///
/// # IL NE PORTE RIEN D'AUTRE, ET C'EST UNE IMPOSITION
///
/// Ni courriel, ni numéro, ni nom. **Seul l'alias public, et il est facultatif**
/// — c'est la seule donnée que l'utilisateur choisit de rendre trouvable. C13 le
/// dit, et le schéma est ce qui le tient : une colonne qui n'existe pas ne se
/// remplit pas par mégarde.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Compte {
    /// D'où vient cet enregistrement.
    pub provenance: Provenance,
    /// L'alias public, si l'utilisateur en a choisi un.
    pub alias: Option<AliasRange>,
}

impl Compte {
    /// Écrit ce compte.
    pub fn ecrire(&self, sortie: &mut [u8; COMPTE_OCTETS]) {
        self.provenance
            .ecrire(sortie.get_mut(..PROVENANCE_OCTETS).unwrap_or_default());
        let reste = sortie.get_mut(PROVENANCE_OCTETS..).unwrap_or_default();
        match &self.alias {
            Some(alias) => {
                poser_un(reste, 1);
                alias.ecrire(reste.get_mut(1..).unwrap_or_default());
            }
            None => reste.fill(0),
        }
    }

    /// Relit un compte.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas un compte.
    pub fn lire(octets: &[u8; COMPTE_OCTETS]) -> Result<Self, Faute> {
        let provenance = Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?;
        let reste = octets.get(PROVENANCE_OCTETS..).unwrap_or_default();
        let alias = match reste.first().copied().unwrap_or(0) {
            0 => {
                if !bourrage_nul(reste.get(1..).unwrap_or_default()) {
                    return Err(Faute::Bourrage);
                }
                None
            }
            1 => Some(AliasRange::lire(reste.get(1..).unwrap_or_default())?),
            lue => return Err(Faute::Etiquette { lue }),
        };
        Ok(Self { provenance, alias })
    }
}

// ── La machine ──────────────────────────────────────────────────────────────

/// Ce qu'une machine occupe.
pub const MACHINE_OCTETS: usize =
    PROVENANCE_OCTETS + IDENTIFIANT_OCTETS + CLE_OCTETS + 1 + 1 + NOM_OCTETS_MAX;

/// Une machine, telle qu'elle est rangée.
///
/// # LES CAPACITÉS SONT DES BITS ICI, ET UN TYPE AILLEURS
///
/// `asl_auth::Capacites` est le type qui DÉCIDE ; il vit à l'étage 2, et cette
/// crate est à l'étage 1. Le ranger ici renverserait la dépendance — une
/// grammaire qui tirerait une machine à états.
///
/// Ce module range donc deux bits, et `asl-auth` construit son type à partir
/// d'eux. C'est une ligne de plus à l'appel, et une arête en moins dans le
/// graphe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Machine {
    /// D'où vient cet enregistrement.
    pub provenance: Provenance,
    /// Le compte qui possède cette machine.
    pub proprietaire: Identifiant,
    /// Sa clé publique Ed25519, **si elle en a une**.
    ///
    /// # UNE MACHINE DÉCLARÉE N'A PAS ENCORE DE CLÉ
    ///
    /// Elle est créée par l'application mobile, qui ne connaît que son nom ; la
    /// clé arrive plus tard, quand la machine présente son code d'enrôlement
    /// (`docs/modele.md` §2.3). Entre les deux, il y a un état — et il faut
    /// pouvoir le RANGER.
    ///
    /// **Trente-deux zéros n'auraient pas fait l'affaire.** Ce n'est pas une
    /// valeur absurde pour Ed25519 : c'est un point d'ordre faible, que certaines
    /// vérifications acceptent, et dont on peut forger des signatures. Une
    /// machine sans clé aurait alors eu une clé que n'importe qui détient.
    ///
    /// **Elle n'est pas interprétée ici.** `asl_cle::ClePublique::depuis_octets`
    /// sait dire si ces octets forment un point de la courbe ; ce module range
    /// des octets, et une seconde vérification serait une seconde vérité.
    pub cle: Option<[u8; CLE_OCTETS]>,
    /// Cette machine peut-elle annoncer des services ?
    pub annonce: bool,
    /// Cette machine peut-elle interroger l'annuaire ?
    pub lecture: bool,
    /// Le nom que son propriétaire lui a donné.
    ///
    /// **Pour l'humain, jamais pour la machine** (`docs/modele.md` §2.3) : rien
    /// ne se cherche par ce nom, rien ne s'y compare. C'est ce qui permet qu'il
    /// porte du texte libre là où le nom d'un SERVICE ne le peut pas — celui-là
    /// est une clé, et une clé qui a deux écritures n'en est pas une.
    pub nom: NomRange,
}

impl Machine {
    /// Le bit d'annonce.
    const BIT_ANNONCE: u8 = 0b0000_0001;
    /// Le bit de lecture.
    const BIT_LECTURE: u8 = 0b0000_0010;
    /// Le bit qui dit qu'une clé est posée.
    ///
    /// **Il n'est pas une capacité**, et il partage pourtant leur octet : c'est
    /// un drapeau de plus dans une place déjà là. Le nommer autrement aurait
    /// coûté un octet pour dire la même chose.
    const BIT_CLE: u8 = 0b0000_0100;

    /// Écrit cette machine.
    pub fn ecrire(&self, sortie: &mut [u8; MACHINE_OCTETS]) {
        self.provenance
            .ecrire(sortie.get_mut(..PROVENANCE_OCTETS).unwrap_or_default());
        let apres_provenance = PROVENANCE_OCTETS.saturating_add(IDENTIFIANT_OCTETS);
        ecrire_identifiant(
            self.proprietaire,
            sortie
                .get_mut(PROVENANCE_OCTETS..apres_provenance)
                .unwrap_or_default(),
        );
        let apres_cle = apres_provenance.saturating_add(CLE_OCTETS);
        let place = sortie
            .get_mut(apres_provenance..apres_cle)
            .unwrap_or_default();
        match &self.cle {
            Some(cle) => poser(place, cle),
            // Le bourrage à zéro, pour la raison écrite sur `bourrage_nul`.
            None => place.fill(0),
        }
        let mut drapeaux = 0_u8;
        if self.annonce {
            drapeaux |= Self::BIT_ANNONCE;
        }
        if self.lecture {
            drapeaux |= Self::BIT_LECTURE;
        }
        if self.cle.is_some() {
            drapeaux |= Self::BIT_CLE;
        }
        poser_un(sortie.get_mut(apres_cle..).unwrap_or_default(), drapeaux);
        let apres_drapeaux = apres_cle.saturating_add(1);
        self.nom
            .ecrire(sortie.get_mut(apres_drapeaux..).unwrap_or_default());
    }

    /// Relit une machine.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas une machine.
    pub fn lire(octets: &[u8; MACHINE_OCTETS]) -> Result<Self, Faute> {
        let provenance = Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?;
        let apres_provenance = PROVENANCE_OCTETS.saturating_add(IDENTIFIANT_OCTETS);
        let proprietaire = lire_identifiant(
            octets
                .get(PROVENANCE_OCTETS..apres_provenance)
                .unwrap_or_default(),
            Genre::Utilisateur,
        )?;
        let apres_cle = apres_provenance.saturating_add(CLE_OCTETS);
        let brute = octets.get(apres_provenance..apres_cle).unwrap_or_default();
        // **LES BITS INCONNUS SONT REFUSÉS.** Les accepter en silence ferait
        // relire sans broncher un enregistrement écrit par une version qui en
        // sait plus que nous — et lui prêterait des capacités qu'on ne
        // comprendrait pas.
        let drapeaux = octets.get(apres_cle).copied().unwrap_or(0);
        let connus = Self::BIT_ANNONCE | Self::BIT_LECTURE | Self::BIT_CLE;
        if drapeaux & !connus != 0 {
            return Err(Faute::Etiquette { lue: drapeaux });
        }
        let cle = if drapeaux & Self::BIT_CLE == 0 {
            // **PAS DE CLÉ VEUT DIRE QUE LA PLACE EST NULLE.** Sans ce contrôle,
            // deux enregistrements différents se reliraient identiques, et l'un
            // d'eux ne se réécrirait pas comme il a été lu.
            if !bourrage_nul(brute) {
                return Err(Faute::Bourrage);
            }
            None
        } else {
            let mut octets = [0_u8; CLE_OCTETS];
            poser(&mut octets, brute);
            Some(octets)
        };
        let apres_drapeaux = apres_cle.saturating_add(1);
        let nom = NomRange::lire(octets.get(apres_drapeaux..).unwrap_or_default())?;
        Ok(Self {
            provenance,
            proprietaire,
            cle,
            annonce: drapeaux & Self::BIT_ANNONCE != 0,
            lecture: drapeaux & Self::BIT_LECTURE != 0,
            nom,
        })
    }
}

// ── L'appareil ──────────────────────────────────────────────────────────────

/// Ce qu'un appareil occupe.
pub const APPAREIL_OCTETS: usize = PROVENANCE_OCTETS + IDENTIFIANT_OCTETS + CLE_OCTETS;

/// Un téléphone enrôlé, tel qu'il est rangé.
///
/// # TROIS CHAMPS, ET C'EST TOUT CE QU'UN APPAREIL EST
///
/// Ni modèle, ni système, ni nom, ni adresse : rien de ce qui désignerait
/// l'appareil ou son porteur (C13). Un appareil, pour l'annuaire, est **une clé
/// publique rattachée à un compte**, et rien d'autre.
///
/// `docs/modele.md` §2.2 lui donne aussi un jeton de poussée, une date
/// d'enrôlement et une date de révocation. **Ils ne sont pas ici, et c'est un
/// manque nommé** : rien ne les écrit ni ne les lit encore, et un champ qu'on
/// range toujours vide ment sur ce que l'annuaire sait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Appareil {
    /// D'où vient cet enregistrement.
    pub provenance: Provenance,
    /// Le compte dont cet appareil est un justificatif.
    pub proprietaire: Identifiant,
    /// Sa clé publique Ed25519, telle quelle.
    ///
    /// Celle qui vit dans le matériel sécurisé du téléphone. **L'annuaire n'en
    /// connaît que la partie publique**, et il ne saurait rien faire de l'autre.
    pub cle: [u8; CLE_OCTETS],
}

impl Appareil {
    /// Écrit cet appareil.
    pub fn ecrire(&self, sortie: &mut [u8; APPAREIL_OCTETS]) {
        self.provenance
            .ecrire(sortie.get_mut(..PROVENANCE_OCTETS).unwrap_or_default());
        let apres_provenance = PROVENANCE_OCTETS.saturating_add(IDENTIFIANT_OCTETS);
        ecrire_identifiant(
            self.proprietaire,
            sortie
                .get_mut(PROVENANCE_OCTETS..apres_provenance)
                .unwrap_or_default(),
        );
        poser(
            sortie.get_mut(apres_provenance..).unwrap_or_default(),
            &self.cle,
        );
    }

    /// Relit un appareil.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas un appareil.
    pub fn lire(octets: &[u8; APPAREIL_OCTETS]) -> Result<Self, Faute> {
        let provenance = Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?;
        let apres_provenance = PROVENANCE_OCTETS.saturating_add(IDENTIFIANT_OCTETS);
        let proprietaire = lire_identifiant(
            octets
                .get(PROVENANCE_OCTETS..apres_provenance)
                .unwrap_or_default(),
            Genre::Utilisateur,
        )?;
        let mut cle = [0_u8; CLE_OCTETS];
        poser(&mut cle, octets.get(apres_provenance..).unwrap_or_default());
        Ok(Self {
            provenance,
            proprietaire,
            cle,
        })
    }
}

// ── Le code d'enrôlement en attente ─────────────────────────────────────────

/// Ce qu'un enrôlement en attente occupe.
pub const ENROLEMENT_OCTETS: usize = PROVENANCE_OCTETS + IDENTIFIANT_OCTETS + 8;

/// Un code d'enrôlement émis et pas encore consommé.
///
/// # LE CODE N'EST PAS ICI, ET C'EST TOUT L'INTÉRÊT
///
/// Cet enregistrement est rangé SOUS l'empreinte du code
/// (`asl_cle::CodeEnrolement::empreinte`) et ne la porte donc pas. Le code
/// lui-même n'est écrit nulle part : une base qui fuirait ne livrerait aucune
/// machine en cours d'enrôlement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Enrolement {
    /// D'où vient cet enregistrement.
    pub provenance: Provenance,
    /// La machine dont ce code liera la clé.
    pub machine: Identifiant,
    /// Quand il cesse de valoir, en millisecondes d'époque.
    ///
    /// **L'expiration est rangée, et non calculée à la lecture.** Un code dont
    /// la validité dépendrait de la durée en vigueur au moment où on le relit
    /// changerait de durée quand on change la constante — y compris pour les
    /// codes déjà en vol.
    pub expire_a: u64,
}

impl Enrolement {
    /// Écrit cet enrôlement.
    pub fn ecrire(&self, sortie: &mut [u8; ENROLEMENT_OCTETS]) {
        self.provenance
            .ecrire(sortie.get_mut(..PROVENANCE_OCTETS).unwrap_or_default());
        let apres_provenance = PROVENANCE_OCTETS.saturating_add(IDENTIFIANT_OCTETS);
        ecrire_identifiant(
            self.machine,
            sortie
                .get_mut(PROVENANCE_OCTETS..apres_provenance)
                .unwrap_or_default(),
        );
        poser(
            sortie.get_mut(apres_provenance..).unwrap_or_default(),
            &self.expire_a.to_be_bytes(),
        );
    }

    /// Relit un enrôlement.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas un enrôlement.
    pub fn lire(octets: &[u8; ENROLEMENT_OCTETS]) -> Result<Self, Faute> {
        let provenance = Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?;
        let apres_provenance = PROVENANCE_OCTETS.saturating_add(IDENTIFIANT_OCTETS);
        let machine = lire_identifiant(
            octets
                .get(PROVENANCE_OCTETS..apres_provenance)
                .unwrap_or_default(),
            Genre::Machine,
        )?;
        let mut quand = [0_u8; 8];
        poser(
            &mut quand,
            octets.get(apres_provenance..).unwrap_or_default(),
        );
        Ok(Self {
            provenance,
            machine,
            expire_a: u64::from_be_bytes(quand),
        })
    }
}

// ── Le service ──────────────────────────────────────────────────────────────

/// Ce qu'un service occupe.
pub const SERVICE_OCTETS: usize = PROVENANCE_OCTETS + IDENTIFIANT_OCTETS + 1 + NOM_OCTETS_MAX;

/// Un service DÉCLARÉ sur une machine.
///
/// # CE QU'IL PORTE, ET CE QU'IL NE PORTE SURTOUT PAS
///
/// **Ni port, ni adresse, ni état.** Un service durable est une DÉCLARATION :
/// « cette machine sert quelque chose qui s'appelle ainsi ». Ce qu'il écoute et
/// s'il répond sont de l'état VIVANT, tenu par `asl-annuaire` et reconstruit à
/// chaque connexion — `modele.md` le décide, et le schéma est ce qui l'exécute.
///
/// Ranger un port ici ferait de l'annuaire un menteur au premier redémarrage
/// d'un daemon : il annoncerait un port que plus personne n'écoute, sans même
/// savoir qu'il l'annonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Service {
    /// D'où vient cet enregistrement.
    pub provenance: Provenance,
    /// La machine qui le sert.
    pub machine: Identifiant,
    /// Son nom, tel que ses clients le demandent.
    pub nom: NomRange,
}

impl Service {
    /// Écrit ce service.
    pub fn ecrire(&self, sortie: &mut [u8; SERVICE_OCTETS]) {
        self.provenance
            .ecrire(sortie.get_mut(..PROVENANCE_OCTETS).unwrap_or_default());
        let apres_machine = PROVENANCE_OCTETS.saturating_add(IDENTIFIANT_OCTETS);
        ecrire_identifiant(
            self.machine,
            sortie
                .get_mut(PROVENANCE_OCTETS..apres_machine)
                .unwrap_or_default(),
        );
        self.nom
            .ecrire(sortie.get_mut(apres_machine..).unwrap_or_default());
    }

    /// Relit un service.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas un service.
    pub fn lire(octets: &[u8; SERVICE_OCTETS]) -> Result<Self, Faute> {
        let provenance = Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?;
        let apres_machine = PROVENANCE_OCTETS.saturating_add(IDENTIFIANT_OCTETS);
        let machine = lire_identifiant(
            octets
                .get(PROVENANCE_OCTETS..apres_machine)
                .unwrap_or_default(),
            Genre::Machine,
        )?;
        let nom = NomRange::lire(octets.get(apres_machine..).unwrap_or_default())?;
        Ok(Self {
            provenance,
            machine,
            nom,
        })
    }
}

// ── L'autorisation ──────────────────────────────────────────────────────────

/// Ce qu'une portée occupe.
pub const PORTEE_OCTETS: usize = 1 + IDENTIFIANT_OCTETS;

/// Jusqu'où une autorisation porte.
///
/// **C'est le miroir d'`asl_auth::Portee`**, et il faut dire pourquoi il y en a
/// deux. Celui-là DÉCIDE et vit à l'étage 2 ; celui-ci RANGE et vit à l'étage 1.
/// Les fondre renverserait la dépendance — une grammaire qui tirerait une
/// machine à états.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Portee {
    /// Tout ce que le compte possède, présent et à venir.
    ToutLeCompte,
    /// Cette machine, et tous ses services.
    UneMachine(Identifiant),
    /// Ce service, et lui seul.
    UnService(Identifiant),
}

impl Portee {
    /// Les étiquettes, sur le disque.
    const TOUT: u8 = 0;
    /// Une machine.
    const MACHINE: u8 = 1;
    /// Un service.
    const SERVICE: u8 = 2;

    /// Écrit cette portée. Occupe [`PORTEE_OCTETS`].
    fn ecrire(self, sortie: &mut [u8]) {
        let (etiquette, quoi) = match self {
            Self::ToutLeCompte => (Self::TOUT, None),
            Self::UneMachine(machine) => (Self::MACHINE, Some(machine)),
            Self::UnService(service) => (Self::SERVICE, Some(service)),
        };
        poser_un(sortie, etiquette);
        let corps = sortie.get_mut(1..).unwrap_or_default();
        match quoi {
            Some(designe) => ecrire_identifiant(designe, corps),
            // Le bourrage à zéro, pour la raison écrite sur `bourrage_nul`.
            None => corps.fill(0),
        }
    }

    /// Relit une portée.
    fn lire(octets: &[u8]) -> Result<Self, Faute> {
        let corps = octets.get(1..).unwrap_or_default();
        match octets.first().copied().unwrap_or(0) {
            Self::TOUT => {
                if bourrage_nul(corps) {
                    Ok(Self::ToutLeCompte)
                } else {
                    Err(Faute::Bourrage)
                }
            }
            Self::MACHINE => Ok(Self::UneMachine(lire_identifiant(corps, Genre::Machine)?)),
            Self::SERVICE => Ok(Self::UnService(lire_identifiant(corps, Genre::Service)?)),
            lue => Err(Faute::Etiquette { lue }),
        }
    }
}

/// Ce qu'une autorisation occupe.
pub const AUTORISATION_OCTETS: usize =
    PROVENANCE_OCTETS + IDENTIFIANT_OCTETS + IDENTIFIANT_OCTETS + PORTEE_OCTETS + 1;

/// Une arête entre deux comptes.
///
/// # ELLE EST RÉVOQUÉE, JAMAIS EFFACÉE
///
/// **C'est une décision, pas une commodité.** Une autorisation effacée ne laisse
/// aucune trace : on ne peut plus dire si elle a existé, ni quand elle a cessé.
/// Un drapeau garde l'arête et son histoire, et `asl_auth::Autorisation::couvre`
/// refuse tout ce qui est révoqué.
///
/// C'est aussi ce qui permet à l'utilisateur de VOIR ce qu'il a retiré, plutôt
/// que de constater une absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Autorisation {
    /// D'où vient cet enregistrement.
    pub provenance: Provenance,
    /// Le compte qui accorde.
    pub par: Identifiant,
    /// Le compte qui reçoit.
    pub a: Identifiant,
    /// Jusqu'où elle porte.
    pub portee: Portee,
    /// A-t-elle été retirée ?
    pub revoquee: bool,
}

impl Autorisation {
    /// Écrit cette autorisation.
    pub fn ecrire(&self, sortie: &mut [u8; AUTORISATION_OCTETS]) {
        let mut curseur = 0_usize;
        let mut tranche = |combien: usize| {
            let debut = curseur;
            curseur = curseur.saturating_add(combien);
            debut..curseur
        };
        let provenance = tranche(PROVENANCE_OCTETS);
        self.provenance
            .ecrire(sortie.get_mut(provenance).unwrap_or_default());
        let par = tranche(IDENTIFIANT_OCTETS);
        ecrire_identifiant(self.par, sortie.get_mut(par).unwrap_or_default());
        let a = tranche(IDENTIFIANT_OCTETS);
        ecrire_identifiant(self.a, sortie.get_mut(a).unwrap_or_default());
        let portee = tranche(PORTEE_OCTETS);
        self.portee
            .ecrire(sortie.get_mut(portee).unwrap_or_default());
        let revoquee = tranche(1);
        poser_un(
            sortie.get_mut(revoquee).unwrap_or_default(),
            u8::from(self.revoquee),
        );
    }

    /// Relit une autorisation.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas une autorisation.
    pub fn lire(octets: &[u8; AUTORISATION_OCTETS]) -> Result<Self, Faute> {
        let mut curseur = 0_usize;
        let mut prendre = |combien: usize| {
            let debut = curseur;
            curseur = curseur.saturating_add(combien);
            debut..curseur
        };
        let provenance =
            Provenance::lire(octets.get(prendre(PROVENANCE_OCTETS)).unwrap_or_default())?;
        let par = lire_identifiant(
            octets.get(prendre(IDENTIFIANT_OCTETS)).unwrap_or_default(),
            Genre::Utilisateur,
        )?;
        let a = lire_identifiant(
            octets.get(prendre(IDENTIFIANT_OCTETS)).unwrap_or_default(),
            Genre::Utilisateur,
        )?;
        let portee = Portee::lire(octets.get(prendre(PORTEE_OCTETS)).unwrap_or_default())?;
        // **NI 0 NI 1 EST UNE CORRUPTION**, et non « vrai par défaut ». Un
        // booléen relu de travers sur une décision d'autorisation est
        // exactement ce qu'on ne veut pas deviner.
        let revoquee = match octets
            .get(prendre(1))
            .and_then(<[u8]>::first)
            .copied()
            .unwrap_or(0)
        {
            0 => false,
            1 => true,
            lue => return Err(Faute::Etiquette { lue }),
        };
        Ok(Self {
            provenance,
            par,
            a,
            portee,
            revoquee,
        })
    }
}

// ── Le journal (C18) ────────────────────────────────────────────────────────

/// Ce qu'une requête a obtenu.
///
/// **SANS LUI, ON NE DISTINGUE PAS L'USAGE NORMAL DU BALAYAGE.** Un compte qui
/// interroge cent fois et obtient cent réponses travaille ; un compte qui
/// interroge cent fois et se fait refuser cent fois cherche.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// La requête a été servie.
    Servi,
    /// Le demandeur n'y avait pas droit.
    Refuse,
    /// Ce qui était demandé n'existe pas.
    Introuvable,
}

impl Verdict {
    /// Son étiquette sur le disque.
    const fn etiquette(self) -> u8 {
        match self {
            Self::Servi => 0,
            Self::Refuse => 1,
            Self::Introuvable => 2,
        }
    }

    /// Ce que cette étiquette désigne.
    const fn depuis(lue: u8) -> Result<Self, Faute> {
        match lue {
            0 => Ok(Self::Servi),
            1 => Ok(Self::Refuse),
            2 => Ok(Self::Introuvable),
            lue => Err(Faute::Etiquette { lue }),
        }
    }
}

/// Ce qu'une entrée de journal occupe.
pub const ENTREE_OCTETS: usize =
    8 + IDENTIFIANT_OCTETS + IDENTIFIANT_OCTETS + 1 + NOM_OCTETS_MAX + 1 + PROVENANCE_OCTETS;

/// Une requête, telle qu'elle est journalisée.
///
/// # CE QU'ELLE NE PORTE PAS, ET C'EST LE PLUS IMPORTANT
///
/// **Ni l'adresse source, ni les candidats servis.** `docs/journal.md` §2.3 le
/// décide, et le schéma est ce qui le tient :
///
///   — l'adresse source est le champ le plus identifiant du lot, et elle
///     rattache une activité à un lieu et à un fournisseur d'accès ;
///   — les candidats servis feraient du journal **une carte historique de
///     l'infrastructure de tout le monde**, là où la base courante ne garde que
///     l'état présent. Une fuite du journal donnerait l'historique des ports de
///     chacun.
///
/// Ce sont les deux champs qu'on peut ajouter plus tard ; **l'inverse ne se
/// rattrape pas**, puisqu'un journal déjà écrit ne se désécrit pas.
///
/// # L'HORODATAGE EST LA TÊTE DE LA CLÉ, ET C'EST CE QUI REND C18 EXÉCUTABLE
///
/// La rétention à quatre-vingt-dix jours est une SUPPRESSION PAR INTERVALLE :
/// tout ce qui précède une date s'efface d'un coup. Cela n'est possible que si
/// le temps ordonne les clés — d'où [`EntreeJournal::clef`], qui met
/// l'horodatage en tête, en gros-boutiste pour que l'ordre des octets soit
/// l'ordre du temps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntreeJournal {
    /// Quand, en millisecondes depuis l'époque.
    pub quand: u64,
    /// La machine qui a demandé.
    pub demandeur: Identifiant,
    /// La machine dont on cherchait un service.
    pub visee: Identifiant,
    /// Le nom du service cherché.
    pub service: NomRange,
    /// Ce que la requête a obtenu.
    pub verdict: Verdict,
    /// Requête locale, ou venue d'un annuaire pair.
    pub provenance: Provenance,
}

/// Ce qu'une clé de journal occupe : l'horodatage, puis un rang.
pub const CLEF_JOURNAL_OCTETS: usize = 8 + 8;

impl EntreeJournal {
    /// La clé sous laquelle cette entrée se range.
    ///
    /// **L'HORODATAGE EN GROS-BOUTISTE, PUIS UN RANG.** Le gros-boutiste fait
    /// coïncider l'ordre lexicographique des octets avec l'ordre du temps, ce
    /// qui rend l'expiration de C18 exprimable comme un intervalle. Le rang
    /// départage deux entrées de la même milliseconde — sans lui, la seconde
    /// écraserait la première, et le journal perdrait des faits sous charge,
    /// c'est-à-dire exactement quand il compte.
    #[must_use]
    pub fn clef(&self, rang: u64) -> [u8; CLEF_JOURNAL_OCTETS] {
        let mut clef = [0_u8; CLEF_JOURNAL_OCTETS];
        for (place, octet) in clef.iter_mut().zip(self.quand.to_be_bytes().iter()) {
            *place = *octet;
        }
        let queue = clef.get_mut(8..).unwrap_or_default();
        for (place, octet) in queue.iter_mut().zip(rang.to_be_bytes().iter()) {
            *place = *octet;
        }
        clef
    }

    /// Écrit cette entrée.
    pub fn ecrire(&self, sortie: &mut [u8; ENTREE_OCTETS]) {
        let mut curseur = 0_usize;
        let mut tranche = |combien: usize| {
            let debut = curseur;
            curseur = curseur.saturating_add(combien);
            debut..curseur
        };

        let quand = tranche(8);
        poser(
            sortie.get_mut(quand).unwrap_or_default(),
            &self.quand.to_be_bytes(),
        );
        let demandeur = tranche(IDENTIFIANT_OCTETS);
        ecrire_identifiant(
            self.demandeur,
            sortie.get_mut(demandeur).unwrap_or_default(),
        );
        let visee = tranche(IDENTIFIANT_OCTETS);
        ecrire_identifiant(self.visee, sortie.get_mut(visee).unwrap_or_default());
        let service = tranche(1 + NOM_OCTETS_MAX);
        self.service
            .ecrire(sortie.get_mut(service).unwrap_or_default());
        let verdict = tranche(1);
        poser_un(
            sortie.get_mut(verdict).unwrap_or_default(),
            self.verdict.etiquette(),
        );
        let provenance = tranche(PROVENANCE_OCTETS);
        self.provenance
            .ecrire(sortie.get_mut(provenance).unwrap_or_default());
    }

    /// Relit une entrée.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas une entrée.
    pub fn lire(octets: &[u8; ENTREE_OCTETS]) -> Result<Self, Faute> {
        let mut curseur = 0_usize;
        let mut prendre = |combien: usize| {
            let debut = curseur;
            curseur = curseur.saturating_add(combien);
            debut..curseur
        };

        let mut quand = [0_u8; 8];
        poser(&mut quand, octets.get(prendre(8)).unwrap_or_default());
        let demandeur = lire_identifiant(
            octets.get(prendre(IDENTIFIANT_OCTETS)).unwrap_or_default(),
            Genre::Machine,
        )?;
        let visee = lire_identifiant(
            octets.get(prendre(IDENTIFIANT_OCTETS)).unwrap_or_default(),
            Genre::Machine,
        )?;
        let service = NomRange::lire(octets.get(prendre(1 + NOM_OCTETS_MAX)).unwrap_or_default())?;
        let verdict = Verdict::depuis(
            octets
                .get(prendre(1))
                .and_then(<[u8]>::first)
                .copied()
                .unwrap_or(0),
        )?;
        let provenance =
            Provenance::lire(octets.get(prendre(PROVENANCE_OCTETS)).unwrap_or_default())?;
        Ok(Self {
            quand: u64::from_be_bytes(quand),
            demandeur,
            visee,
            service,
            verdict,
            provenance,
        })
    }
}

#[cfg(test)]
mod tests {
    use asl_id::{Genre, Identifiant};

    use super::{
        ALIAS_OCTETS_MAX, APPAREIL_OCTETS, AUTORISATION_OCTETS, AliasRange, Appareil, Autorisation,
        CLE_OCTETS, CLEF_JOURNAL_OCTETS, COMPTE_OCTETS, Compte, Court, ENROLEMENT_OCTETS,
        ENTREE_OCTETS, Enrolement, EntreeJournal, Faute, IDENTIFIANT_OCTETS, MACHINE_OCTETS,
        Machine, NOM_OCTETS_MAX, NomRange, PROVENANCE_OCTETS, Portee, Provenance, SERVICE_OCTETS,
        Service, Verdict,
    };

    /// Un identifiant de ce genre, reproductible.
    fn un(genre: Genre, graine: u8) -> Identifiant {
        Identifiant::depuis_entropie(genre, [graine; 16])
    }

    // ── Court ───────────────────────────────────────────────────────────────

    #[test]
    fn un_texte_court_se_range_et_se_relit() {
        let alias = AliasRange::nouveau("thierry").expect("il tient");
        assert_eq!(alias.octets(), b"thierry");
        assert_eq!(alias.longueur(), 7);

        let mut sortie = [0_u8; 1 + ALIAS_OCTETS_MAX];
        alias.ecrire(&mut sortie);
        assert_eq!(AliasRange::lire(&sortie), Ok(alias));
    }

    #[test]
    fn un_texte_vide_se_range_aussi() {
        let vide = AliasRange::nouveau("").expect("le vide tient");
        assert_eq!(vide.octets(), b"");
        let mut sortie = [0_u8; 1 + ALIAS_OCTETS_MAX];
        vide.ecrire(&mut sortie);
        assert_eq!(AliasRange::lire(&sortie), Ok(vide));
    }

    #[test]
    fn un_texte_a_la_borne_tient_exactement() {
        let pile = "x".repeat(ALIAS_OCTETS_MAX);
        let range = AliasRange::nouveau(&pile).expect("il tient pile");
        assert_eq!(range.longueur(), ALIAS_OCTETS_MAX);
    }

    #[test]
    fn un_texte_trop_long_est_refuse() {
        let trop = "x".repeat(ALIAS_OCTETS_MAX + 1);
        assert_eq!(
            AliasRange::nouveau(&trop),
            Err(Faute::Longueur {
                annoncee: ALIAS_OCTETS_MAX + 1,
                maximum: ALIAS_OCTETS_MAX,
            })
        );
    }

    #[test]
    fn le_bourrage_vaut_aussi_pour_un_nom_de_service() {
        // **DEUX INSTANCIATIONS, DEUX FONCTIONS** : éprouver le bourrage sur la
        // taille d'un alias ne dit rien de celle d'un nom de service.
        let mut octets = [0_u8; 1 + NOM_OCTETS_MAX];
        octets[0] = 4;
        octets[1] = b'i';
        octets[2] = b'm';
        octets[3] = b'a';
        octets[4] = b'p';
        octets[40] = 0xFF;
        assert_eq!(NomRange::lire(&octets), Err(Faute::Bourrage));
    }

    #[test]
    fn la_borne_vaut_aussi_pour_un_nom_de_service() {
        // **LES DEUX TAILLES SONT DEUX INSTANCIATIONS**, et éprouver l'une ne
        // dit rien de l'autre : un `const N` produit deux fonctions distinctes.
        let trop = "x".repeat(NOM_OCTETS_MAX + 1);
        assert_eq!(
            NomRange::nouveau(&trop),
            Err(Faute::Longueur {
                annoncee: NOM_OCTETS_MAX + 1,
                maximum: NOM_OCTETS_MAX,
            })
        );
        let pile = "x".repeat(NOM_OCTETS_MAX);
        assert!(NomRange::nouveau(&pile).is_ok());
    }

    #[test]
    fn une_longueur_corrompue_ne_fait_jamais_lire_au_dela() {
        // **C'EST LA SEULE LONGUEUR QUI VIENNE DES OCTETS**, et donc la seule
        // qui puisse mentir. Le tableau qui la suit est sa borne.
        let mut octets = [0_u8; 1 + ALIAS_OCTETS_MAX];
        octets[0] = 200;
        assert_eq!(
            Court::<ALIAS_OCTETS_MAX>::lire(&octets),
            Err(Faute::Longueur {
                annoncee: 200,
                maximum: ALIAS_OCTETS_MAX,
            })
        );
    }

    #[test]
    fn un_bourrage_de_texte_non_nul_est_refuse() {
        // **L'ENCODAGE EST CANONIQUE** : une valeur, une seule suite d'octets.
        // Ce qui suit le texte ne porte rien, et ne doit donc rien porter.
        let mut octets = [0_u8; 1 + ALIAS_OCTETS_MAX];
        octets[0] = 3;
        octets[1] = b'a';
        octets[2] = b'b';
        octets[3] = b'c';
        octets[9] = 0xFF;
        assert_eq!(
            Court::<ALIAS_OCTETS_MAX>::lire(&octets),
            Err(Faute::Bourrage)
        );
    }

    // ── Provenance ──────────────────────────────────────────────────────────

    #[test]
    fn une_provenance_locale_se_relit() {
        let mut sortie = [0_u8; PROVENANCE_OCTETS];
        Provenance::Ici.ecrire(&mut sortie);
        assert_eq!(Provenance::lire(&sortie), Ok(Provenance::Ici));
    }

    #[test]
    fn une_provenance_locale_n_emporte_aucun_reste() {
        // Un tampon réemployé garderait sinon l'identifiant précédent sur le
        // disque, invisible mais présent.
        let mut sortie = [0xFF_u8; PROVENANCE_OCTETS];
        Provenance::Ici.ecrire(&mut sortie);
        assert!(
            sortie.iter().skip(1).all(|octet| *octet == 0),
            "le reste n'a pas été effacé : {sortie:?}"
        );
    }

    #[test]
    fn une_provenance_distante_se_relit() {
        let annuaire = un(Genre::Annuaire, 7);
        let mut sortie = [0_u8; PROVENANCE_OCTETS];
        Provenance::Annuaire(annuaire).ecrire(&mut sortie);
        assert_eq!(
            Provenance::lire(&sortie),
            Ok(Provenance::Annuaire(annuaire))
        );
    }

    #[test]
    fn une_etiquette_de_provenance_inconnue_est_refusee() {
        let mut octets = [0_u8; PROVENANCE_OCTETS];
        octets[0] = 9;
        assert_eq!(Provenance::lire(&octets), Err(Faute::Etiquette { lue: 9 }));
    }

    #[test]
    fn une_provenance_distante_exige_un_genre_annuaire() {
        // Un identifiant d'utilisateur à la place d'un annuaire : la corruption
        // se voit ici, et pas trois couches plus haut.
        let mut octets = [0_u8; PROVENANCE_OCTETS];
        octets[0] = 1;
        octets[1] = Genre::Utilisateur.prefixe();
        assert_eq!(
            Provenance::lire(&octets),
            Err(Faute::Genre {
                attendu: Genre::Annuaire
            })
        );
    }

    #[test]
    fn la_rupture_de_confiance_reconnait_ce_qui_vient_du_pair() {
        let pair = un(Genre::Annuaire, 1);
        let autre = un(Genre::Annuaire, 2);
        assert!(Provenance::Annuaire(pair).vient_de(pair));
        assert!(!Provenance::Annuaire(autre).vient_de(pair));
        assert!(
            !Provenance::Ici.vient_de(pair),
            "ce qu'on a écrit soi-même ne s'efface jamais avec une relation"
        );
    }

    #[test]
    fn une_provenance_locale_au_bourrage_sale_est_refusee() {
        // C'est le cas qui compte : un champ ajouté par une version future
        // serait sinon ignoré en silence, et l'enregistrement rendu amputé en
        // se croyant entier.
        let mut octets = [0_u8; PROVENANCE_OCTETS];
        octets[5] = 1;
        assert_eq!(Provenance::lire(&octets), Err(Faute::Bourrage));
    }

    // ── Compte ──────────────────────────────────────────────────────────────

    #[test]
    fn un_compte_sans_alias_se_relit() {
        let compte = Compte {
            provenance: Provenance::Ici,
            alias: None,
        };
        let mut sortie = [0_u8; COMPTE_OCTETS];
        compte.ecrire(&mut sortie);
        assert_eq!(Compte::lire(&sortie), Ok(compte));
    }

    #[test]
    fn un_compte_avec_alias_se_relit() {
        let compte = Compte {
            provenance: Provenance::Annuaire(un(Genre::Annuaire, 3)),
            alias: Some(AliasRange::nouveau("thierry").expect("il tient")),
        };
        let mut sortie = [0_u8; COMPTE_OCTETS];
        compte.ecrire(&mut sortie);
        assert_eq!(Compte::lire(&sortie), Ok(compte));
    }

    #[test]
    fn un_compte_sans_alias_n_emporte_aucun_reste() {
        let avec = Compte {
            provenance: Provenance::Ici,
            alias: Some(AliasRange::nouveau("visible").expect("il tient")),
        };
        let mut sortie = [0_u8; COMPTE_OCTETS];
        avec.ecrire(&mut sortie);

        let sans = Compte {
            provenance: Provenance::Ici,
            alias: None,
        };
        sans.ecrire(&mut sortie);
        assert!(
            !sortie.windows(7).any(|f| f == b"visible"),
            "l'alias précédent est resté sur le disque"
        );
        assert_eq!(Compte::lire(&sortie), Ok(sans));
    }

    #[test]
    fn une_etiquette_d_alias_inconnue_est_refusee() {
        let mut octets = [0_u8; COMPTE_OCTETS];
        octets[PROVENANCE_OCTETS] = 4;
        assert_eq!(Compte::lire(&octets), Err(Faute::Etiquette { lue: 4 }));
    }

    #[test]
    fn un_alias_de_longueur_corrompue_refuse_le_compte_entier() {
        let mut octets = [0_u8; COMPTE_OCTETS];
        octets[PROVENANCE_OCTETS] = 1;
        octets[PROVENANCE_OCTETS + 1] = 250;
        assert_eq!(
            Compte::lire(&octets),
            Err(Faute::Longueur {
                annoncee: 250,
                maximum: ALIAS_OCTETS_MAX,
            })
        );
    }

    #[test]
    fn une_provenance_corrompue_refuse_le_compte_entier() {
        // La faute remonte du champ au dossier : un compte dont on ne sait pas
        // d'où il vient ne peut pas être effacé par une rupture de confiance,
        // donc il ne doit pas être relu du tout.
        let mut octets = [0_u8; COMPTE_OCTETS];
        octets[0] = 9;
        assert_eq!(Compte::lire(&octets), Err(Faute::Etiquette { lue: 9 }));
    }

    #[test]
    fn un_compte_sans_alias_au_bourrage_sale_est_refuse() {
        let mut octets = [0_u8; COMPTE_OCTETS];
        octets[PROVENANCE_OCTETS + 4] = 0xAA;
        assert_eq!(Compte::lire(&octets), Err(Faute::Bourrage));
    }

    // ── Machine ─────────────────────────────────────────────────────────────

    #[test]
    fn une_machine_se_relit_entiere() {
        let machine = Machine {
            provenance: Provenance::Ici,
            proprietaire: un(Genre::Utilisateur, 5),
            cle: Some([0x42; 32]),
            annonce: true,
            lecture: false,
            nom: nom_de_machine("grenier"),
        };
        let mut sortie = [0_u8; MACHINE_OCTETS];
        machine.ecrire(&mut sortie);
        assert_eq!(Machine::lire(&sortie), Ok(machine));
    }

    #[test]
    fn les_quatre_combinaisons_de_capacites_se_relisent() {
        for (annonce, lecture) in [(false, false), (true, false), (false, true), (true, true)] {
            let machine = Machine {
                provenance: Provenance::Ici,
                proprietaire: un(Genre::Utilisateur, 1),
                cle: Some([0; 32]),
                annonce,
                lecture,
                nom: nom_de_machine("grenier"),
            };
            let mut sortie = [0_u8; MACHINE_OCTETS];
            machine.ecrire(&mut sortie);
            assert_eq!(Machine::lire(&sortie), Ok(machine), "{annonce} {lecture}");
        }
    }

    #[test]
    fn un_bit_de_capacite_inconnu_est_refuse() {
        // **UNE VERSION QUI EN SAIT PLUS QUE NOUS NE DOIT PAS ÊTRE RELUE À
        // MOITIÉ** : lui prêter des capacités qu'on ne comprend pas serait pire
        // que de refuser.
        let machine = Machine {
            provenance: Provenance::Ici,
            proprietaire: un(Genre::Utilisateur, 1),
            cle: Some([0; 32]),
            annonce: true,
            lecture: true,
            nom: nom_de_machine("grenier"),
        };
        let mut octets = [0_u8; MACHINE_OCTETS];
        machine.ecrire(&mut octets);
        // **L'OCTET DES DRAPEAUX N'EST PLUS LE DERNIER** : le nom le suit
        // désormais. Le calculer depuis les constantes plutôt que de compter à
        // rebours est ce qui empêche cet essai de viser à côté au prochain champ
        // — il a visé à côté une fois, et il a rendu `Bourrage`.
        let drapeaux = PROVENANCE_OCTETS + IDENTIFIANT_OCTETS + CLE_OCTETS;
        octets[drapeaux] |= 0b1000_0000;
        assert_eq!(
            // `0b111` : annonce, lecture, et la clé posée.
            Machine::lire(&octets),
            Err(Faute::Etiquette { lue: 0b1000_0111 })
        );
    }

    #[test]
    fn une_machine_sans_cle_se_relit_sans_cle() {
        // C'est l'état d'une machine DÉCLARÉE et pas encore enrôlée, et il doit
        // faire l'aller-retour comme les autres.
        let machine = Machine {
            provenance: Provenance::Ici,
            proprietaire: un(Genre::Utilisateur, 1),
            cle: None,
            annonce: false,
            lecture: true,
            nom: nom_de_machine("portable"),
        };
        let mut octets = [0_u8; MACHINE_OCTETS];
        machine.ecrire(&mut octets);
        assert_eq!(Machine::lire(&octets), Ok(machine));
    }

    #[test]
    fn une_machine_sans_cle_dont_la_place_n_est_pas_nulle_est_refusee() {
        // **DEUX ÉCRITURES POUR UNE MÊME VALEUR, ET C'EST NON.** Sans ce refus,
        // un enregistrement relu ne se réécrirait pas comme il a été lu.
        let machine = Machine {
            provenance: Provenance::Ici,
            proprietaire: un(Genre::Utilisateur, 1),
            cle: None,
            annonce: true,
            lecture: false,
            nom: nom_de_machine("grenier"),
        };
        let mut octets = [0_u8; MACHINE_OCTETS];
        machine.ecrire(&mut octets);
        octets[PROVENANCE_OCTETS + IDENTIFIANT_OCTETS] = 0x01;
        assert_eq!(Machine::lire(&octets), Err(Faute::Bourrage));
    }

    #[test]
    fn un_proprietaire_qui_n_est_pas_un_utilisateur_est_refuse() {
        let mut octets = [0_u8; MACHINE_OCTETS];
        octets[PROVENANCE_OCTETS] = Genre::Service.prefixe();
        assert_eq!(
            Machine::lire(&octets),
            Err(Faute::Genre {
                attendu: Genre::Utilisateur
            })
        );
    }

    #[test]
    fn une_provenance_corrompue_refuse_la_machine_entiere() {
        let mut octets = [0_u8; MACHINE_OCTETS];
        octets[0] = 9;
        assert_eq!(Machine::lire(&octets), Err(Faute::Etiquette { lue: 9 }));
    }

    // ── Service ─────────────────────────────────────────────────────────────

    #[test]
    fn un_service_se_relit_entier() {
        let service = Service {
            provenance: Provenance::Ici,
            machine: un(Genre::Machine, 4),
            nom: NomRange::nouveau("depot-de-messages").expect("il tient"),
        };
        let mut sortie = [0_u8; SERVICE_OCTETS];
        service.ecrire(&mut sortie);
        assert_eq!(Service::lire(&sortie), Ok(service));
    }

    #[test]
    fn un_service_dont_la_machine_n_en_est_pas_une_est_refuse() {
        let mut octets = [0_u8; SERVICE_OCTETS];
        octets[PROVENANCE_OCTETS] = Genre::Utilisateur.prefixe();
        assert_eq!(
            Service::lire(&octets),
            Err(Faute::Genre {
                attendu: Genre::Machine
            })
        );
    }

    #[test]
    fn un_service_au_nom_corrompu_est_refuse() {
        let mut octets = [0_u8; SERVICE_OCTETS];
        octets[PROVENANCE_OCTETS] = Genre::Machine.prefixe();
        octets[PROVENANCE_OCTETS + IDENTIFIANT_OCTETS] = 250;
        assert_eq!(
            Service::lire(&octets),
            Err(Faute::Longueur {
                annoncee: 250,
                maximum: NOM_OCTETS_MAX,
            })
        );
    }

    #[test]
    fn une_provenance_corrompue_refuse_le_service_entier() {
        let mut octets = [0_u8; SERVICE_OCTETS];
        octets[0] = 9;
        assert_eq!(Service::lire(&octets), Err(Faute::Etiquette { lue: 9 }));
    }

    // ── Portée et autorisation ──────────────────────────────────────────────

    /// Une autorisation, reproductible.
    fn une_autorisation(portee: Portee) -> Autorisation {
        Autorisation {
            provenance: Provenance::Ici,
            par: un(Genre::Utilisateur, 1),
            a: un(Genre::Utilisateur, 2),
            portee,
            revoquee: false,
        }
    }

    #[test]
    fn les_trois_portees_se_relisent() {
        for portee in [
            Portee::ToutLeCompte,
            Portee::UneMachine(un(Genre::Machine, 5)),
            Portee::UnService(un(Genre::Service, 6)),
        ] {
            let autorisation = une_autorisation(portee);
            let mut sortie = [0_u8; AUTORISATION_OCTETS];
            autorisation.ecrire(&mut sortie);
            assert_eq!(Autorisation::lire(&sortie), Ok(autorisation), "{portee:?}");
        }
    }

    #[test]
    fn une_autorisation_revoquee_se_relit_revoquee() {
        // **ELLE EST RÉVOQUÉE, JAMAIS EFFACÉE** : sans ce drapeau, on ne
        // pourrait plus dire qu'elle a existé.
        let mut autorisation = une_autorisation(Portee::ToutLeCompte);
        autorisation.revoquee = true;
        let mut sortie = [0_u8; AUTORISATION_OCTETS];
        autorisation.ecrire(&mut sortie);
        assert_eq!(Autorisation::lire(&sortie), Ok(autorisation));
    }

    #[test]
    fn une_portee_de_tout_le_compte_ne_garde_aucun_reste() {
        // Sinon l'identifiant d'une portée précédente resterait sur le disque.
        let large = une_autorisation(Portee::UneMachine(un(Genre::Machine, 5)));
        let mut sortie = [0_u8; AUTORISATION_OCTETS];
        large.ecrire(&mut sortie);
        let tout = une_autorisation(Portee::ToutLeCompte);
        tout.ecrire(&mut sortie);
        assert_eq!(Autorisation::lire(&sortie), Ok(tout));
    }

    #[test]
    fn une_etiquette_de_portee_inconnue_est_refusee() {
        let autorisation = une_autorisation(Portee::ToutLeCompte);
        let mut octets = [0_u8; AUTORISATION_OCTETS];
        autorisation.ecrire(&mut octets);
        let place = PROVENANCE_OCTETS + IDENTIFIANT_OCTETS + IDENTIFIANT_OCTETS;
        octets[place] = 7;
        assert_eq!(
            Autorisation::lire(&octets),
            Err(Faute::Etiquette { lue: 7 })
        );
    }

    #[test]
    fn une_portee_de_tout_le_compte_au_bourrage_sale_est_refusee() {
        let autorisation = une_autorisation(Portee::ToutLeCompte);
        let mut octets = [0_u8; AUTORISATION_OCTETS];
        autorisation.ecrire(&mut octets);
        let place = PROVENANCE_OCTETS + IDENTIFIANT_OCTETS + IDENTIFIANT_OCTETS + 3;
        octets[place] = 0xAA;
        assert_eq!(Autorisation::lire(&octets), Err(Faute::Bourrage));
    }

    #[test]
    fn une_portee_de_machine_exige_un_genre_machine() {
        let autorisation = une_autorisation(Portee::UnService(un(Genre::Service, 1)));
        let mut octets = [0_u8; AUTORISATION_OCTETS];
        autorisation.ecrire(&mut octets);
        let place = PROVENANCE_OCTETS + IDENTIFIANT_OCTETS + IDENTIFIANT_OCTETS;
        octets[place] = Portee::MACHINE;
        assert_eq!(
            Autorisation::lire(&octets),
            Err(Faute::Genre {
                attendu: Genre::Machine
            })
        );
    }

    #[test]
    fn une_portee_de_service_exige_un_genre_service() {
        let autorisation = une_autorisation(Portee::UneMachine(un(Genre::Machine, 1)));
        let mut octets = [0_u8; AUTORISATION_OCTETS];
        autorisation.ecrire(&mut octets);
        let place = PROVENANCE_OCTETS + IDENTIFIANT_OCTETS + IDENTIFIANT_OCTETS;
        octets[place] = Portee::SERVICE;
        assert_eq!(
            Autorisation::lire(&octets),
            Err(Faute::Genre {
                attendu: Genre::Service
            })
        );
    }

    #[test]
    fn un_drapeau_de_revocation_qui_n_est_ni_0_ni_1_est_refuse() {
        // **PAS DE « VRAI PAR DÉFAUT ».** Un booléen relu de travers sur une
        // décision d'autorisation est exactement ce qu'on ne veut pas deviner.
        let autorisation = une_autorisation(Portee::ToutLeCompte);
        let mut octets = [0_u8; AUTORISATION_OCTETS];
        autorisation.ecrire(&mut octets);
        let dernier = AUTORISATION_OCTETS - 1;
        octets[dernier] = 2;
        assert_eq!(
            Autorisation::lire(&octets),
            Err(Faute::Etiquette { lue: 2 })
        );
    }

    #[test]
    fn les_deux_comptes_d_une_autorisation_doivent_etre_des_utilisateurs() {
        for place in [PROVENANCE_OCTETS, PROVENANCE_OCTETS + IDENTIFIANT_OCTETS] {
            let autorisation = une_autorisation(Portee::ToutLeCompte);
            let mut octets = [0_u8; AUTORISATION_OCTETS];
            autorisation.ecrire(&mut octets);
            octets[place] = Genre::Machine.prefixe();
            assert_eq!(
                Autorisation::lire(&octets),
                Err(Faute::Genre {
                    attendu: Genre::Utilisateur
                }),
                "à l'octet {place}"
            );
        }
    }

    #[test]
    fn une_provenance_corrompue_refuse_l_autorisation_entiere() {
        let mut octets = [0_u8; AUTORISATION_OCTETS];
        octets[0] = 9;
        assert_eq!(
            Autorisation::lire(&octets),
            Err(Faute::Etiquette { lue: 9 })
        );
    }

    // ── Journal ─────────────────────────────────────────────────────────────

    /// Une entrée de journal, reproductible.
    fn une_entree(quand: u64) -> EntreeJournal {
        EntreeJournal {
            quand,
            demandeur: un(Genre::Machine, 1),
            visee: un(Genre::Machine, 2),
            service: NomRange::nouveau("imap").expect("il tient"),
            verdict: Verdict::Servi,
            provenance: Provenance::Ici,
        }
    }

    #[test]
    fn une_entree_de_journal_se_relit_entiere() {
        let entree = une_entree(1_757_000_000_000);
        let mut sortie = [0_u8; ENTREE_OCTETS];
        entree.ecrire(&mut sortie);
        assert_eq!(EntreeJournal::lire(&sortie), Ok(entree));
    }

    #[test]
    fn les_trois_verdicts_se_relisent() {
        for verdict in [Verdict::Servi, Verdict::Refuse, Verdict::Introuvable] {
            let mut entree = une_entree(1);
            entree.verdict = verdict;
            let mut sortie = [0_u8; ENTREE_OCTETS];
            entree.ecrire(&mut sortie);
            assert_eq!(EntreeJournal::lire(&sortie), Ok(entree), "{verdict:?}");
        }
    }

    #[test]
    fn un_verdict_inconnu_est_refuse() {
        let entree = une_entree(1);
        let mut octets = [0_u8; ENTREE_OCTETS];
        entree.ecrire(&mut octets);
        let place = 8 + 17 + 17 + 1 + NOM_OCTETS_MAX;
        octets[place] = 200;
        assert_eq!(
            EntreeJournal::lire(&octets),
            Err(Faute::Etiquette { lue: 200 })
        );
    }

    #[test]
    fn un_demandeur_qui_n_est_pas_une_machine_est_refuse() {
        let mut octets = [0_u8; ENTREE_OCTETS];
        octets[8] = Genre::Utilisateur.prefixe();
        assert_eq!(
            EntreeJournal::lire(&octets),
            Err(Faute::Genre {
                attendu: Genre::Machine
            })
        );
    }

    #[test]
    fn une_visee_qui_n_est_pas_une_machine_est_refusee() {
        let mut octets = [0_u8; ENTREE_OCTETS];
        octets[8] = Genre::Machine.prefixe();
        octets[8 + 17] = Genre::Service.prefixe();
        assert_eq!(
            EntreeJournal::lire(&octets),
            Err(Faute::Genre {
                attendu: Genre::Machine
            })
        );
    }

    #[test]
    fn un_nom_de_service_corrompu_refuse_l_entree() {
        let entree = une_entree(1);
        let mut octets = [0_u8; ENTREE_OCTETS];
        entree.ecrire(&mut octets);
        octets[8 + 17 + 17] = 250;
        assert_eq!(
            EntreeJournal::lire(&octets),
            Err(Faute::Longueur {
                annoncee: 250,
                maximum: NOM_OCTETS_MAX,
            })
        );
    }

    #[test]
    fn une_provenance_de_journal_corrompue_refuse_l_entree() {
        let entree = une_entree(1);
        let mut octets = [0_u8; ENTREE_OCTETS];
        entree.ecrire(&mut octets);
        let place = 8 + 17 + 17 + 1 + NOM_OCTETS_MAX + 1;
        octets[place] = 9;
        assert_eq!(
            EntreeJournal::lire(&octets),
            Err(Faute::Etiquette { lue: 9 })
        );
    }

    // ── La clé, et C18 ──────────────────────────────────────────────────────

    #[test]
    fn l_ordre_des_clefs_est_l_ordre_du_temps() {
        // **C'EST CE QUI REND C18 EXÉCUTABLE.** Sans cet ordre, expirer
        // quatre-vingt-dix jours demanderait de lire le journal entier.
        let tot = une_entree(1_000).clef(0);
        let tard = une_entree(2_000).clef(0);
        assert!(tot < tard, "l'horodatage n'ordonne pas les clés");
    }

    #[test]
    fn deux_entrees_de_la_meme_milliseconde_ne_se_confondent_pas() {
        // Sans le rang, la seconde écraserait la première — et le journal
        // perdrait des faits sous charge, c'est-à-dire quand il compte.
        let entree = une_entree(1_000);
        assert_ne!(entree.clef(0), entree.clef(1));
        assert!(entree.clef(0) < entree.clef(1), "le rang ordonne aussi");
    }

    #[test]
    fn une_clef_fait_la_taille_annoncee() {
        assert_eq!(une_entree(1).clef(0).len(), CLEF_JOURNAL_OCTETS);
    }

    /// Un nom de machine, pour les essais.
    fn nom_de_machine(texte: &str) -> NomRange {
        NomRange::nouveau(texte).expect("un nom court se range")
    }

    // ── L'appareil et l'enrôlement ──────────────────────────────────────────

    #[test]
    fn un_appareil_fait_l_aller_retour() {
        let appareil = Appareil {
            provenance: Provenance::Ici,
            proprietaire: un(Genre::Utilisateur, 7),
            cle: [0x33; CLE_OCTETS],
        };
        let mut octets = [0_u8; APPAREIL_OCTETS];
        appareil.ecrire(&mut octets);
        assert_eq!(Appareil::lire(&octets), Ok(appareil));
    }

    #[test]
    fn un_appareil_venu_d_un_pair_fait_l_aller_retour() {
        // C17 : il porte son origine comme tout le reste, même si rien ne
        // fédère un téléphone aujourd'hui.
        let appareil = Appareil {
            provenance: Provenance::Annuaire(un(Genre::Annuaire, 2)),
            proprietaire: un(Genre::Utilisateur, 7),
            cle: [0; CLE_OCTETS],
        };
        let mut octets = [0_u8; APPAREIL_OCTETS];
        appareil.ecrire(&mut octets);
        assert_eq!(Appareil::lire(&octets), Ok(appareil));
    }

    #[test]
    fn un_proprietaire_d_appareil_qui_n_est_pas_un_utilisateur_est_refuse() {
        let mut octets = [0_u8; APPAREIL_OCTETS];
        octets[PROVENANCE_OCTETS] = Genre::Machine.prefixe();
        assert_eq!(
            Appareil::lire(&octets),
            Err(Faute::Genre {
                attendu: Genre::Utilisateur
            })
        );
    }

    #[test]
    fn un_enrolement_fait_l_aller_retour() {
        let enrolement = Enrolement {
            provenance: Provenance::Ici,
            machine: un(Genre::Machine, 4),
            expire_a: 1_757_000_000_000,
        };
        let mut octets = [0_u8; ENROLEMENT_OCTETS];
        enrolement.ecrire(&mut octets);
        assert_eq!(Enrolement::lire(&octets), Ok(enrolement));
    }

    #[test]
    fn un_enrolement_venu_d_un_pair_fait_l_aller_retour() {
        let enrolement = Enrolement {
            provenance: Provenance::Annuaire(un(Genre::Annuaire, 9)),
            machine: un(Genre::Machine, 4),
            expire_a: 0,
        };
        let mut octets = [0_u8; ENROLEMENT_OCTETS];
        enrolement.ecrire(&mut octets);
        assert_eq!(Enrolement::lire(&octets), Ok(enrolement));
    }

    #[test]
    fn un_enrolement_qui_ne_designe_pas_une_machine_est_refuse() {
        let mut octets = [0_u8; ENROLEMENT_OCTETS];
        octets[PROVENANCE_OCTETS] = Genre::Service.prefixe();
        assert_eq!(
            Enrolement::lire(&octets),
            Err(Faute::Genre {
                attendu: Genre::Machine
            })
        );
    }

    #[test]
    fn une_machine_dont_le_nom_est_illisible_est_refusee() {
        // La longueur annoncée du nom dépasse la place : c'est une corruption,
        // et elle se lit plutôt qu'elle ne se devine.
        let machine = Machine {
            provenance: Provenance::Ici,
            proprietaire: un(Genre::Utilisateur, 1),
            cle: Some([9; CLE_OCTETS]),
            annonce: true,
            lecture: true,
            nom: nom_de_machine("grenier"),
        };
        let mut octets = [0_u8; MACHINE_OCTETS];
        machine.ecrire(&mut octets);
        let longueur_du_nom = PROVENANCE_OCTETS + IDENTIFIANT_OCTETS + CLE_OCTETS + 1;
        octets[longueur_du_nom] = 200;
        assert_eq!(
            Machine::lire(&octets),
            Err(Faute::Longueur {
                annoncee: 200,
                maximum: NOM_OCTETS_MAX
            })
        );
    }

    #[test]
    fn une_provenance_illisible_est_refusee_sur_les_deux_enregistrements_neufs() {
        // L'étiquette de provenance vient en tête : elle est le premier refus.
        let mut appareil = [0_u8; APPAREIL_OCTETS];
        appareil[0] = 0x7F;
        assert_eq!(
            Appareil::lire(&appareil),
            Err(Faute::Etiquette { lue: 0x7F })
        );

        let mut enrolement = [0_u8; ENROLEMENT_OCTETS];
        enrolement[0] = 0x7F;
        assert_eq!(
            Enrolement::lire(&enrolement),
            Err(Faute::Etiquette { lue: 0x7F })
        );
    }
}
