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

/// Ce qu'une estampille occupe : le compteur, puis l'identifiant de la racine.
pub const ESTAMPILLE_OCTETS: usize = 8 + IDENTIFIANT_OCTETS;

/// Ce que l'empreinte d'un code d'enrôlement occupe. Égal à
/// `asl_cle::EMPREINTE_OCTETS`, défini ici plutôt qu'importé — pour la raison
/// écrite sur [`CLE_APPAREIL_OCTETS`] : une grammaire ne dépend pas d'une
/// décision.
pub const EMPREINTE_OCTETS: usize = 32;

/// Ce qu'un alias peut faire, en octets. Égal à `asl_api::ALIAS_MAX`.
pub const ALIAS_OCTETS_MAX: usize = 32;

/// Ce qu'un nom de service peut faire. Égal à `asl_proto::NOM_MAX`.
pub const NOM_OCTETS_MAX: usize = 64;

/// Ce qu'une clé publique Ed25519 occupe. C'est celle d'une MACHINE.
pub const CLE_OCTETS: usize = 32;

/// Ce qu'une clé publique d'APPAREIL occupe : un point P-256, SEC1 compressé.
///
/// La Secure Enclave et StrongBox ne font que cette courbe, donc la clé d'un
/// téléphone ne peut pas être un Ed25519 de 32 octets. Égal à
/// `asl_cle::CLE_APPAREIL_OCTETS`, défini ici plutôt qu'importé — `asl-cle` est
/// à l'étage 2, ce format à l'étage 1, et une grammaire ne dépend pas d'une
/// décision.
pub const CLE_APPAREIL_OCTETS: usize = 33;

/// Ce qu'un jeton de poussée peut faire.
///
/// # POURQUOI 255, ET NON UNE BORNE CHOISIE POUR CE QU'ON VOIT AUJOURD'HUI
///
/// Un jeton APNs fait 64 caractères hexadécimaux ; un jeton FCM en fait environ
/// 160, et **Google ne promet aucune longueur** — sa documentation dit de ne pas
/// en supposer une. Une borne serrée sur ce qu'on observe aujourd'hui refuserait
/// un jour un jeton parfaitement valide, et le téléphone concerné cesserait
/// silencieusement de recevoir ses notifications.
///
/// 255 est le plus grand que [`Court`] sache écrire — sa longueur tient sur un
/// octet — et c'est la raison de ce nombre-là plutôt qu'un autre.
pub const JETON_OCTETS_MAX: usize = 255;

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
    /// Un texte porte un octet qui ne s'imprime pas.
    ///
    /// # ELLE N'EXISTE QUE POUR LE JETON DE POUSSÉE, ET IL FAUT DIRE POURQUOI
    ///
    /// Partout ailleurs, une longueur corrompue se voit : elle dépasse le
    /// tableau. **Le jeton de poussée est le seul texte dont la borne vaut 255**,
    /// et une longueur tenant sur un octet ne peut donc jamais la dépasser — le
    /// contrôle de [`Court::lire`] y est structurellement inatteignable.
    ///
    /// Ce qui reste pour voir la corruption est le contenu : un jeton est du
    /// texte imprimable, et un octet nul au milieu trahit une longueur qu'on a
    /// allongée.
    NonImprimable {
        /// Où, dans le texte.
        position: usize,
    },
    /// Une opération dont les octets s'arrêtent avant la fin de sa charge.
    ///
    /// # ELLE N'EXISTE QUE POUR LES OPÉRATIONS, ET C'EST STRUCTUREL
    ///
    /// Un enregistrement se lit dans un tableau de sa taille exacte, donc il
    /// ne peut pas être tronqué : la forme du type est la borne. Une opération
    /// se lit dans une TRANCHE — le disque en range une par valeur, le fil les
    /// enchaîne — et c'est son genre qui dit combien d'octets elle occupe. Une
    /// tranche plus courte que ce que le genre annonce n'est pas une opération.
    Tronquee {
        /// Ce que le genre exigeait.
        attendus: usize,
        /// Ce qu'il y avait.
        obtenus: usize,
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
        // La longueur tient sur un octet : `N` vaut au plus 255 dans ce module,
        // et `nouveau` a déjà refusé au-delà.
        #[expect(
            clippy::cast_possible_truncation,
            reason = "la longueur est bornée par N, au plus 255"
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

/// Un jeton de poussée rangé.
pub type JetonRange = Court<JETON_OCTETS_MAX>;

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

// ── L'estampille (`docs/modele.md` §2.10) ───────────────────────────────────

/// Quand — au sens d'une horloge de Lamport — et par quelle racine un
/// enregistrement a été écrit.
///
/// # UNE COLONNE DE PLUS, SUR LE MODÈLE DE L'ORIGINE
///
/// Chaque racine tient un compteur, et chaque écriture locale porte
/// `(compteur, racine)` : le compteur avance de un à chaque écriture, et se
/// hisse au-dessus de tout ce que la racine reçoit de l'autre
/// (`docs/replication.md` §4). **C'est ce qui rend la règle de conflit
/// calculable après coup**, dans les deux ordres d'arrivée — et non l'heure
/// murale, que deux machines n'ont pas en commun et qu'un NTP recale.
///
/// # L'ORDRE EST TOTAL, ET C'EST LE `derive` QUI LE TIENT
///
/// Le compteur d'abord, la racine ensuite : c'est l'ordre des champs, et
/// `Ord` dérivé les compare dans cet ordre. Deux racines qui calculent
/// « le plus ancien » sur des estampilles obtiennent donc le même — c'est
/// l'invariant de `replication.md` §3.1, et l'essai `l_ordre_des_estampilles…`
/// le tient.
///
/// **Elle ne dit pas l'heure**, et c'est une qualité : répliquer n'ajoute
/// aucune ligne de temps à ce que l'entrepôt porte déjà (C13, C18).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Estampille {
    /// La `compteur`-ième écriture de cette racine.
    pub compteur: u64,
    /// La racine qui a écrit.
    pub racine: Identifiant,
}

impl Estampille {
    /// Écrit cette estampille. Occupe [`ESTAMPILLE_OCTETS`].
    fn ecrire(self, sortie: &mut [u8]) {
        poser(sortie, &self.compteur.to_be_bytes());
        ecrire_identifiant(self.racine, sortie.get_mut(8..).unwrap_or_default());
    }

    /// Relit une estampille, et EXIGE que la racine soit un annuaire.
    fn lire(octets: &[u8]) -> Result<Self, Faute> {
        let mut compteur = [0_u8; 8];
        poser(&mut compteur, octets);
        let racine = lire_identifiant(octets.get(8..).unwrap_or_default(), Genre::Annuaire)?;
        Ok(Self {
            compteur: u64::from_be_bytes(compteur),
            racine,
        })
    }
}

// ── Le compte ───────────────────────────────────────────────────────────────

/// Ce qu'un compte occupe.
pub const COMPTE_OCTETS: usize =
    PROVENANCE_OCTETS + ESTAMPILLE_OCTETS + ESTAMPILLE_OCTETS + 1 + 1 + ALIAS_OCTETS_MAX;

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
    /// Sa dernière écriture.
    pub estampille: Estampille,
    /// L'alias public, si l'utilisateur en a choisi un.
    pub alias: Option<AliasRange>,
    /// La réclamation courante de l'alias — son dernier `PUT` ou `DELETE`.
    ///
    /// # UN ALIAS EST UNE RÉCLAMATION, ET LA PLUS ANCIENNE TIENT
    ///
    /// `docs/replication.md` §3.2 : pour un alias donné, le titulaire est le
    /// compte dont la réclamation courante porte la plus petite estampille.
    /// C'est une fonction de l'ensemble des réclamations, pas de leur ordre
    /// d'arrivée — et pour la calculer, chaque compte doit porter QUAND il a
    /// réclamé. Sans alias, c'est l'estampille de son dernier retrait, ou de
    /// sa création.
    pub reclamation: Estampille,
}

impl Compte {
    /// Écrit ce compte.
    pub fn ecrire(&self, sortie: &mut [u8; COMPTE_OCTETS]) {
        let mut curseur = 0_usize;
        let mut tranche = |combien: usize| {
            let debut = curseur;
            curseur = curseur.saturating_add(combien);
            debut..curseur
        };
        let provenance = tranche(PROVENANCE_OCTETS);
        self.provenance
            .ecrire(sortie.get_mut(provenance).unwrap_or_default());
        let estampille = tranche(ESTAMPILLE_OCTETS);
        self.estampille
            .ecrire(sortie.get_mut(estampille).unwrap_or_default());
        let reclamation = tranche(ESTAMPILLE_OCTETS);
        self.reclamation
            .ecrire(sortie.get_mut(reclamation).unwrap_or_default());
        let reste = sortie.get_mut(curseur..).unwrap_or_default();
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
        let mut curseur = 0_usize;
        let mut prendre = |combien: usize| {
            let debut = curseur;
            curseur = curseur.saturating_add(combien);
            debut..curseur
        };
        let provenance =
            Provenance::lire(octets.get(prendre(PROVENANCE_OCTETS)).unwrap_or_default())?;
        let estampille =
            Estampille::lire(octets.get(prendre(ESTAMPILLE_OCTETS)).unwrap_or_default())?;
        let reclamation =
            Estampille::lire(octets.get(prendre(ESTAMPILLE_OCTETS)).unwrap_or_default())?;
        Self::lire_corps(
            provenance,
            estampille,
            reclamation,
            octets.get(curseur..).unwrap_or_default(),
        )
    }

    /// Relit un compte de la forme d'avant l'estampille, et lui donne celle-ci.
    ///
    /// **C'est la reprise de `docs/replication.md` §11.4** : une base écrite
    /// avant 0.5.0 n'a ni estampille ni réclamation, et chaque enregistrement
    /// en reçoit une, attribuée en séquence par la racine qui reprend. La
    /// réclamation reçoit la même : l'alias qu'un compte tenait est réclamé
    /// depuis sa reprise.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas un compte ancien.
    pub fn lire_ancien(
        octets: &[u8; ancien::COMPTE_OCTETS],
        estampille: Estampille,
    ) -> Result<Self, Faute> {
        let provenance = Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?;
        Self::lire_corps(
            provenance,
            estampille,
            estampille,
            octets.get(PROVENANCE_OCTETS..).unwrap_or_default(),
        )
    }

    /// Ce qui suit la provenance et les estampilles : l'alias, ou rien.
    fn lire_corps(
        provenance: Provenance,
        estampille: Estampille,
        reclamation: Estampille,
        reste: &[u8],
    ) -> Result<Self, Faute> {
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
        Ok(Self {
            provenance,
            estampille,
            alias,
            reclamation,
        })
    }
}

// ── La machine ──────────────────────────────────────────────────────────────

/// Ce qu'une machine occupe.
///
/// Cinq estampilles : la dernière écriture, le nom, les capacités, et les deux
/// de la clé — la liaison, et l'émission du code qui l'a liée.
pub const MACHINE_OCTETS: usize = PROVENANCE_OCTETS
    + ESTAMPILLE_OCTETS
    + ESTAMPILLE_OCTETS
    + ESTAMPILLE_OCTETS
    + ESTAMPILLE_OCTETS
    + ESTAMPILLE_OCTETS
    + IDENTIFIANT_OCTETS
    + CLE_OCTETS
    + 1
    + 1
    + NOM_OCTETS_MAX;

/// Les deux capacités d'une machine.
///
/// **C'est le miroir d'`asl_auth::Capacites`**, et il faut dire pourquoi il y
/// en a deux : celui-là DÉCIDE et vit à l'étage 2, celui-ci RANGE et vit à
/// l'étage 1 — la même raison que [`Portee`]. Il n'existe que pour
/// l'opération `machine-modifiee`, qui porte « les capacités » comme UN champ
/// avec UNE estampille ; l'enregistrement, lui, les range en deux bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capacites {
    /// Cette machine peut-elle annoncer des services ?
    pub annonce: bool,
    /// Cette machine peut-elle interroger l'annuaire ?
    pub lecture: bool,
}

impl Capacites {
    /// L'octet qui les range : annonce en bit 0, lecture en bit 1.
    const fn octet(self) -> u8 {
        let mut drapeaux = 0_u8;
        if self.annonce {
            drapeaux |= Machine::BIT_ANNONCE;
        }
        if self.lecture {
            drapeaux |= Machine::BIT_LECTURE;
        }
        drapeaux
    }
}

/// La clé d'une machine, et ce qui l'a liée.
///
/// # DEUX ESTAMPILLES, ET LA RÈGLE QUI LES EXIGE
///
/// `docs/replication.md` §3.2 : quand le même code a été consommé des deux
/// côtés, **la liaison qui gagne est celle du code le plus récemment ÉMIS ; à
/// code égal, la première consommation.** Pour le calculer après coup, la clé
/// doit porter les deux — l'estampille d'émission de son code, et la sienne.
/// C'est un ordre total, donc le plus grand gagne quel que soit l'ordre
/// d'arrivée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleLiee {
    /// La clé publique Ed25519.
    ///
    /// **Elle n'est pas interprétée ici.** `asl_cle::ClePublique::depuis_octets`
    /// sait dire si ces octets forment un point de la courbe ; ce module range
    /// des octets, et une seconde vérification serait une seconde vérité.
    pub cle: [u8; CLE_OCTETS],
    /// L'écriture qui l'a liée.
    pub liaison: Estampille,
    /// L'émission du code qui l'a liée.
    pub code: Estampille,
}

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
///
/// # UNE ESTAMPILLE PAR CHAMP, LÀ OÙ `PATCH` EST CHAMP PAR CHAMP
///
/// `docs/replication.md` §3.2 : un `PATCH` de machine des deux côtés se règle
/// **champ par champ** — le nom a son estampille, les capacités ont la leur.
/// Une règle par enregistrement ferait perdre un nom parce qu'une capacité a
/// gagné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Machine {
    /// D'où vient cet enregistrement.
    pub provenance: Provenance,
    /// Sa dernière écriture.
    pub estampille: Estampille,
    /// Le compte qui possède cette machine.
    pub proprietaire: Identifiant,
    /// Sa clé publique Ed25519, **si elle en a une**, et ce qui l'a liée.
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
    pub cle: Option<CleLiee>,
    /// Cette machine peut-elle annoncer des services ?
    pub annonce: bool,
    /// Cette machine peut-elle interroger l'annuaire ?
    pub lecture: bool,
    /// La dernière écriture des capacités.
    pub capacites_estampille: Estampille,
    /// Le nom que son propriétaire lui a donné.
    ///
    /// **Pour l'humain, jamais pour la machine** (`docs/modele.md` §2.3) : rien
    /// ne se cherche par ce nom, rien ne s'y compare. C'est ce qui permet qu'il
    /// porte du texte libre là où le nom d'un SERVICE ne le peut pas — celui-là
    /// est une clé, et une clé qui a deux écritures n'en est pas une.
    pub nom: NomRange,
    /// La dernière écriture du nom.
    pub nom_estampille: Estampille,
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

    /// Les capacités, comme un seul champ.
    #[must_use]
    pub const fn capacites(&self) -> Capacites {
        Capacites {
            annonce: self.annonce,
            lecture: self.lecture,
        }
    }

    /// Écrit cette machine.
    pub fn ecrire(&self, sortie: &mut [u8; MACHINE_OCTETS]) {
        let mut curseur = 0_usize;
        let mut tranche = |combien: usize| {
            let debut = curseur;
            curseur = curseur.saturating_add(combien);
            debut..curseur
        };
        let provenance = tranche(PROVENANCE_OCTETS);
        self.provenance
            .ecrire(sortie.get_mut(provenance).unwrap_or_default());
        let estampille = tranche(ESTAMPILLE_OCTETS);
        self.estampille
            .ecrire(sortie.get_mut(estampille).unwrap_or_default());
        let nom_estampille = tranche(ESTAMPILLE_OCTETS);
        self.nom_estampille
            .ecrire(sortie.get_mut(nom_estampille).unwrap_or_default());
        let capacites_estampille = tranche(ESTAMPILLE_OCTETS);
        self.capacites_estampille
            .ecrire(sortie.get_mut(capacites_estampille).unwrap_or_default());
        let liaison = tranche(ESTAMPILLE_OCTETS);
        let code = tranche(ESTAMPILLE_OCTETS);
        let proprietaire = tranche(IDENTIFIANT_OCTETS);
        ecrire_identifiant(
            self.proprietaire,
            sortie.get_mut(proprietaire).unwrap_or_default(),
        );
        let cle = tranche(CLE_OCTETS);
        match &self.cle {
            Some(liee) => {
                liee.liaison
                    .ecrire(sortie.get_mut(liaison).unwrap_or_default());
                liee.code.ecrire(sortie.get_mut(code).unwrap_or_default());
                poser(sortie.get_mut(cle).unwrap_or_default(), &liee.cle);
            }
            // Le bourrage à zéro, pour la raison écrite sur `bourrage_nul` —
            // les deux estampilles de la clé comme la clé elle-même.
            None => {
                sortie.get_mut(liaison).unwrap_or_default().fill(0);
                sortie.get_mut(code).unwrap_or_default().fill(0);
                sortie.get_mut(cle).unwrap_or_default().fill(0);
            }
        }
        let mut drapeaux = self.capacites().octet();
        if self.cle.is_some() {
            drapeaux |= Self::BIT_CLE;
        }
        let place = tranche(1);
        poser_un(sortie.get_mut(place).unwrap_or_default(), drapeaux);
        self.nom
            .ecrire(sortie.get_mut(curseur..).unwrap_or_default());
    }

    /// Relit une machine.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas une machine.
    pub fn lire(octets: &[u8; MACHINE_OCTETS]) -> Result<Self, Faute> {
        let mut curseur = 0_usize;
        let mut prendre = |combien: usize| {
            let debut = curseur;
            curseur = curseur.saturating_add(combien);
            debut..curseur
        };
        let provenance =
            Provenance::lire(octets.get(prendre(PROVENANCE_OCTETS)).unwrap_or_default())?;
        let estampille =
            Estampille::lire(octets.get(prendre(ESTAMPILLE_OCTETS)).unwrap_or_default())?;
        let nom_estampille =
            Estampille::lire(octets.get(prendre(ESTAMPILLE_OCTETS)).unwrap_or_default())?;
        let capacites_estampille =
            Estampille::lire(octets.get(prendre(ESTAMPILLE_OCTETS)).unwrap_or_default())?;
        let liaison = octets.get(prendre(ESTAMPILLE_OCTETS)).unwrap_or_default();
        let code = octets.get(prendre(ESTAMPILLE_OCTETS)).unwrap_or_default();
        Self::lire_corps(
            provenance,
            Estampilles {
                estampille,
                nom: nom_estampille,
                capacites: capacites_estampille,
            },
            LiaisonRangee::Lue { liaison, code },
            octets.get(curseur..).unwrap_or_default(),
        )
    }

    /// Relit une machine de la forme d'avant l'estampille, et lui donne
    /// celle-ci — pour chacun de ses champs.
    ///
    /// La reprise de `docs/replication.md` §11.4 : le nom, les capacités et la
    /// clé, si elle est là, sont réputés écrits à la reprise, par la racine qui
    /// reprend ; et le code qui a lié la clé est réputé émis au même instant.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas une machine ancienne.
    pub fn lire_ancien(
        octets: &[u8; ancien::MACHINE_OCTETS],
        estampille: Estampille,
    ) -> Result<Self, Faute> {
        let provenance = Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?;
        Self::lire_corps(
            provenance,
            Estampilles {
                estampille,
                nom: estampille,
                capacites: estampille,
            },
            LiaisonRangee::Reprise(estampille),
            octets.get(PROVENANCE_OCTETS..).unwrap_or_default(),
        )
    }

    /// Ce qui suit les estampilles : le propriétaire, la clé, les drapeaux,
    /// le nom — la forme qu'une machine a toujours eue.
    fn lire_corps(
        provenance: Provenance,
        estampilles: Estampilles,
        liaison: LiaisonRangee<'_>,
        reste: &[u8],
    ) -> Result<Self, Faute> {
        let mut curseur = 0_usize;
        let mut prendre = |combien: usize| {
            let debut = curseur;
            curseur = curseur.saturating_add(combien);
            debut..curseur
        };
        let proprietaire = lire_identifiant(
            reste.get(prendre(IDENTIFIANT_OCTETS)).unwrap_or_default(),
            Genre::Utilisateur,
        )?;
        let brute = reste.get(prendre(CLE_OCTETS)).unwrap_or_default();
        // **LES BITS INCONNUS SONT REFUSÉS.** Les accepter en silence ferait
        // relire sans broncher un enregistrement écrit par une version qui en
        // sait plus que nous — et lui prêterait des capacités qu'on ne
        // comprendrait pas.
        let drapeaux = reste
            .get(prendre(1))
            .and_then(<[u8]>::first)
            .copied()
            .unwrap_or(0);
        let connus = Self::BIT_ANNONCE | Self::BIT_LECTURE | Self::BIT_CLE;
        if drapeaux & !connus != 0 {
            return Err(Faute::Etiquette { lue: drapeaux });
        }
        let cle = if drapeaux & Self::BIT_CLE == 0 {
            // **PAS DE CLÉ VEUT DIRE QUE LA PLACE EST NULLE** — la clé, et ses
            // deux estampilles. Sans ce contrôle, deux enregistrements
            // différents se reliraient identiques, et l'un d'eux ne se
            // réécrirait pas comme il a été lu.
            if !bourrage_nul(brute) || !liaison.est_nulle() {
                return Err(Faute::Bourrage);
            }
            None
        } else {
            let mut octets = [0_u8; CLE_OCTETS];
            poser(&mut octets, brute);
            let (liaison, code) = liaison.lire()?;
            Some(CleLiee {
                cle: octets,
                liaison,
                code,
            })
        };
        let nom = NomRange::lire(reste.get(curseur..).unwrap_or_default())?;
        Ok(Self {
            provenance,
            estampille: estampilles.estampille,
            proprietaire,
            cle,
            annonce: drapeaux & Self::BIT_ANNONCE != 0,
            lecture: drapeaux & Self::BIT_LECTURE != 0,
            capacites_estampille: estampilles.capacites,
            nom,
            nom_estampille: estampilles.nom,
        })
    }
}

/// Les trois estampilles d'une machine qui ne dépendent pas de sa clé.
struct Estampilles {
    /// La dernière écriture.
    estampille: Estampille,
    /// Celle du nom.
    nom: Estampille,
    /// Celle des capacités.
    capacites: Estampille,
}

/// D'où viennent les deux estampilles de la clé d'une machine.
enum LiaisonRangee<'a> {
    /// Lues sur le disque, dans la forme courante.
    Lue {
        /// Les octets de la liaison.
        liaison: &'a [u8],
        /// Les octets de l'émission du code.
        code: &'a [u8],
    },
    /// Attribuées par la reprise, qui n'en a lu aucune.
    Reprise(Estampille),
}

impl LiaisonRangee<'_> {
    /// Sans clé, les deux places doivent être nulles.
    fn est_nulle(&self) -> bool {
        match self {
            Self::Lue { liaison, code } => bourrage_nul(liaison) && bourrage_nul(code),
            Self::Reprise(_) => true,
        }
    }

    /// Avec une clé, les deux estampilles.
    fn lire(&self) -> Result<(Estampille, Estampille), Faute> {
        match self {
            Self::Lue { liaison, code } => {
                Ok((Estampille::lire(liaison)?, Estampille::lire(code)?))
            }
            Self::Reprise(estampille) => Ok((*estampille, *estampille)),
        }
    }
}

// ── L'appareil ──────────────────────────────────────────────────────────────

/// Ce qu'un appareil occupe.
pub const APPAREIL_OCTETS: usize =
    PROVENANCE_OCTETS + ESTAMPILLE_OCTETS + IDENTIFIANT_OCTETS + CLE_APPAREIL_OCTETS + 1 + 1;

/// Un téléphone enrôlé, tel qu'il est rangé.
///
/// # QUATRE CHAMPS, ET C'EST TOUT CE QU'UN APPAREIL EST
///
/// Ni nom, ni adresse : rien de ce qui désignerait le porteur (C13). Un
/// appareil, pour l'annuaire, est **une clé publique rattachée à un compte**,
/// et rien d'autre.
///
/// `docs/modele.md` §2.2 lui donne aussi deux dates. **Elles ne sont pas ici, et
/// c'est un manque nommé** : rien ne les écrit ni ne les lit encore, et un champ
/// qu'on range toujours vide ment sur ce que l'annuaire sait.
///
/// **Le jeton de poussée, lui, est ailleurs** — voir [`JetonPoussee`]. Il n'est
/// pas ici parce qu'il ne tient pas dans une rangée de taille fixe, et parce
/// qu'il se retire seul : un appareil qui refuse les notifications reste un
/// appareil.
///
/// **Le système et le modèle sont ailleurs aussi** — voir [`Description`]. Ce
/// que l'appareil dit de lui-même n'est pas ce qui le prouve, et ne se range
/// pas à côté.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Appareil {
    /// D'où vient cet enregistrement.
    pub provenance: Provenance,
    /// Sa dernière écriture.
    pub estampille: Estampille,
    /// Le compte dont cet appareil est un justificatif.
    pub proprietaire: Identifiant,
    /// Sa clé publique P-256, SEC1 compressée.
    ///
    /// Celle qui vit dans le matériel sécurisé du téléphone. **L'annuaire n'en
    /// connaît que la partie publique**, et il ne saurait rien faire de l'autre.
    /// P-256 et non Ed25519 : voir [`CLE_APPAREIL_OCTETS`].
    pub cle: [u8; CLE_APPAREIL_OCTETS],
    /// Sous quelle attestation il est entré.
    ///
    /// # POURQUOI ON LE GARDE, ALORS QUE LA DÉCISION EST DÉJÀ PRISE
    ///
    /// Au moment de créer le compte, `asl-auth` a décidé si l'attestation
    /// suffisait. Une fois l'appareil rangé, cette décision est du passé — et
    /// c'est justement pourquoi il faut en garder la trace : **la posture d'un
    /// annuaire change** (`--attestation optional` un jour, `required` le
    /// lendemain), et sans ce champ on ne saurait plus, compte par compte,
    /// lesquels sont entrés sans preuve. C'est ce qu'on regarde le jour où l'on
    /// resserre, pour savoir qui prévenir.
    pub atteste: Attestation,
    /// A-t-il été révoqué ?
    ///
    /// # POURQUOI UN DRAPEAU, ET NON UNE LIGNE SUPPRIMÉE
    ///
    /// Supprimer marcherait — une clé qu'on ne trouve plus ne prouve plus rien.
    /// **Mais l'application doit pouvoir MONTRER ce qui a été révoqué** : c'est
    /// l'écran qu'on regarde après avoir perdu un téléphone, et une ligne
    /// disparue n'y dit rien. Un appareil révoqué reste donc, et ne vaut plus.
    ///
    /// C'est le même choix que pour une autorisation, et pour la même raison.
    pub revoque: bool,
}

impl Appareil {
    /// Écrit cet appareil.
    pub fn ecrire(&self, sortie: &mut [u8; APPAREIL_OCTETS]) {
        let mut curseur = 0_usize;
        let mut tranche = |combien: usize| {
            let debut = curseur;
            curseur = curseur.saturating_add(combien);
            debut..curseur
        };
        let provenance = tranche(PROVENANCE_OCTETS);
        self.provenance
            .ecrire(sortie.get_mut(provenance).unwrap_or_default());
        let estampille = tranche(ESTAMPILLE_OCTETS);
        self.estampille
            .ecrire(sortie.get_mut(estampille).unwrap_or_default());
        let proprietaire = tranche(IDENTIFIANT_OCTETS);
        ecrire_identifiant(
            self.proprietaire,
            sortie.get_mut(proprietaire).unwrap_or_default(),
        );
        let cle = tranche(CLE_APPAREIL_OCTETS);
        poser(sortie.get_mut(cle).unwrap_or_default(), &self.cle);
        let atteste = tranche(1);
        poser_un(
            sortie.get_mut(atteste).unwrap_or_default(),
            self.atteste.etiquette(),
        );
        poser_un(
            sortie.get_mut(curseur..).unwrap_or_default(),
            u8::from(self.revoque),
        );
    }

    /// Relit un appareil.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas un appareil.
    pub fn lire(octets: &[u8; APPAREIL_OCTETS]) -> Result<Self, Faute> {
        let provenance = Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?;
        let apres = PROVENANCE_OCTETS.saturating_add(ESTAMPILLE_OCTETS);
        let estampille =
            Estampille::lire(octets.get(PROVENANCE_OCTETS..apres).unwrap_or_default())?;
        Self::lire_corps(
            provenance,
            estampille,
            octets.get(apres..).unwrap_or_default(),
        )
    }

    /// Relit un appareil de la forme d'avant l'estampille, et lui donne
    /// celle-ci (`docs/replication.md` §11.4).
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas un appareil ancien.
    pub fn lire_ancien(
        octets: &[u8; ancien::APPAREIL_OCTETS],
        estampille: Estampille,
    ) -> Result<Self, Faute> {
        let provenance = Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?;
        Self::lire_corps(
            provenance,
            estampille,
            octets.get(PROVENANCE_OCTETS..).unwrap_or_default(),
        )
    }

    /// Ce qui suit l'estampille : le propriétaire, la clé, l'attestation, le
    /// drapeau.
    fn lire_corps(
        provenance: Provenance,
        estampille: Estampille,
        reste: &[u8],
    ) -> Result<Self, Faute> {
        let proprietaire = lire_identifiant(
            reste.get(..IDENTIFIANT_OCTETS).unwrap_or_default(),
            Genre::Utilisateur,
        )?;
        let apres_cle = IDENTIFIANT_OCTETS.saturating_add(CLE_APPAREIL_OCTETS);
        let mut cle = [0_u8; CLE_APPAREIL_OCTETS];
        poser(
            &mut cle,
            reste.get(IDENTIFIANT_OCTETS..apres_cle).unwrap_or_default(),
        );
        let atteste = Attestation::depuis(reste.get(apres_cle).copied().unwrap_or(0))?;
        // **UN BOOLÉEN N'A QUE DEUX ÉCRITURES**, et `2` n'en est pas une : un
        // enregistrement relu se réécrirait alors différemment de lui-même.
        let apres_atteste = apres_cle.saturating_add(1);
        let revoque = match reste.get(apres_atteste).copied().unwrap_or(0) {
            0 => false,
            1 => true,
            lue => return Err(Faute::Etiquette { lue }),
        };
        Ok(Self {
            provenance,
            estampille,
            proprietaire,
            cle,
            atteste,
            revoque,
        })
    }
}

// ── L'attestation sous laquelle un appareil est entré ───────────────────────

/// Ce qui a cautionné un appareil au moment de son enrôlement.
///
/// # TROIS ÉTATS, ET `Aucune` EN EST UN À PART ENTIÈRE
///
/// Ce n'est pas « attesté ou non » : c'est PAR QUOI. Un annuaire en posture
/// `facultative` laisse entrer des appareils sans preuve, et il faut pouvoir
/// dire qu'ils sont entrés ainsi — non pas qu'on a oublié de le noter. `Aucune`
/// est donc une valeur, pas une absence.
///
/// # POURQUOI LES ÉTIQUETTES RANGÉES NE SONT PAS CELLES DU FIL
///
/// Sur le fil (`POST /v1/comptes`), la plate-forme se note `0` aucune, `1`
/// Apple, `2` Android — parce que là, zéro est ce qu'écrit une application qui
/// n'atteste rien, et c'est un choix explicite de sa part.
///
/// **Ici, zéro ne doit désigner personne.** Un octet oublié dans un tampon
/// réemployé vaut zéro, et s'il valait `Aucune` un appareil mal écrit se
/// relirait comme un appareil non attesté — un enregistrement à demi formé qui
/// se croirait entier, exactement ce que le fuzz du registre existe pour
/// fermer. Les étiquettes rangées commencent donc à `1`.
///
/// # `Android` A PRIS L'OCTET DE `Google`, SANS RUPTURE
///
/// L'étiquette `3` disait « Google Play Integrity » ; elle dit « l'attestation
/// de clé d'Android » depuis le 2026-09-16 (`protocole.md` §2.1, C19). Aucun
/// appareil n'a jamais été rangé sous `3` — Play Integrity n'a jamais été
/// accepté —, donc aucun enregistrement existant ne change de sens, et le
/// format ne bouge pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attestation {
    /// Entré sans preuve, sous une posture `facultative`.
    Aucune,
    /// Cautionné par Apple App Attest.
    Apple,
    /// Cautionné par l'attestation de clé d'Android (Keystore), contre une
    /// racine que l'exploitant épingle.
    Android,
}

impl Attestation {
    /// L'étiquette d'« aucune ».
    const AUCUNE: u8 = 1;
    /// L'étiquette d'Apple.
    const APPLE: u8 = 2;
    /// L'étiquette d'Android — celle qui disait Google.
    const ANDROID: u8 = 3;

    /// Son étiquette rangée. **Aucune ne vaut zéro** — voir l'en-tête du type.
    const fn etiquette(self) -> u8 {
        match self {
            Self::Aucune => Self::AUCUNE,
            Self::Apple => Self::APPLE,
            Self::Android => Self::ANDROID,
        }
    }

    /// Relit une étiquette.
    const fn depuis(octet: u8) -> Result<Self, Faute> {
        match octet {
            Self::AUCUNE => Ok(Self::Aucune),
            Self::APPLE => Ok(Self::Apple),
            Self::ANDROID => Ok(Self::Android),
            lue => Err(Faute::Etiquette { lue }),
        }
    }
}

// ── Le jeton de poussée ─────────────────────────────────────────────────────

/// La plate-forme qui délivrera la notification.
///
/// # DEUX, ET L'ANNUAIRE NE SAIT RIEN FAIRE DE PLUS
///
/// Ce n'est pas un champ libre. Un jeton ne veut rien dire hors du service qui
/// l'a émis, et l'annuaire doit savoir à qui le présenter — le ranger sans le
/// savoir en ferait une chaîne opaque que personne ne pourrait employer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plateforme {
    /// Apple Push Notification service.
    Apns,
    /// Firebase Cloud Messaging.
    Fcm,
}

impl Plateforme {
    /// L'étiquette d'APNs.
    const APNS: u8 = 1;
    /// L'étiquette de FCM.
    const FCM: u8 = 2;

    /// Son étiquette rangée.
    ///
    /// **AUCUNE NE VAUT ZÉRO** : un octet oublié dans un tampon réemployé vaut
    /// zéro, et le laisser désigner APNs ferait présenter à Apple des jetons
    /// qu'on n'a jamais reçus.
    const fn etiquette(self) -> u8 {
        match self {
            Self::Apns => Self::APNS,
            Self::Fcm => Self::FCM,
        }
    }

    /// Relit une étiquette.
    const fn depuis(octet: u8) -> Result<Self, Faute> {
        match octet {
            Self::APNS => Ok(Self::Apns),
            Self::FCM => Ok(Self::Fcm),
            lue => Err(Faute::Etiquette { lue }),
        }
    }
}

/// Ce qu'un jeton de poussée occupe.
pub const POUSSEE_OCTETS: usize = PROVENANCE_OCTETS + ESTAMPILLE_OCTETS + 1 + 1 + JETON_OCTETS_MAX;

/// Le jeton par lequel un appareil reçoit ses notifications.
///
/// # IL EST RANGÉ À PART DE L'APPAREIL, ET CE N'EST PAS UN DÉTAIL
///
/// Trois raisons, dont deux tiennent au produit :
///
/// - **Il se retire seul.** Un utilisateur qui coupe les notifications garde son
///   appareil ; un champ dans la rangée d'appareil aurait fait d'un retrait une
///   réécriture de ce qui prouve son identité.
/// - **Il ne vient pas de nous.** Apple et Google le font tourner, l'invalident,
///   le remplacent. Ce qui change au rythme d'un tiers ne se range pas à côté de
///   ce qui ne change jamais.
/// - Il ne tiendrait pas dans une rangée de taille fixe raisonnable : 255 octets
///   pour un champ le plus souvent vide, dans une table qu'on lit à chaque
///   requête authentifiée.
///
/// **Il est rangé sous l'identifiant de l'appareil**, et se révoque avec lui
/// (`docs/modele.md` §2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JetonPoussee {
    /// D'où vient cet enregistrement.
    pub provenance: Provenance,
    /// Sa dernière écriture. Entre deux jetons, le plus récent gagne.
    pub estampille: Estampille,
    /// À qui le présenter.
    pub plateforme: Plateforme,
    /// Le jeton lui-même, tel que la plate-forme l'a donné.
    ///
    /// **L'ANNUAIRE NE LE LIT PAS.** Il ne sait pas ce qu'il porte, et n'a aucune
    /// raison de le savoir : c'est une chaîne opaque qu'il rend à Apple ou à
    /// Google. La seule chose qu'on en exige est qu'elle soit du texte imprimable
    /// — pas pour la comprendre, mais pour qu'une base corrompue se voie.
    pub jeton: JetonRange,
}

impl JetonPoussee {
    /// Écrit ce jeton.
    pub fn ecrire(&self, sortie: &mut [u8; POUSSEE_OCTETS]) {
        self.provenance
            .ecrire(sortie.get_mut(..PROVENANCE_OCTETS).unwrap_or_default());
        let apres_estampille = PROVENANCE_OCTETS.saturating_add(ESTAMPILLE_OCTETS);
        self.estampille.ecrire(
            sortie
                .get_mut(PROVENANCE_OCTETS..apres_estampille)
                .unwrap_or_default(),
        );
        poser_un(
            sortie.get_mut(apres_estampille..).unwrap_or_default(),
            self.plateforme.etiquette(),
        );
        let apres = apres_estampille.saturating_add(1);
        self.jeton
            .ecrire(sortie.get_mut(apres..).unwrap_or_default());
    }

    /// Relit un jeton.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas un jeton.
    pub fn lire(octets: &[u8; POUSSEE_OCTETS]) -> Result<Self, Faute> {
        let provenance = Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?;
        let apres = PROVENANCE_OCTETS.saturating_add(ESTAMPILLE_OCTETS);
        let estampille =
            Estampille::lire(octets.get(PROVENANCE_OCTETS..apres).unwrap_or_default())?;
        Self::lire_corps(
            provenance,
            estampille,
            octets.get(apres..).unwrap_or_default(),
        )
    }

    /// Relit un jeton de la forme d'avant l'estampille, et lui donne celle-ci
    /// (`docs/replication.md` §11.4).
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas un jeton ancien.
    pub fn lire_ancien(
        octets: &[u8; ancien::POUSSEE_OCTETS],
        estampille: Estampille,
    ) -> Result<Self, Faute> {
        let provenance = Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?;
        Self::lire_corps(
            provenance,
            estampille,
            octets.get(PROVENANCE_OCTETS..).unwrap_or_default(),
        )
    }

    /// Ce qui suit l'estampille : la plate-forme, puis le jeton.
    fn lire_corps(
        provenance: Provenance,
        estampille: Estampille,
        reste: &[u8],
    ) -> Result<Self, Faute> {
        let plateforme = Plateforme::depuis(reste.first().copied().unwrap_or(0))?;
        let jeton = JetonRange::lire(reste.get(1..).unwrap_or_default())?;
        // **LE SEUL CONTRÔLE DE CONTENU DE TOUT CE MODULE.** Voir
        // [`Faute::NonImprimable`] : à 255 octets de borne, la longueur ne peut
        // pas se dénoncer elle-même, et il n'y a que le texte pour le faire.
        if let Some(position) = jeton
            .octets()
            .iter()
            .position(|octet| !octet.is_ascii_graphic())
        {
            return Err(Faute::NonImprimable { position });
        }
        Ok(Self {
            provenance,
            estampille,
            plateforme,
            jeton,
        })
    }
}

// ── La description d'un appareil ────────────────────────────────────────────

/// Le système qu'un appareil fait tourner.
///
/// # TROIS, ET LA LISTE EST FERMÉE
///
/// Ce n'est pas un champ libre : l'application qui décrit l'appareil est l'une
/// des trois que ce produit porte, et un système qu'aucune n'annonce serait un
/// enregistrement qu'aucune ne saurait afficher. Un quatrième se déclarera ici,
/// avec son étiquette, le jour où une quatrième application existera.
///
/// **CE N'EST PAS [`Plateforme`].** Celle-là dit à qui présenter un jeton de
/// poussée ; celle-ci dit ce que l'appareil fait tourner. Un Mac n'a pas de
/// jeton et a bien un système.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Systeme {
    /// iOS — un iPhone ou un iPad.
    Ios,
    /// Android.
    Android,
    /// macOS — l'application d'enrôlement du Mac.
    Macos,
}

impl Systeme {
    /// L'étiquette d'iOS.
    const IOS: u8 = 1;
    /// L'étiquette d'Android.
    const ANDROID: u8 = 2;
    /// L'étiquette de macOS.
    const MACOS: u8 = 3;

    /// Son étiquette rangée. **Aucune ne vaut zéro**, pour la raison écrite sur
    /// [`Attestation`] : un tampon réemployé vaut zéro, et ne doit désigner
    /// personne.
    const fn etiquette(self) -> u8 {
        match self {
            Self::Ios => Self::IOS,
            Self::Android => Self::ANDROID,
            Self::Macos => Self::MACOS,
        }
    }

    /// Relit une étiquette.
    const fn depuis(octet: u8) -> Result<Self, Faute> {
        match octet {
            Self::IOS => Ok(Self::Ios),
            Self::ANDROID => Ok(Self::Android),
            Self::MACOS => Ok(Self::Macos),
            lue => Err(Faute::Etiquette { lue }),
        }
    }
}

/// Ce qu'une description d'appareil occupe.
pub const DESCRIPTION_OCTETS: usize =
    PROVENANCE_OCTETS + ESTAMPILLE_OCTETS + 1 + 1 + NOM_OCTETS_MAX;

/// Ce qu'un appareil dit de lui-même : son système, et son modèle.
///
/// # UNE ÉTIQUETTE, PAS UNE PREUVE
///
/// C'est l'appareil qui la pose, sur sa propre connexion, et l'annuaire ne
/// vérifie rien de ce qu'elle dit : un appareil pirate peut se dire « iPhone
/// 17 ». Ce qui identifie un appareil est son identifiant `a-…`, et c'est lui
/// que les applications affichent à côté. La description sert à ce que l'écran
/// Compte montre « MacBook Pro » et non « Autre » — de quoi reconnaître les
/// siens, jamais de quoi les prouver.
///
/// # LE MODÈLE, ET JAMAIS LE NOM DONNÉ PAR L'UTILISATEUR
///
/// Un téléphone porte deux textes : le nom que son porteur lui a donné —
/// « iPhone de Thierry », un prénom, précisément ce que C13 refuse — et le nom
/// de son modèle, qui ne nomme personne. **Seul le second entre ici**, et
/// l'application qui pose la description en répond. Ce module range du texte
/// libre aux mêmes règles qu'un nom de machine ([`Machine::nom`]) ; le refus de
/// ce qui ne s'affiche pas se prend dans `asl-api`, à l'entrée.
///
/// # RANGÉE À PART DE L'APPAREIL, COMME LE JETON
///
/// Elle est posée APRÈS l'enrôlement, par un second verbe, et un appareil qui
/// ne l'a pas posée reste un appareil entier. Un champ dans la rangée
/// d'appareil aurait fait d'une étiquette d'affichage une réécriture de ce qui
/// prouve son identité — et aurait changé la forme d'une table que des bases
/// réelles portent déjà.
///
/// **Elle reste quand l'appareil est révoqué**, à l'inverse du jeton : l'écran
/// d'après une perte doit montrer CE QU'ON a retiré, et « iPhone 17, révoqué »
/// le dit mieux que « Autre, révoqué ».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Description {
    /// D'où vient cet enregistrement.
    pub provenance: Provenance,
    /// Sa dernière écriture. Entre deux descriptions, la plus récente gagne.
    pub estampille: Estampille,
    /// Ce que l'appareil fait tourner.
    pub systeme: Systeme,
    /// Le modèle, tel que l'appareil se nomme — « MacBook Pro (2019) ».
    pub modele: NomRange,
}

impl Description {
    /// Écrit cette description.
    pub fn ecrire(&self, sortie: &mut [u8; DESCRIPTION_OCTETS]) {
        self.provenance
            .ecrire(sortie.get_mut(..PROVENANCE_OCTETS).unwrap_or_default());
        let apres_estampille = PROVENANCE_OCTETS.saturating_add(ESTAMPILLE_OCTETS);
        self.estampille.ecrire(
            sortie
                .get_mut(PROVENANCE_OCTETS..apres_estampille)
                .unwrap_or_default(),
        );
        poser_un(
            sortie.get_mut(apres_estampille..).unwrap_or_default(),
            self.systeme.etiquette(),
        );
        let apres = apres_estampille.saturating_add(1);
        self.modele
            .ecrire(sortie.get_mut(apres..).unwrap_or_default());
    }

    /// Relit une description.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas une description.
    pub fn lire(octets: &[u8; DESCRIPTION_OCTETS]) -> Result<Self, Faute> {
        let provenance = Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?;
        let apres = PROVENANCE_OCTETS.saturating_add(ESTAMPILLE_OCTETS);
        let estampille =
            Estampille::lire(octets.get(PROVENANCE_OCTETS..apres).unwrap_or_default())?;
        Self::lire_corps(
            provenance,
            estampille,
            octets.get(apres..).unwrap_or_default(),
        )
    }

    /// Relit une description de la forme d'avant l'estampille, et lui donne
    /// celle-ci (`docs/replication.md` §11.4).
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas une description ancienne.
    pub fn lire_ancien(
        octets: &[u8; ancien::DESCRIPTION_OCTETS],
        estampille: Estampille,
    ) -> Result<Self, Faute> {
        let provenance = Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?;
        Self::lire_corps(
            provenance,
            estampille,
            octets.get(PROVENANCE_OCTETS..).unwrap_or_default(),
        )
    }

    /// Ce qui suit l'estampille : le système, puis le modèle.
    fn lire_corps(
        provenance: Provenance,
        estampille: Estampille,
        reste: &[u8],
    ) -> Result<Self, Faute> {
        let systeme = Systeme::depuis(reste.first().copied().unwrap_or(0))?;
        let modele = NomRange::lire(reste.get(1..).unwrap_or_default())?;
        Ok(Self {
            provenance,
            estampille,
            systeme,
            modele,
        })
    }
}

// ── Le code d'enrôlement en attente ─────────────────────────────────────────

/// Ce qu'un enrôlement en attente occupe.
pub const ENROLEMENT_OCTETS: usize = PROVENANCE_OCTETS + ESTAMPILLE_OCTETS + IDENTIFIANT_OCTETS + 8;

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
    /// L'émission du code.
    ///
    /// C'est elle que la clé liée emportera ([`CleLiee::code`]) : entre deux
    /// clés liées par deux codes, celle du code le plus récemment émis gagne.
    pub estampille: Estampille,
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
        let apres_estampille = PROVENANCE_OCTETS.saturating_add(ESTAMPILLE_OCTETS);
        self.estampille.ecrire(
            sortie
                .get_mut(PROVENANCE_OCTETS..apres_estampille)
                .unwrap_or_default(),
        );
        let apres_machine = apres_estampille.saturating_add(IDENTIFIANT_OCTETS);
        ecrire_identifiant(
            self.machine,
            sortie
                .get_mut(apres_estampille..apres_machine)
                .unwrap_or_default(),
        );
        poser(
            sortie.get_mut(apres_machine..).unwrap_or_default(),
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
        let apres = PROVENANCE_OCTETS.saturating_add(ESTAMPILLE_OCTETS);
        let estampille =
            Estampille::lire(octets.get(PROVENANCE_OCTETS..apres).unwrap_or_default())?;
        Self::lire_corps(
            provenance,
            estampille,
            octets.get(apres..).unwrap_or_default(),
        )
    }

    /// Relit un enrôlement de la forme d'avant l'estampille, et lui donne
    /// celle-ci (`docs/replication.md` §11.4).
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas un enrôlement ancien.
    pub fn lire_ancien(
        octets: &[u8; ancien::ENROLEMENT_OCTETS],
        estampille: Estampille,
    ) -> Result<Self, Faute> {
        let provenance = Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?;
        Self::lire_corps(
            provenance,
            estampille,
            octets.get(PROVENANCE_OCTETS..).unwrap_or_default(),
        )
    }

    /// Ce qui suit l'estampille : la machine, puis l'expiration.
    fn lire_corps(
        provenance: Provenance,
        estampille: Estampille,
        reste: &[u8],
    ) -> Result<Self, Faute> {
        let machine = lire_identifiant(
            reste.get(..IDENTIFIANT_OCTETS).unwrap_or_default(),
            Genre::Machine,
        )?;
        let mut quand = [0_u8; 8];
        poser(
            &mut quand,
            reste.get(IDENTIFIANT_OCTETS..).unwrap_or_default(),
        );
        Ok(Self {
            provenance,
            estampille,
            machine,
            expire_a: u64::from_be_bytes(quand),
        })
    }
}

// ── Le service ──────────────────────────────────────────────────────────────

/// Ce qu'un service occupe.
pub const SERVICE_OCTETS: usize =
    PROVENANCE_OCTETS + ESTAMPILLE_OCTETS + IDENTIFIANT_OCTETS + 1 + NOM_OCTETS_MAX;

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
    /// Sa déclaration. Entre deux services du même `(machine, nom)`, le plus
    /// ancien reste (`docs/replication.md` §3.2).
    pub estampille: Estampille,
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
        let apres_estampille = PROVENANCE_OCTETS.saturating_add(ESTAMPILLE_OCTETS);
        self.estampille.ecrire(
            sortie
                .get_mut(PROVENANCE_OCTETS..apres_estampille)
                .unwrap_or_default(),
        );
        let apres_machine = apres_estampille.saturating_add(IDENTIFIANT_OCTETS);
        ecrire_identifiant(
            self.machine,
            sortie
                .get_mut(apres_estampille..apres_machine)
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
        let apres = PROVENANCE_OCTETS.saturating_add(ESTAMPILLE_OCTETS);
        let estampille =
            Estampille::lire(octets.get(PROVENANCE_OCTETS..apres).unwrap_or_default())?;
        Self::lire_corps(
            provenance,
            estampille,
            octets.get(apres..).unwrap_or_default(),
        )
    }

    /// Relit un service de la forme d'avant l'estampille, et lui donne
    /// celle-ci (`docs/replication.md` §11.4).
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas un service ancien.
    pub fn lire_ancien(
        octets: &[u8; ancien::SERVICE_OCTETS],
        estampille: Estampille,
    ) -> Result<Self, Faute> {
        let provenance = Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?;
        Self::lire_corps(
            provenance,
            estampille,
            octets.get(PROVENANCE_OCTETS..).unwrap_or_default(),
        )
    }

    /// Ce qui suit l'estampille : la machine, puis le nom.
    fn lire_corps(
        provenance: Provenance,
        estampille: Estampille,
        reste: &[u8],
    ) -> Result<Self, Faute> {
        let machine = lire_identifiant(
            reste.get(..IDENTIFIANT_OCTETS).unwrap_or_default(),
            Genre::Machine,
        )?;
        let nom = NomRange::lire(reste.get(IDENTIFIANT_OCTETS..).unwrap_or_default())?;
        Ok(Self {
            provenance,
            estampille,
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
///
/// Le dernier `1 + NOM_OCTETS_MAX` est l'étiquette, un [`Court`] comme le nom
/// d'une machine : un octet de longueur, puis ses octets.
pub const AUTORISATION_OCTETS: usize = PROVENANCE_OCTETS
    + ESTAMPILLE_OCTETS
    + IDENTIFIANT_OCTETS
    + IDENTIFIANT_OCTETS
    + PORTEE_OCTETS
    + 1
    + 1
    + NOM_OCTETS_MAX;

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
    /// Sa dernière écriture.
    pub estampille: Estampille,
    /// Le compte qui accorde.
    pub par: Identifiant,
    /// Le compte qui reçoit.
    pub a: Identifiant,
    /// Jusqu'où elle porte.
    pub portee: Portee,
    /// A-t-elle été retirée ?
    pub revoquee: bool,
    /// Le libellé que son auteur lui a donné.
    ///
    /// **Pour l'humain, jamais pour la machine** (`docs/modele.md` §2.5) : rien
    /// ne se cherche par lui. C'est ce qu'on lit « six mois plus tard » pour
    /// savoir ce qu'on révoque. Du texte libre, aux mêmes règles qu'un nom de
    /// machine — la grammaire d'entrée (`asl_api`) a déjà refusé ce qui ne s'y
    /// range pas.
    pub etiquette: NomRange,
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
        let estampille = tranche(ESTAMPILLE_OCTETS);
        self.estampille
            .ecrire(sortie.get_mut(estampille).unwrap_or_default());
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
        let etiquette = tranche(1 + NOM_OCTETS_MAX);
        self.etiquette
            .ecrire(sortie.get_mut(etiquette).unwrap_or_default());
    }

    /// Relit une autorisation.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas une autorisation.
    pub fn lire(octets: &[u8; AUTORISATION_OCTETS]) -> Result<Self, Faute> {
        let provenance = Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?;
        let apres = PROVENANCE_OCTETS.saturating_add(ESTAMPILLE_OCTETS);
        let estampille =
            Estampille::lire(octets.get(PROVENANCE_OCTETS..apres).unwrap_or_default())?;
        Self::lire_corps(
            provenance,
            estampille,
            octets.get(apres..).unwrap_or_default(),
        )
    }

    /// Relit une autorisation de la forme d'avant l'estampille, et lui donne
    /// celle-ci (`docs/replication.md` §11.4).
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas une autorisation ancienne.
    pub fn lire_ancien(
        octets: &[u8; ancien::AUTORISATION_OCTETS],
        estampille: Estampille,
    ) -> Result<Self, Faute> {
        let provenance = Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?;
        Self::lire_corps(
            provenance,
            estampille,
            octets.get(PROVENANCE_OCTETS..).unwrap_or_default(),
        )
    }

    /// Ce qui suit l'estampille : les deux comptes, la portée, le drapeau,
    /// l'étiquette.
    fn lire_corps(
        provenance: Provenance,
        estampille: Estampille,
        reste: &[u8],
    ) -> Result<Self, Faute> {
        let mut curseur = 0_usize;
        let mut prendre = |combien: usize| {
            let debut = curseur;
            curseur = curseur.saturating_add(combien);
            debut..curseur
        };
        let par = lire_identifiant(
            reste.get(prendre(IDENTIFIANT_OCTETS)).unwrap_or_default(),
            Genre::Utilisateur,
        )?;
        let a = lire_identifiant(
            reste.get(prendre(IDENTIFIANT_OCTETS)).unwrap_or_default(),
            Genre::Utilisateur,
        )?;
        let portee = Portee::lire(reste.get(prendre(PORTEE_OCTETS)).unwrap_or_default())?;
        // **NI 0 NI 1 EST UNE CORRUPTION**, et non « vrai par défaut ». Un
        // booléen relu de travers sur une décision d'autorisation est
        // exactement ce qu'on ne veut pas deviner.
        let revoquee = match reste
            .get(prendre(1))
            .and_then(<[u8]>::first)
            .copied()
            .unwrap_or(0)
        {
            0 => false,
            1 => true,
            lue => return Err(Faute::Etiquette { lue }),
        };
        let etiquette = NomRange::lire(reste.get(prendre(1 + NOM_OCTETS_MAX)).unwrap_or_default())?;
        Ok(Self {
            provenance,
            estampille,
            par,
            a,
            portee,
            revoquee,
            etiquette,
        })
    }
}

// ── La forme d'avant l'estampille ───────────────────────────────────────────

pub mod ancien {
    //! Ce que les enregistrements occupaient AVANT l'estampille (≤ 0.4.3).
    //!
    //! # POURQUOI CES TAILLES SURVIVENT
    //!
    //! `docs/replication.md` §11.4 : les bancs tournent avec des bases sans
    //! estampille ni journal, et elles portent de vrais comptes. Une base
    //! ancienne est REPRISE à l'ouverture — chaque enregistrement reçoit une
    //! estampille —, et pour la relire il faut savoir ce qu'il occupait.
    //! `redb` range le type d'une table avec elle, taille comprise : la table
    //! d'hier ne s'ouvre qu'avec la taille d'hier.
    //!
    //! Chaque enregistrement a son `lire_ancien`, qui prend ces octets-là et
    //! l'estampille que la reprise lui attribue. **Il n'y a pas d'`ecrire`
    //! ancien** : rien n'écrit plus dans cette forme, et un écrivain qu'on
    //! garderait « pour les essais » serait un second format vivant.

    use super::{
        ALIAS_OCTETS_MAX, CLE_APPAREIL_OCTETS, CLE_OCTETS, IDENTIFIANT_OCTETS, JETON_OCTETS_MAX,
        NOM_OCTETS_MAX, PORTEE_OCTETS, PROVENANCE_OCTETS,
    };

    /// Ce qu'un compte occupait.
    pub const COMPTE_OCTETS: usize = PROVENANCE_OCTETS + 1 + 1 + ALIAS_OCTETS_MAX;
    /// Ce qu'une machine occupait.
    pub const MACHINE_OCTETS: usize =
        PROVENANCE_OCTETS + IDENTIFIANT_OCTETS + CLE_OCTETS + 1 + 1 + NOM_OCTETS_MAX;
    /// Ce qu'un appareil occupait.
    pub const APPAREIL_OCTETS: usize =
        PROVENANCE_OCTETS + IDENTIFIANT_OCTETS + CLE_APPAREIL_OCTETS + 1 + 1;
    /// Ce qu'un jeton de poussée occupait.
    pub const POUSSEE_OCTETS: usize = PROVENANCE_OCTETS + 1 + 1 + JETON_OCTETS_MAX;
    /// Ce qu'une description occupait.
    pub const DESCRIPTION_OCTETS: usize = PROVENANCE_OCTETS + 1 + 1 + NOM_OCTETS_MAX;
    /// Ce qu'un enrôlement occupait.
    pub const ENROLEMENT_OCTETS: usize = PROVENANCE_OCTETS + IDENTIFIANT_OCTETS + 8;
    /// Ce qu'un service occupait.
    pub const SERVICE_OCTETS: usize = PROVENANCE_OCTETS + IDENTIFIANT_OCTETS + 1 + NOM_OCTETS_MAX;
    /// Ce qu'une autorisation occupait.
    pub const AUTORISATION_OCTETS: usize = PROVENANCE_OCTETS
        + IDENTIFIANT_OCTETS
        + IDENTIFIANT_OCTETS
        + PORTEE_OCTETS
        + 1
        + 1
        + NOM_OCTETS_MAX;
}

// ── Les opérations (`docs/replication.md` §5) ───────────────────────────────

/// Ce que l'en-tête d'une opération occupe : le genre, puis l'estampille.
pub const OPERATION_ENTETE_OCTETS: usize = 1 + ESTAMPILLE_OCTETS;

/// Ce que la plus grande charge occupe — celle d'un jeton de poussée.
const CHARGE_OCTETS_MAX: usize = IDENTIFIANT_OCTETS + POUSSEE_OCTETS;

/// Ce qu'une opération occupe, au plus. C'est la taille du tampon dans lequel
/// [`Operation::ecrire`] écrit ; ce qu'elle a réellement occupé est rendu.
pub const OPERATION_OCTETS_MAX: usize = OPERATION_ENTETE_OCTETS + CHARGE_OCTETS_MAX;

/// Ce qu'une racine a écrit, tel que l'autre le tire.
///
/// # UN CADRE À CHAMPS FIXES, ET LA CHARGE EST L'ENREGISTREMENT
///
/// ```text
/// genre (1) ‖ compteur (8) ‖ racine (17) ‖ charge (taille fixée par le genre)
/// ```
///
/// **La charge est l'enregistrement dans le format de l'entrepôt** — ce codec,
/// couvert à 100 % et fuzzé, qui sert déjà à le ranger. Le genre fixe la taille
/// de la charge, donc **aucune longueur ne vient du réseau**, et il n'y a pas de
/// second décodeur : ce qui se lit sur le fil est ce qui se lit sur le disque.
///
/// # LES QUATORZE GENRES SONT CEUX DE `replication.md` §5.2
///
/// Un par écriture locale possible, et aucun pour ce qui ne se réplique pas —
/// l'expiration d'un code, le retrait d'un jeton par son appareil n'ont pas
/// d'opération. Il n'y a pas non plus d'effacement d'un compte, d'une machine ou
/// d'un service : l'API n'en a pas.
///
/// **L'estampille n'est pas dans la variante** : elle est celle de l'opération,
/// et [`Operation::ecrire`] la prend à part. Une opération est un fait daté par
/// la racine qui l'écrit, et le même fait peut être rejoué par un instantané
/// avec l'estampille d'origine — c'est pourquoi les deux se séparent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// Un compte créé. Insérer si absent.
    Compte {
        /// Son identifiant.
        compte: Identifiant,
        /// L'enregistrement.
        enregistrement: Compte,
    },
    /// La réclamation courante d'un compte : un alias, ou rien.
    Alias {
        /// Le compte qui réclame.
        compte: Identifiant,
        /// Ce qu'il réclame — rien, s'il lâche.
        alias: Option<AliasRange>,
    },
    /// Un appareil enrôlé. Insérer si absent.
    Appareil {
        /// Son identifiant.
        appareil: Identifiant,
        /// L'enregistrement.
        enregistrement: Appareil,
    },
    /// Un appareil révoqué. Marquer, retirer le jeton. Toujours.
    AppareilRevoque {
        /// Lequel.
        appareil: Identifiant,
    },
    /// Ce qu'un appareil dit de lui-même. Le plus récent.
    Description {
        /// L'appareil.
        appareil: Identifiant,
        /// L'enregistrement.
        enregistrement: Description,
    },
    /// Un jeton de poussée. Le plus récent ; refusé si l'appareil est révoqué.
    Poussee {
        /// L'appareil.
        appareil: Identifiant,
        /// L'enregistrement.
        enregistrement: JetonPoussee,
    },
    /// Une machine déclarée, sans clé. Insérer si absent.
    Machine {
        /// Son identifiant.
        machine: Identifiant,
        /// L'enregistrement.
        enregistrement: Machine,
    },
    /// Un `PATCH` de machine. Le plus récent, champ par champ.
    MachineModifiee {
        /// Laquelle.
        machine: Identifiant,
        /// Le nom, s'il change.
        nom: Option<NomRange>,
        /// Les capacités, si elles changent.
        capacites: Option<Capacites>,
    },
    /// Un code d'enrôlement émis. Le code courant de la machine : le plus
    /// récent ; le précédent s'efface.
    Enrolement {
        /// L'empreinte du code.
        empreinte: [u8; EMPREINTE_OCTETS],
        /// L'enregistrement.
        enregistrement: Enrolement,
    },
    /// Une clé liée par un code. Supprimer le code s'il est là ; lier la clé
    /// selon §3.2 — code le plus récent, puis première consommation.
    CleMachine {
        /// La machine.
        machine: Identifiant,
        /// La clé liée.
        cle: [u8; CLE_OCTETS],
        /// L'empreinte du code consommé.
        empreinte: [u8; EMPREINTE_OCTETS],
        /// L'émission de ce code.
        code: Estampille,
    },
    /// Une clé révoquée. Retirer la clé si c'est bien celle-là ; fermer les
    /// connexions.
    CleMachineRevoquee {
        /// La machine.
        machine: Identifiant,
        /// La clé révoquée.
        cle: [u8; CLE_OCTETS],
    },
    /// Un service déclaré. Insérer ; si `(machine, nom)` est déjà tenu, le
    /// plus ancien reste.
    Service {
        /// Son identifiant.
        service: Identifiant,
        /// L'enregistrement.
        enregistrement: Service,
    },
    /// Une autorisation accordée. Insérer si absent.
    Autorisation {
        /// Son identifiant.
        autorisation: Identifiant,
        /// L'enregistrement.
        enregistrement: Autorisation,
    },
    /// Une autorisation révoquée. Marquer. Toujours.
    AutorisationRevoquee {
        /// Laquelle.
        autorisation: Identifiant,
    },
}

/// Le genre d'une opération, tel qu'il s'écrit en tête du cadre.
///
/// **Aucun ne vaut zéro**, pour la raison écrite sur [`Attestation`] : un
/// tampon réemployé vaut zéro, et ne doit désigner aucune opération.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenreOperation {
    /// `compte`.
    Compte,
    /// `alias`.
    Alias,
    /// `appareil`.
    Appareil,
    /// `appareil-revoque`.
    AppareilRevoque,
    /// `description`.
    Description,
    /// `poussee`.
    Poussee,
    /// `machine`.
    Machine,
    /// `machine-modifiee`.
    MachineModifiee,
    /// `enrolement`.
    Enrolement,
    /// `cle-machine`.
    CleMachine,
    /// `cle-machine-revoquee`.
    CleMachineRevoquee,
    /// `service`.
    Service,
    /// `autorisation`.
    Autorisation,
    /// `autorisation-revoquee`.
    AutorisationRevoquee,
}

impl GenreOperation {
    /// Les quatorze, dans l'ordre de `replication.md` §5.2 — et l'ordre de
    /// leurs étiquettes, de 1 à 14.
    pub const TOUS: [Self; 14] = [
        Self::Compte,
        Self::Alias,
        Self::Appareil,
        Self::AppareilRevoque,
        Self::Description,
        Self::Poussee,
        Self::Machine,
        Self::MachineModifiee,
        Self::Enrolement,
        Self::CleMachine,
        Self::CleMachineRevoquee,
        Self::Service,
        Self::Autorisation,
        Self::AutorisationRevoquee,
    ];

    /// Son étiquette, en tête du cadre.
    #[must_use]
    pub const fn etiquette(self) -> u8 {
        match self {
            Self::Compte => 1,
            Self::Alias => 2,
            Self::Appareil => 3,
            Self::AppareilRevoque => 4,
            Self::Description => 5,
            Self::Poussee => 6,
            Self::Machine => 7,
            Self::MachineModifiee => 8,
            Self::Enrolement => 9,
            Self::CleMachine => 10,
            Self::CleMachineRevoquee => 11,
            Self::Service => 12,
            Self::Autorisation => 13,
            Self::AutorisationRevoquee => 14,
        }
    }

    /// Relit une étiquette.
    ///
    /// # Errors
    ///
    /// [`Faute::Etiquette`] si l'octet ne désigne aucun genre — zéro compris.
    pub const fn depuis(octet: u8) -> Result<Self, Faute> {
        Ok(match octet {
            1 => Self::Compte,
            2 => Self::Alias,
            3 => Self::Appareil,
            4 => Self::AppareilRevoque,
            5 => Self::Description,
            6 => Self::Poussee,
            7 => Self::Machine,
            8 => Self::MachineModifiee,
            9 => Self::Enrolement,
            10 => Self::CleMachine,
            11 => Self::CleMachineRevoquee,
            12 => Self::Service,
            13 => Self::Autorisation,
            14 => Self::AutorisationRevoquee,
            lue => return Err(Faute::Etiquette { lue }),
        })
    }

    /// Ce que la charge de ce genre occupe.
    ///
    /// **C'est ici que la taille est fixée, et nulle part sur le fil.**
    #[must_use]
    pub const fn charge_octets(self) -> usize {
        match self {
            Self::Compte => IDENTIFIANT_OCTETS + COMPTE_OCTETS,
            Self::Alias => IDENTIFIANT_OCTETS + 1 + 1 + ALIAS_OCTETS_MAX,
            Self::Appareil => IDENTIFIANT_OCTETS + APPAREIL_OCTETS,
            Self::AppareilRevoque | Self::AutorisationRevoquee => IDENTIFIANT_OCTETS,
            Self::Description => IDENTIFIANT_OCTETS + DESCRIPTION_OCTETS,
            Self::Poussee => IDENTIFIANT_OCTETS + POUSSEE_OCTETS,
            Self::Machine => IDENTIFIANT_OCTETS + MACHINE_OCTETS,
            Self::MachineModifiee => IDENTIFIANT_OCTETS + 1 + 1 + NOM_OCTETS_MAX + 1,
            Self::Enrolement => EMPREINTE_OCTETS + ENROLEMENT_OCTETS,
            Self::CleMachine => {
                IDENTIFIANT_OCTETS + CLE_OCTETS + EMPREINTE_OCTETS + ESTAMPILLE_OCTETS
            }
            Self::CleMachineRevoquee => IDENTIFIANT_OCTETS + CLE_OCTETS,
            Self::Service => IDENTIFIANT_OCTETS + SERVICE_OCTETS,
            Self::Autorisation => IDENTIFIANT_OCTETS + AUTORISATION_OCTETS,
        }
    }

    /// Ce que l'opération entière occupe : l'en-tête, puis la charge.
    #[must_use]
    pub const fn octets(self) -> usize {
        OPERATION_ENTETE_OCTETS.saturating_add(self.charge_octets())
    }
}

impl Operation {
    /// Le bit qui dit qu'un `PATCH` porte le nom.
    const PRESENT_NOM: u8 = 0b0000_0001;
    /// Le bit qui dit qu'un `PATCH` porte les capacités.
    const PRESENT_CAPACITES: u8 = 0b0000_0010;

    /// Son genre.
    #[must_use]
    pub const fn genre(&self) -> GenreOperation {
        match self {
            Self::Compte { .. } => GenreOperation::Compte,
            Self::Alias { .. } => GenreOperation::Alias,
            Self::Appareil { .. } => GenreOperation::Appareil,
            Self::AppareilRevoque { .. } => GenreOperation::AppareilRevoque,
            Self::Description { .. } => GenreOperation::Description,
            Self::Poussee { .. } => GenreOperation::Poussee,
            Self::Machine { .. } => GenreOperation::Machine,
            Self::MachineModifiee { .. } => GenreOperation::MachineModifiee,
            Self::Enrolement { .. } => GenreOperation::Enrolement,
            Self::CleMachine { .. } => GenreOperation::CleMachine,
            Self::CleMachineRevoquee { .. } => GenreOperation::CleMachineRevoquee,
            Self::Service { .. } => GenreOperation::Service,
            Self::Autorisation { .. } => GenreOperation::Autorisation,
            Self::AutorisationRevoquee { .. } => GenreOperation::AutorisationRevoquee,
        }
    }

    /// Écrit cette opération sous cette estampille, et rend ce qu'elle occupe.
    ///
    /// **Le tampon fait toujours [`OPERATION_OCTETS_MAX`]**, et seuls les
    /// premiers octets rendus comptent : c'est ce qui permet d'écrire sans
    /// allouer, dans une crate qui n'alloue rien.
    pub fn ecrire(&self, estampille: Estampille, sortie: &mut [u8; OPERATION_OCTETS_MAX]) -> usize {
        let genre = self.genre();
        // Le tampon est réemployé : ce que la charge ne couvre pas doit être
        // nul, pour que le cadre soit canonique et qu'aucun octet de
        // l'opération précédente ne survive dans le bourrage.
        sortie.fill(0);
        poser_un(sortie, genre.etiquette());
        estampille.ecrire(sortie.get_mut(1..).unwrap_or_default());
        let charge = sortie
            .get_mut(OPERATION_ENTETE_OCTETS..)
            .unwrap_or_default();
        match self {
            Self::Compte {
                compte,
                enregistrement,
            } => {
                ecrire_identifiant(*compte, charge);
                let mut octets = [0_u8; COMPTE_OCTETS];
                enregistrement.ecrire(&mut octets);
                poser(
                    charge.get_mut(IDENTIFIANT_OCTETS..).unwrap_or_default(),
                    &octets,
                );
            }
            Self::Alias { compte, alias } => {
                ecrire_identifiant(*compte, charge);
                let reste = charge.get_mut(IDENTIFIANT_OCTETS..).unwrap_or_default();
                if let Some(alias) = alias {
                    poser_un(reste, 1);
                    alias.ecrire(reste.get_mut(1..).unwrap_or_default());
                }
            }
            Self::Appareil {
                appareil,
                enregistrement,
            } => {
                ecrire_identifiant(*appareil, charge);
                let mut octets = [0_u8; APPAREIL_OCTETS];
                enregistrement.ecrire(&mut octets);
                poser(
                    charge.get_mut(IDENTIFIANT_OCTETS..).unwrap_or_default(),
                    &octets,
                );
            }
            Self::AppareilRevoque { appareil } => ecrire_identifiant(*appareil, charge),
            Self::Description {
                appareil,
                enregistrement,
            } => {
                ecrire_identifiant(*appareil, charge);
                let mut octets = [0_u8; DESCRIPTION_OCTETS];
                enregistrement.ecrire(&mut octets);
                poser(
                    charge.get_mut(IDENTIFIANT_OCTETS..).unwrap_or_default(),
                    &octets,
                );
            }
            Self::Poussee {
                appareil,
                enregistrement,
            } => {
                ecrire_identifiant(*appareil, charge);
                let mut octets = [0_u8; POUSSEE_OCTETS];
                enregistrement.ecrire(&mut octets);
                poser(
                    charge.get_mut(IDENTIFIANT_OCTETS..).unwrap_or_default(),
                    &octets,
                );
            }
            Self::Machine {
                machine,
                enregistrement,
            } => {
                ecrire_identifiant(*machine, charge);
                let mut octets = [0_u8; MACHINE_OCTETS];
                enregistrement.ecrire(&mut octets);
                poser(
                    charge.get_mut(IDENTIFIANT_OCTETS..).unwrap_or_default(),
                    &octets,
                );
            }
            Self::MachineModifiee {
                machine,
                nom,
                capacites,
            } => {
                ecrire_identifiant(*machine, charge);
                let reste = charge.get_mut(IDENTIFIANT_OCTETS..).unwrap_or_default();
                let mut presents = 0_u8;
                if let Some(nom) = nom {
                    presents |= Self::PRESENT_NOM;
                    nom.ecrire(reste.get_mut(1..).unwrap_or_default());
                }
                if let Some(capacites) = capacites {
                    presents |= Self::PRESENT_CAPACITES;
                    poser_un(
                        reste.get_mut(1 + 1 + NOM_OCTETS_MAX..).unwrap_or_default(),
                        capacites.octet(),
                    );
                }
                poser_un(reste, presents);
            }
            Self::Enrolement {
                empreinte,
                enregistrement,
            } => {
                poser(charge, empreinte);
                let mut octets = [0_u8; ENROLEMENT_OCTETS];
                enregistrement.ecrire(&mut octets);
                poser(
                    charge.get_mut(EMPREINTE_OCTETS..).unwrap_or_default(),
                    &octets,
                );
            }
            Self::CleMachine {
                machine,
                cle,
                empreinte,
                code,
            } => {
                ecrire_identifiant(*machine, charge);
                let apres_cle = IDENTIFIANT_OCTETS.saturating_add(CLE_OCTETS);
                poser(
                    charge.get_mut(IDENTIFIANT_OCTETS..).unwrap_or_default(),
                    cle,
                );
                poser(charge.get_mut(apres_cle..).unwrap_or_default(), empreinte);
                code.ecrire(
                    charge
                        .get_mut(apres_cle.saturating_add(EMPREINTE_OCTETS)..)
                        .unwrap_or_default(),
                );
            }
            Self::CleMachineRevoquee { machine, cle } => {
                ecrire_identifiant(*machine, charge);
                poser(
                    charge.get_mut(IDENTIFIANT_OCTETS..).unwrap_or_default(),
                    cle,
                );
            }
            Self::Service {
                service,
                enregistrement,
            } => {
                ecrire_identifiant(*service, charge);
                let mut octets = [0_u8; SERVICE_OCTETS];
                enregistrement.ecrire(&mut octets);
                poser(
                    charge.get_mut(IDENTIFIANT_OCTETS..).unwrap_or_default(),
                    &octets,
                );
            }
            Self::Autorisation {
                autorisation,
                enregistrement,
            } => {
                ecrire_identifiant(*autorisation, charge);
                let mut octets = [0_u8; AUTORISATION_OCTETS];
                enregistrement.ecrire(&mut octets);
                poser(
                    charge.get_mut(IDENTIFIANT_OCTETS..).unwrap_or_default(),
                    &octets,
                );
            }
            Self::AutorisationRevoquee { autorisation } => {
                ecrire_identifiant(*autorisation, charge);
            }
        }
        genre.octets()
    }

    /// Relit une opération en tête de ces octets, et rend son estampille,
    /// elle-même, et ce qu'elle a occupé.
    ///
    /// **Ce qui suit n'est pas regardé** : sur le fil, c'est l'opération
    /// suivante ; sur le disque, il n'y a rien. C'est le genre qui dit où
    /// celle-ci s'arrête, et c'est l'appelant qui avance.
    ///
    /// # Errors
    ///
    /// [`Faute::Etiquette`] sur un genre inconnu, [`Faute::Tronquee`] si les
    /// octets s'arrêtent avant la fin de la charge, et les fautes de
    /// l'enregistrement porté.
    pub fn lire(octets: &[u8]) -> Result<(Estampille, Self, usize), Faute> {
        let genre = GenreOperation::depuis(octets.first().copied().unwrap_or(0))?;
        let attendus = genre.octets();
        if octets.len() < attendus {
            return Err(Faute::Tronquee {
                attendus,
                obtenus: octets.len(),
            });
        }
        let estampille =
            Estampille::lire(octets.get(1..OPERATION_ENTETE_OCTETS).unwrap_or_default())?;
        let charge = octets
            .get(OPERATION_ENTETE_OCTETS..attendus)
            .unwrap_or_default();
        let apres_identifiant = charge.get(IDENTIFIANT_OCTETS..).unwrap_or_default();
        let operation = match genre {
            GenreOperation::Compte => Self::Compte {
                compte: lire_identifiant(charge, Genre::Utilisateur)?,
                enregistrement: Compte::lire(&copie(apres_identifiant))?,
            },
            GenreOperation::Alias => Self::Alias {
                compte: lire_identifiant(charge, Genre::Utilisateur)?,
                alias: match apres_identifiant.first().copied().unwrap_or(0) {
                    0 => {
                        if !bourrage_nul(apres_identifiant.get(1..).unwrap_or_default()) {
                            return Err(Faute::Bourrage);
                        }
                        None
                    }
                    1 => Some(AliasRange::lire(
                        apres_identifiant.get(1..).unwrap_or_default(),
                    )?),
                    lue => return Err(Faute::Etiquette { lue }),
                },
            },
            GenreOperation::Appareil => Self::Appareil {
                appareil: lire_identifiant(charge, Genre::Appareil)?,
                enregistrement: Appareil::lire(&copie(apres_identifiant))?,
            },
            GenreOperation::AppareilRevoque => Self::AppareilRevoque {
                appareil: lire_identifiant(charge, Genre::Appareil)?,
            },
            GenreOperation::Description => Self::Description {
                appareil: lire_identifiant(charge, Genre::Appareil)?,
                enregistrement: Description::lire(&copie(apres_identifiant))?,
            },
            GenreOperation::Poussee => Self::Poussee {
                appareil: lire_identifiant(charge, Genre::Appareil)?,
                enregistrement: JetonPoussee::lire(&copie(apres_identifiant))?,
            },
            GenreOperation::Machine => Self::Machine {
                machine: lire_identifiant(charge, Genre::Machine)?,
                enregistrement: Machine::lire(&copie(apres_identifiant))?,
            },
            GenreOperation::MachineModifiee => {
                let presents = apres_identifiant.first().copied().unwrap_or(0);
                if presents & !(Self::PRESENT_NOM | Self::PRESENT_CAPACITES) != 0 {
                    return Err(Faute::Etiquette { lue: presents });
                }
                let place_du_nom = apres_identifiant
                    .get(1..1 + 1 + NOM_OCTETS_MAX)
                    .unwrap_or_default();
                let place_des_capacites = apres_identifiant
                    .get(1 + 1 + NOM_OCTETS_MAX..)
                    .unwrap_or_default();
                let nom = if presents & Self::PRESENT_NOM == 0 {
                    if !bourrage_nul(place_du_nom) {
                        return Err(Faute::Bourrage);
                    }
                    None
                } else {
                    Some(NomRange::lire(place_du_nom)?)
                };
                let capacites = if presents & Self::PRESENT_CAPACITES == 0 {
                    if !bourrage_nul(place_des_capacites) {
                        return Err(Faute::Bourrage);
                    }
                    None
                } else {
                    let octet = place_des_capacites.first().copied().unwrap_or(0);
                    if octet & !(Machine::BIT_ANNONCE | Machine::BIT_LECTURE) != 0 {
                        return Err(Faute::Etiquette { lue: octet });
                    }
                    Some(Capacites {
                        annonce: octet & Machine::BIT_ANNONCE != 0,
                        lecture: octet & Machine::BIT_LECTURE != 0,
                    })
                };
                Self::MachineModifiee {
                    machine: lire_identifiant(charge, Genre::Machine)?,
                    nom,
                    capacites,
                }
            }
            GenreOperation::Enrolement => {
                let mut empreinte = [0_u8; EMPREINTE_OCTETS];
                poser(&mut empreinte, charge);
                Self::Enrolement {
                    empreinte,
                    enregistrement: Enrolement::lire(&copie(
                        charge.get(EMPREINTE_OCTETS..).unwrap_or_default(),
                    ))?,
                }
            }
            GenreOperation::CleMachine => {
                let mut cle = [0_u8; CLE_OCTETS];
                poser(&mut cle, apres_identifiant);
                let mut empreinte = [0_u8; EMPREINTE_OCTETS];
                poser(
                    &mut empreinte,
                    apres_identifiant.get(CLE_OCTETS..).unwrap_or_default(),
                );
                Self::CleMachine {
                    machine: lire_identifiant(charge, Genre::Machine)?,
                    cle,
                    empreinte,
                    code: Estampille::lire(
                        apres_identifiant
                            .get(CLE_OCTETS.saturating_add(EMPREINTE_OCTETS)..)
                            .unwrap_or_default(),
                    )?,
                }
            }
            GenreOperation::CleMachineRevoquee => {
                let mut cle = [0_u8; CLE_OCTETS];
                poser(&mut cle, apres_identifiant);
                Self::CleMachineRevoquee {
                    machine: lire_identifiant(charge, Genre::Machine)?,
                    cle,
                }
            }
            GenreOperation::Service => Self::Service {
                service: lire_identifiant(charge, Genre::Service)?,
                enregistrement: Service::lire(&copie(apres_identifiant))?,
            },
            GenreOperation::Autorisation => Self::Autorisation {
                autorisation: lire_identifiant(charge, Genre::Autorisation)?,
                enregistrement: Autorisation::lire(&copie(apres_identifiant))?,
            },
            GenreOperation::AutorisationRevoquee => Self::AutorisationRevoquee {
                autorisation: lire_identifiant(charge, Genre::Autorisation)?,
            },
        };
        Ok((estampille, operation, attendus))
    }
}

/// Une tranche recopiée dans le tableau de taille fixe qu'un enregistrement
/// lit.
///
/// **La tranche a TOUJOURS cette taille exacte** : elle est découpée dans une
/// charge dont le genre a fixé la longueur, et [`Operation::lire`] a déjà
/// refusé ce qui était trop court. Une conversion `try_from` ouvrirait une
/// branche qu'aucun essai ne peut prendre ; la copie n'en ouvre aucune, et
/// c'est l'idiome de tout ce module — `zip` s'arrête sur le plus court.
fn copie<const N: usize>(tranche: &[u8]) -> [u8; N] {
    let mut tableau = [0_u8; N];
    poser(&mut tableau, tranche);
    tableau
}

// ── Le cadre de fin d'un instantané (`docs/replication.md` §5.4) ────────────

/// L'étiquette du cadre de fin : la quinzième, juste après les quatorze genres
/// d'opération, et **ce n'est pas un genre d'opération**.
///
/// [`GenreOperation::depuis`] la refuse, et c'est voulu : une opération est un
/// fait à appliquer, le cadre de fin est un signal de coupe. Le lecteur qui
/// applique ne doit jamais le prendre pour un fait, et celui qui lit un
/// instantané doit savoir le reconnaître AVANT de demander une opération.
pub const ETIQUETTE_DE_FIN: u8 = 15;

/// Ce qu'un cadre de fin occupe : l'en-tête seul, sans charge.
///
/// `fin (1) ‖ compteur (8) ‖ racine (17)` — le compteur est celui auquel
/// l'instantané a été coupé, la racine est celle qui l'a émis. C'est là que le
/// tireur reprend `GET /v1/pair/operations`.
pub const CADRE_DE_FIN_OCTETS: usize = OPERATION_ENTETE_OCTETS;

/// Ce qu'une racine met sur le fil : une opération, ou la fin d'un instantané.
///
/// # POURQUOI UN TYPE DE PLUS, ET NON UNE VARIANTE D'[`Operation`]
///
/// Un instantané « est une suite d'opérations, pas un second format » (§5.4),
/// et il se termine par un cadre qui porte le compteur de coupe. Ce cadre a la
/// forme d'une opération sans charge, et il se lit dans le même flux. Mais il
/// ne S'APPLIQUE pas : en faire une variante d'[`Operation`] obligerait tout ce
/// qui applique à porter un bras « ne rien faire », c'est-à-dire un fait qui
/// n'en est pas un. Le lecteur du fil décode un [`Cadre`], et ne passe à
/// l'application que ce qui en est une.
///
/// **Les deux variantes n'ont pas la même taille, et c'est accepté** : un
/// cadre vit le temps d'être lu puis appliqué, sur la pile du lecteur, et
/// cette crate n'alloue pas — mettre l'opération dans une boîte pour que la
/// fin soit petite coûterait une allocation à chaque opération pour épargner
/// trois cents octets à un cadre qui ne passe qu'une fois par instantané.
#[expect(
    clippy::large_enum_variant,
    reason = "un cadre vit sur la pile le temps d'une lecture, et la crate n'alloue pas"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cadre {
    /// Une opération, sous son estampille.
    Operation {
        /// Quand, et par quelle racine.
        estampille: Estampille,
        /// Quoi.
        operation: Operation,
    },
    /// La fin d'un instantané.
    Fin {
        /// Le compteur auquel l'instantané a été coupé, et la racine qui l'a
        /// émis : le tireur reprend le flux à partir de là.
        coupe: Estampille,
    },
}

impl Cadre {
    /// Écrit ce cadre, et rend ce qu'il occupe.
    ///
    /// Le tampon fait toujours [`OPERATION_OCTETS_MAX`], comme pour
    /// [`Operation::ecrire`], et pour la même raison : écrire sans allouer.
    pub fn ecrire(&self, sortie: &mut [u8; OPERATION_OCTETS_MAX]) -> usize {
        match self {
            Self::Operation {
                estampille,
                operation,
            } => operation.ecrire(*estampille, sortie),
            Self::Fin { coupe } => {
                sortie.fill(0);
                poser_un(sortie, ETIQUETTE_DE_FIN);
                coupe.ecrire(sortie.get_mut(1..).unwrap_or_default());
                CADRE_DE_FIN_OCTETS
            }
        }
    }

    /// Relit un cadre en tête de ces octets, et rend ce qu'il a occupé.
    ///
    /// **Le premier octet dit lequel des deux**, et rien d'autre n'est regardé
    /// avant : un cadre de fin est reconnu sans passer par
    /// [`GenreOperation::depuis`], qui le refuserait.
    ///
    /// # Errors
    ///
    /// [`Faute::Tronquee`] si les octets s'arrêtent avant la fin du cadre, et
    /// les fautes d'[`Operation::lire`] pour une opération.
    pub fn lire(octets: &[u8]) -> Result<(Self, usize), Faute> {
        if octets.first().copied() == Some(ETIQUETTE_DE_FIN) {
            if octets.len() < CADRE_DE_FIN_OCTETS {
                return Err(Faute::Tronquee {
                    attendus: CADRE_DE_FIN_OCTETS,
                    obtenus: octets.len(),
                });
            }
            let coupe = Estampille::lire(octets.get(1..CADRE_DE_FIN_OCTETS).unwrap_or_default())?;
            return Ok((Self::Fin { coupe }, CADRE_DE_FIN_OCTETS));
        }
        let (estampille, operation, combien) = Operation::lire(octets)?;
        Ok((
            Self::Operation {
                estampille,
                operation,
            },
            combien,
        ))
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
        ALIAS_OCTETS_MAX, APPAREIL_OCTETS, AUTORISATION_OCTETS, AliasRange, Appareil, Attestation,
        Autorisation, CADRE_DE_FIN_OCTETS, CLE_APPAREIL_OCTETS, CLE_OCTETS, CLEF_JOURNAL_OCTETS,
        COMPTE_OCTETS, Cadre, Capacites, CleLiee, Compte, Court, DESCRIPTION_OCTETS, Description,
        EMPREINTE_OCTETS, ENROLEMENT_OCTETS, ENTREE_OCTETS, ESTAMPILLE_OCTETS, ETIQUETTE_DE_FIN,
        Enrolement, EntreeJournal, Estampille, Faute, GenreOperation, IDENTIFIANT_OCTETS,
        JETON_OCTETS_MAX, JetonPoussee, JetonRange, MACHINE_OCTETS, Machine, NOM_OCTETS_MAX,
        NomRange, OPERATION_ENTETE_OCTETS, OPERATION_OCTETS_MAX, Operation, PORTEE_OCTETS,
        POUSSEE_OCTETS, PROVENANCE_OCTETS, Plateforme, Portee, Provenance, SERVICE_OCTETS, Service,
        Systeme, Verdict, ancien,
    };

    /// Un identifiant de ce genre, reproductible.
    fn un(genre: Genre, graine: u8) -> Identifiant {
        Identifiant::depuis_entropie(genre, [graine; 16])
    }

    /// Une estampille de cette racine-ci, à ce compteur.
    fn e(compteur: u64) -> Estampille {
        Estampille {
            compteur,
            racine: un(Genre::Annuaire, 0xEE),
        }
    }

    /// Une clé liée, reproductible.
    fn cle_liee(octet: u8) -> CleLiee {
        CleLiee {
            cle: [octet; CLE_OCTETS],
            liaison: e(7),
            code: e(6),
        }
    }

    /// Un compte, reproductible.
    fn un_compte(provenance: Provenance, alias: Option<&str>) -> Compte {
        Compte {
            provenance,
            estampille: e(3),
            alias: alias.map(|texte| AliasRange::nouveau(texte).expect("il tient")),
            reclamation: e(3),
        }
    }

    /// Une machine, reproductible.
    fn une_machine(cle: Option<CleLiee>, annonce: bool, lecture: bool, nom: &str) -> Machine {
        Machine {
            provenance: Provenance::Ici,
            estampille: e(9),
            proprietaire: un(Genre::Utilisateur, 5),
            cle,
            annonce,
            lecture,
            capacites_estampille: e(8),
            nom: nom_de_machine(nom),
            nom_estampille: e(4),
        }
    }

    /// Un appareil, reproductible.
    fn un_appareil(atteste: Attestation, revoque: bool) -> Appareil {
        Appareil {
            provenance: Provenance::Ici,
            estampille: e(2),
            proprietaire: un(Genre::Utilisateur, 7),
            cle: [0x33; CLE_APPAREIL_OCTETS],
            atteste,
            revoque,
        }
    }

    /// Un enrôlement, reproductible.
    fn un_enrolement(provenance: Provenance, expire_a: u64) -> Enrolement {
        Enrolement {
            provenance,
            estampille: e(11),
            machine: un(Genre::Machine, 4),
            expire_a,
        }
    }

    /// Les octets d'un enregistrement ancien : la provenance, puis le corps
    /// que la forme courante range APRÈS ses estampilles.
    ///
    /// **C'est exactement ce que la reprise reçoit** : la forme d'avant est la
    /// forme courante moins ses estampilles, et rien d'autre n'a bougé.
    fn ancien<const NEUF: usize, const VIEUX: usize>(
        neuf: &[u8; NEUF],
        estampilles: usize,
    ) -> [u8; VIEUX] {
        let mut vieux = [0_u8; VIEUX];
        vieux[..PROVENANCE_OCTETS].copy_from_slice(&neuf[..PROVENANCE_OCTETS]);
        let corps = PROVENANCE_OCTETS.saturating_add(estampilles.saturating_mul(ESTAMPILLE_OCTETS));
        vieux[PROVENANCE_OCTETS..].copy_from_slice(&neuf[corps..]);
        vieux
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

    // ── Estampille ──────────────────────────────────────────────────────────

    #[test]
    fn une_estampille_se_relit() {
        let mut sortie = [0_u8; ESTAMPILLE_OCTETS];
        e(4_812).ecrire(&mut sortie);
        assert_eq!(Estampille::lire(&sortie), Ok(e(4_812)));
        // Le compteur est en gros-boutiste : les huit premiers octets.
        assert_eq!(&sortie[..8], &4_812_u64.to_be_bytes());
    }

    #[test]
    fn une_estampille_exige_une_racine() {
        // Une machine n'estampille rien : seule une racine écrit.
        let mut octets = [0_u8; ESTAMPILLE_OCTETS];
        octets[8] = Genre::Machine.prefixe();
        assert_eq!(
            Estampille::lire(&octets),
            Err(Faute::Genre {
                attendu: Genre::Annuaire
            })
        );
    }

    #[test]
    fn l_ordre_des_estampilles_est_le_compteur_puis_la_racine() {
        // **C'EST L'ORDRE TOTAL DE `replication.md` §4**, et l'invariant de
        // §3.1 en dépend : deux racines qui calculent « le plus ancien »
        // doivent obtenir le même, quel que soit l'ordre d'arrivée.
        let nitrogen = un(Genre::Annuaire, 0x01);
        let argon = un(Genre::Annuaire, 0x02);
        let a = |compteur, racine| Estampille { compteur, racine };

        // Le compteur d'abord…
        assert!(a(1, argon) < a(2, nitrogen));
        assert!(a(2, nitrogen) > a(1, argon));
        // …puis la racine, à compteur égal.
        assert!(a(5, nitrogen) < a(5, argon));
        assert_ne!(a(5, nitrogen), a(5, argon));
        // Et une estampille est égale à elle-même, et à elle seule.
        assert_eq!(a(5, nitrogen), a(5, nitrogen));
        assert_eq!(
            a(5, nitrogen).cmp(&a(5, nitrogen)),
            core::cmp::Ordering::Equal
        );

        // L'ordre est total : un tri ne dépend pas de l'ordre de départ.
        let mut une = [a(3, argon), a(1, nitrogen), a(3, nitrogen), a(2, argon)];
        let mut autre = [a(2, argon), a(3, nitrogen), a(1, nitrogen), a(3, argon)];
        une.sort();
        autre.sort();
        assert_eq!(une, autre);
        assert_eq!(
            une,
            [a(1, nitrogen), a(2, argon), a(3, nitrogen), a(3, argon)]
        );
    }

    // ── Compte ──────────────────────────────────────────────────────────────

    #[test]
    fn un_compte_sans_alias_se_relit() {
        let compte = un_compte(Provenance::Ici, None);
        let mut sortie = [0_u8; COMPTE_OCTETS];
        compte.ecrire(&mut sortie);
        assert_eq!(Compte::lire(&sortie), Ok(compte));
    }

    #[test]
    fn un_compte_avec_alias_se_relit() {
        let mut compte = un_compte(
            Provenance::Annuaire(un(Genre::Annuaire, 3)),
            Some("thierry"),
        );
        // La réclamation a sa propre estampille, distincte de la dernière
        // écriture : c'est elle que la règle de l'alias compare.
        compte.reclamation = e(1);
        let mut sortie = [0_u8; COMPTE_OCTETS];
        compte.ecrire(&mut sortie);
        assert_eq!(Compte::lire(&sortie), Ok(compte));
    }

    #[test]
    fn un_compte_sans_alias_n_emporte_aucun_reste() {
        let avec = un_compte(Provenance::Ici, Some("visible"));
        let mut sortie = [0_u8; COMPTE_OCTETS];
        avec.ecrire(&mut sortie);

        let sans = un_compte(Provenance::Ici, None);
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
        un_compte(Provenance::Ici, None).ecrire(&mut octets);
        octets[PROVENANCE_OCTETS + 2 * ESTAMPILLE_OCTETS] = 4;
        assert_eq!(Compte::lire(&octets), Err(Faute::Etiquette { lue: 4 }));
    }

    #[test]
    fn un_alias_de_longueur_corrompue_refuse_le_compte_entier() {
        let mut octets = [0_u8; COMPTE_OCTETS];
        un_compte(Provenance::Ici, Some("x")).ecrire(&mut octets);
        octets[PROVENANCE_OCTETS + 2 * ESTAMPILLE_OCTETS + 1] = 250;
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
    fn une_estampille_corrompue_refuse_le_compte_entier() {
        // Les deux estampilles, l'une après l'autre : sans l'une, la règle de
        // conflit n'est plus calculable ; sans l'autre, l'alias n'a plus de
        // rang dans la file.
        let mut octets = [0_u8; COMPTE_OCTETS];
        un_compte(Provenance::Ici, None).ecrire(&mut octets);
        for place in [
            PROVENANCE_OCTETS + 8,
            PROVENANCE_OCTETS + ESTAMPILLE_OCTETS + 8,
        ] {
            let mut corrompus = octets;
            corrompus[place] = Genre::Service.prefixe();
            assert_eq!(
                Compte::lire(&corrompus),
                Err(Faute::Genre {
                    attendu: Genre::Annuaire
                }),
                "à l'octet {place}"
            );
        }
    }

    #[test]
    fn un_compte_sans_alias_au_bourrage_sale_est_refuse() {
        let mut octets = [0_u8; COMPTE_OCTETS];
        un_compte(Provenance::Ici, None).ecrire(&mut octets);
        octets[PROVENANCE_OCTETS + 2 * ESTAMPILLE_OCTETS + 4] = 0xAA;
        assert_eq!(Compte::lire(&octets), Err(Faute::Bourrage));
    }

    #[test]
    fn un_compte_ancien_se_reprend_avec_l_estampille_qu_on_lui_donne() {
        // **C'EST LA REPRISE DE §11.4** : l'enregistrement d'avant, sans
        // estampille, relu avec celle que la racine lui attribue — et la
        // réclamation reçoit la même.
        for alias in [None, Some("thierry")] {
            let attendu = Compte {
                estampille: e(40),
                reclamation: e(40),
                ..un_compte(Provenance::Annuaire(un(Genre::Annuaire, 3)), alias)
            };
            let mut neuf = [0_u8; COMPTE_OCTETS];
            attendu.ecrire(&mut neuf);
            let vieux: [u8; ancien::COMPTE_OCTETS] = ancien(&neuf, 2);
            assert_eq!(Compte::lire_ancien(&vieux, e(40)), Ok(attendu), "{alias:?}");
        }

        // Et la corruption se voit dans la forme ancienne comme dans la neuve.
        let mut vieux = [0_u8; ancien::COMPTE_OCTETS];
        vieux[0] = 9;
        assert_eq!(
            Compte::lire_ancien(&vieux, e(1)),
            Err(Faute::Etiquette { lue: 9 })
        );
    }

    // ── Machine ─────────────────────────────────────────────────────────────

    #[test]
    fn une_machine_se_relit_entiere() {
        let machine = une_machine(Some(cle_liee(0x42)), true, false, "grenier");
        let mut sortie = [0_u8; MACHINE_OCTETS];
        machine.ecrire(&mut sortie);
        assert_eq!(Machine::lire(&sortie), Ok(machine));
        assert_eq!(
            machine.capacites(),
            Capacites {
                annonce: true,
                lecture: false
            }
        );
    }

    #[test]
    fn les_quatre_combinaisons_de_capacites_se_relisent() {
        for (annonce, lecture) in [(false, false), (true, false), (false, true), (true, true)] {
            let machine = une_machine(Some(cle_liee(0)), annonce, lecture, "grenier");
            let mut sortie = [0_u8; MACHINE_OCTETS];
            machine.ecrire(&mut sortie);
            assert_eq!(Machine::lire(&sortie), Ok(machine), "{annonce} {lecture}");
        }
    }

    /// Où l'octet des drapeaux se trouve dans une machine.
    const DRAPEAUX: usize =
        PROVENANCE_OCTETS + 5 * ESTAMPILLE_OCTETS + IDENTIFIANT_OCTETS + CLE_OCTETS;

    #[test]
    fn un_bit_de_capacite_inconnu_est_refuse() {
        // **UNE VERSION QUI EN SAIT PLUS QUE NOUS NE DOIT PAS ÊTRE RELUE À
        // MOITIÉ** : lui prêter des capacités qu'on ne comprend pas serait pire
        // que de refuser.
        let machine = une_machine(Some(cle_liee(0)), true, true, "grenier");
        let mut octets = [0_u8; MACHINE_OCTETS];
        machine.ecrire(&mut octets);
        // **L'OCTET DES DRAPEAUX SE CALCULE DEPUIS LES CONSTANTES**, et non à
        // rebours : il a visé à côté une fois, et il a rendu `Bourrage`.
        octets[DRAPEAUX] |= 0b1000_0000;
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
        let machine = une_machine(None, false, true, "portable");
        let mut octets = [0_u8; MACHINE_OCTETS];
        machine.ecrire(&mut octets);
        assert_eq!(Machine::lire(&octets), Ok(machine));
    }

    #[test]
    fn une_machine_sans_cle_dont_la_place_n_est_pas_nulle_est_refusee() {
        // **DEUX ÉCRITURES POUR UNE MÊME VALEUR, ET C'EST NON.** Sans ce refus,
        // un enregistrement relu ne se réécrirait pas comme il a été lu. La
        // place de la clé, et celles de ses deux estampilles.
        let machine = une_machine(None, true, false, "grenier");
        for place in [
            PROVENANCE_OCTETS + 3 * ESTAMPILLE_OCTETS,
            PROVENANCE_OCTETS + 4 * ESTAMPILLE_OCTETS,
            PROVENANCE_OCTETS + 5 * ESTAMPILLE_OCTETS + IDENTIFIANT_OCTETS,
        ] {
            let mut octets = [0_u8; MACHINE_OCTETS];
            machine.ecrire(&mut octets);
            octets[place] = 0x01;
            assert_eq!(
                Machine::lire(&octets),
                Err(Faute::Bourrage),
                "à l'octet {place}"
            );
        }
    }

    #[test]
    fn une_cle_dont_une_estampille_est_corrompue_est_refusee() {
        let machine = une_machine(Some(cle_liee(1)), true, false, "grenier");
        for place in [
            PROVENANCE_OCTETS + 3 * ESTAMPILLE_OCTETS + 8,
            PROVENANCE_OCTETS + 4 * ESTAMPILLE_OCTETS + 8,
        ] {
            let mut octets = [0_u8; MACHINE_OCTETS];
            machine.ecrire(&mut octets);
            octets[place] = Genre::Machine.prefixe();
            assert_eq!(
                Machine::lire(&octets),
                Err(Faute::Genre {
                    attendu: Genre::Annuaire
                }),
                "à l'octet {place}"
            );
        }
    }

    #[test]
    fn une_cle_liee_ne_laisse_aucun_reste_derriere_elle() {
        // Une machine enrôlée puis réécrite sans clé — une révocation — ne
        // doit rien laisser de la clé ni de ses estampilles.
        let mut octets = [0xFF_u8; MACHINE_OCTETS];
        une_machine(Some(cle_liee(0x42)), true, true, "grenier").ecrire(&mut octets);
        let sans = une_machine(None, true, true, "grenier");
        sans.ecrire(&mut octets);
        assert_eq!(Machine::lire(&octets), Ok(sans));
    }

    #[test]
    fn un_proprietaire_qui_n_est_pas_un_utilisateur_est_refuse() {
        let mut octets = [0_u8; MACHINE_OCTETS];
        une_machine(None, true, true, "grenier").ecrire(&mut octets);
        octets[PROVENANCE_OCTETS + 5 * ESTAMPILLE_OCTETS] = Genre::Service.prefixe();
        assert_eq!(
            Machine::lire(&octets),
            Err(Faute::Genre {
                attendu: Genre::Utilisateur
            })
        );
    }

    #[test]
    fn une_provenance_ou_une_estampille_corrompue_refuse_la_machine_entiere() {
        let mut octets = [0_u8; MACHINE_OCTETS];
        octets[0] = 9;
        assert_eq!(Machine::lire(&octets), Err(Faute::Etiquette { lue: 9 }));

        // Les trois estampilles hors clé, l'une après l'autre.
        for rang in 0..3 {
            let mut octets = [0_u8; MACHINE_OCTETS];
            une_machine(None, true, true, "grenier").ecrire(&mut octets);
            octets[PROVENANCE_OCTETS + rang * ESTAMPILLE_OCTETS + 8] = Genre::Machine.prefixe();
            assert_eq!(
                Machine::lire(&octets),
                Err(Faute::Genre {
                    attendu: Genre::Annuaire
                }),
                "estampille {rang}"
            );
        }
    }

    #[test]
    fn une_machine_ancienne_se_reprend_avec_l_estampille_qu_on_lui_donne() {
        // **TOUS LES CHAMPS REÇOIVENT LA MÊME** : le nom, les capacités, et la
        // clé si elle est là — dont le code est réputé émis à la reprise.
        for cle in [None, Some([0x42; CLE_OCTETS])] {
            let attendue = Machine {
                estampille: e(40),
                capacites_estampille: e(40),
                nom_estampille: e(40),
                cle: cle.map(|cle| CleLiee {
                    cle,
                    liaison: e(40),
                    code: e(40),
                }),
                ..une_machine(None, true, false, "grenier")
            };
            let mut neuf = [0_u8; MACHINE_OCTETS];
            attendue.ecrire(&mut neuf);
            let vieux: [u8; ancien::MACHINE_OCTETS] = ancien(&neuf, 5);
            assert_eq!(Machine::lire_ancien(&vieux, e(40)), Ok(attendue), "{cle:?}");
        }

        let mut vieux = [0_u8; ancien::MACHINE_OCTETS];
        vieux[0] = 9;
        assert_eq!(
            Machine::lire_ancien(&vieux, e(1)),
            Err(Faute::Etiquette { lue: 9 })
        );
    }

    // ── Service ─────────────────────────────────────────────────────────────

    /// Un service, reproductible.
    fn un_service(provenance: Provenance, nom: &str) -> Service {
        Service {
            provenance,
            estampille: e(12),
            machine: un(Genre::Machine, 4),
            nom: NomRange::nouveau(nom).expect("il tient"),
        }
    }

    #[test]
    fn un_service_se_relit_entier() {
        let service = un_service(Provenance::Ici, "depot-de-messages");
        let mut sortie = [0_u8; SERVICE_OCTETS];
        service.ecrire(&mut sortie);
        assert_eq!(Service::lire(&sortie), Ok(service));
    }

    #[test]
    fn un_service_dont_la_machine_n_en_est_pas_une_est_refuse() {
        let mut octets = [0_u8; SERVICE_OCTETS];
        un_service(Provenance::Ici, "depot").ecrire(&mut octets);
        octets[PROVENANCE_OCTETS + ESTAMPILLE_OCTETS] = Genre::Utilisateur.prefixe();
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
        un_service(Provenance::Ici, "depot").ecrire(&mut octets);
        octets[PROVENANCE_OCTETS + ESTAMPILLE_OCTETS + IDENTIFIANT_OCTETS] = 250;
        assert_eq!(
            Service::lire(&octets),
            Err(Faute::Longueur {
                annoncee: 250,
                maximum: NOM_OCTETS_MAX,
            })
        );
    }

    #[test]
    fn une_provenance_ou_une_estampille_corrompue_refuse_le_service_entier() {
        let mut octets = [0_u8; SERVICE_OCTETS];
        octets[0] = 9;
        assert_eq!(Service::lire(&octets), Err(Faute::Etiquette { lue: 9 }));

        un_service(Provenance::Ici, "depot").ecrire(&mut octets);
        octets[PROVENANCE_OCTETS + 8] = Genre::Machine.prefixe();
        assert_eq!(
            Service::lire(&octets),
            Err(Faute::Genre {
                attendu: Genre::Annuaire
            })
        );
    }

    #[test]
    fn un_service_ancien_se_reprend_avec_l_estampille_qu_on_lui_donne() {
        let attendu = Service {
            estampille: e(40),
            ..un_service(Provenance::Annuaire(un(Genre::Annuaire, 3)), "depot")
        };
        let mut neuf = [0_u8; SERVICE_OCTETS];
        attendu.ecrire(&mut neuf);
        let vieux: [u8; ancien::SERVICE_OCTETS] = ancien(&neuf, 1);
        assert_eq!(Service::lire_ancien(&vieux, e(40)), Ok(attendu));

        let mut vieux = [0_u8; ancien::SERVICE_OCTETS];
        vieux[0] = 9;
        assert_eq!(
            Service::lire_ancien(&vieux, e(1)),
            Err(Faute::Etiquette { lue: 9 })
        );
    }

    // ── Portée et autorisation ──────────────────────────────────────────────

    /// Une autorisation, reproductible.
    fn une_autorisation(portee: Portee) -> Autorisation {
        Autorisation {
            provenance: Provenance::Ici,
            estampille: e(13),
            par: un(Genre::Utilisateur, 1),
            a: un(Genre::Utilisateur, 2),
            portee,
            revoquee: false,
            etiquette: NomRange::nouveau("le portable de Léa").unwrap(),
        }
    }

    /// Où la portée commence dans une autorisation.
    const PORTEE: usize =
        PROVENANCE_OCTETS + ESTAMPILLE_OCTETS + IDENTIFIANT_OCTETS + IDENTIFIANT_OCTETS;

    #[test]
    fn une_autorisation_garde_son_etiquette() {
        // L'étiquette fait l'aller-retour, texte non nul comme un nom.
        let mut autorisation = une_autorisation(Portee::ToutLeCompte);
        autorisation.etiquette = NomRange::nouveau("accès NAS, révoquer en juin").unwrap();
        let mut sortie = [0_u8; AUTORISATION_OCTETS];
        autorisation.ecrire(&mut sortie);
        assert_eq!(Autorisation::lire(&sortie), Ok(autorisation));
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
        octets[PORTEE] = 7;
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
        octets[PORTEE + 3] = 0xAA;
        assert_eq!(Autorisation::lire(&octets), Err(Faute::Bourrage));
    }

    #[test]
    fn une_portee_de_machine_exige_un_genre_machine() {
        let autorisation = une_autorisation(Portee::UnService(un(Genre::Service, 1)));
        let mut octets = [0_u8; AUTORISATION_OCTETS];
        autorisation.ecrire(&mut octets);
        octets[PORTEE] = Portee::MACHINE;
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
        octets[PORTEE] = Portee::SERVICE;
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
        // Le drapeau de révocation est juste après la portée, avant l'étiquette
        // — ce n'est plus le dernier octet depuis que l'étiquette existe.
        octets[PORTEE + PORTEE_OCTETS] = 2;
        assert_eq!(
            Autorisation::lire(&octets),
            Err(Faute::Etiquette { lue: 2 })
        );
    }

    #[test]
    fn une_etiquette_dont_la_longueur_deborde_refuse_l_autorisation() {
        // L'étiquette est un `Court` : une longueur annoncée au-delà de sa borne
        // n'est pas une étiquette, et l'autorisation entière est refusée.
        let autorisation = une_autorisation(Portee::ToutLeCompte);
        let mut octets = [0_u8; AUTORISATION_OCTETS];
        autorisation.ecrire(&mut octets);
        octets[PORTEE + PORTEE_OCTETS + 1] =
            u8::try_from(NOM_OCTETS_MAX + 1).expect("tient sur un octet");
        assert_eq!(
            Autorisation::lire(&octets),
            Err(Faute::Longueur {
                annoncee: NOM_OCTETS_MAX + 1,
                maximum: NOM_OCTETS_MAX,
            })
        );
    }

    #[test]
    fn les_deux_comptes_d_une_autorisation_doivent_etre_des_utilisateurs() {
        let apres_estampille = PROVENANCE_OCTETS + ESTAMPILLE_OCTETS;
        for place in [apres_estampille, apres_estampille + IDENTIFIANT_OCTETS] {
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
    fn une_provenance_ou_une_estampille_corrompue_refuse_l_autorisation_entiere() {
        let mut octets = [0_u8; AUTORISATION_OCTETS];
        octets[0] = 9;
        assert_eq!(
            Autorisation::lire(&octets),
            Err(Faute::Etiquette { lue: 9 })
        );

        une_autorisation(Portee::ToutLeCompte).ecrire(&mut octets);
        octets[PROVENANCE_OCTETS + 8] = Genre::Machine.prefixe();
        assert_eq!(
            Autorisation::lire(&octets),
            Err(Faute::Genre {
                attendu: Genre::Annuaire
            })
        );
    }

    #[test]
    fn une_autorisation_ancienne_se_reprend_avec_l_estampille_qu_on_lui_donne() {
        let attendue = Autorisation {
            estampille: e(40),
            revoquee: true,
            ..une_autorisation(Portee::UnService(un(Genre::Service, 6)))
        };
        let mut neuf = [0_u8; AUTORISATION_OCTETS];
        attendue.ecrire(&mut neuf);
        let vieux: [u8; ancien::AUTORISATION_OCTETS] = ancien(&neuf, 1);
        assert_eq!(Autorisation::lire_ancien(&vieux, e(40)), Ok(attendue));

        let mut vieux = [0_u8; ancien::AUTORISATION_OCTETS];
        vieux[0] = 9;
        assert_eq!(
            Autorisation::lire_ancien(&vieux, e(1)),
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

    // ── Le jeton de poussée ─────────────────────────────────────────────────

    /// Un jeton de poussée, reproductible.
    fn un_jeton(plateforme: Plateforme, texte: &str) -> JetonPoussee {
        JetonPoussee {
            provenance: Provenance::Ici,
            estampille: e(14),
            plateforme,
            jeton: JetonRange::nouveau(texte).expect("il tient"),
        }
    }

    /// Où la plate-forme se trouve dans un jeton.
    const PLATEFORME: usize = PROVENANCE_OCTETS + ESTAMPILLE_OCTETS;

    #[test]
    fn un_jeton_de_poussee_fait_l_aller_retour() {
        for plateforme in [Plateforme::Apns, Plateforme::Fcm] {
            let jeton = un_jeton(plateforme, "c0ffee");
            let mut octets = [0_u8; POUSSEE_OCTETS];
            jeton.ecrire(&mut octets);
            assert_eq!(JetonPoussee::lire(&octets), Ok(jeton), "{plateforme:?}");
        }
    }

    #[test]
    fn un_jeton_venu_d_un_pair_fait_l_aller_retour() {
        // C17 : il porte son origine comme tout le reste.
        let jeton = JetonPoussee {
            provenance: Provenance::Annuaire(un(Genre::Annuaire, 2)),
            ..un_jeton(Plateforme::Fcm, "d0d0")
        };
        let mut octets = [0_u8; POUSSEE_OCTETS];
        jeton.ecrire(&mut octets);
        assert_eq!(JetonPoussee::lire(&octets), Ok(jeton));
    }

    #[test]
    fn un_jeton_de_la_longueur_maximale_tient() {
        // **255 EST LA BORNE, ET ELLE DOIT PASSER**, pas seulement les longueurs
        // qu'on observe : un jeton FCM n'a pas de longueur promise.
        let long = "a".repeat(JETON_OCTETS_MAX);
        let jeton = un_jeton(Plateforme::Fcm, &long);
        let mut octets = [0_u8; POUSSEE_OCTETS];
        jeton.ecrire(&mut octets);
        assert_eq!(JetonPoussee::lire(&octets), Ok(jeton));
        assert_eq!(jeton.jeton.longueur(), JETON_OCTETS_MAX);

        // Et un octet de plus est refusé, plutôt que tronqué : un jeton tronqué
        // serait présenté tel quel à Apple, qui le refuserait sans dire pourquoi.
        let trop = "a".repeat(JETON_OCTETS_MAX + 1);
        assert_eq!(
            JetonRange::nouveau(&trop),
            Err(Faute::Longueur {
                annoncee: JETON_OCTETS_MAX + 1,
                maximum: JETON_OCTETS_MAX,
            })
        );
    }

    #[test]
    fn une_plateforme_inconnue_refuse_le_jeton() {
        let jeton = un_jeton(Plateforme::Apns, "c0ffee");
        let mut octets = [0_u8; POUSSEE_OCTETS];
        jeton.ecrire(&mut octets);
        // **ZÉRO EN FAIT PARTIE**, et c'est le cas qui compte : un tampon
        // réemployé vaut zéro, et le laisser désigner APNs ferait présenter à
        // Apple des jetons qu'on n'a jamais reçus.
        for lue in [0_u8, 3, 200] {
            octets[PLATEFORME] = lue;
            assert_eq!(
                JetonPoussee::lire(&octets),
                Err(Faute::Etiquette { lue }),
                "{lue}"
            );
        }
    }

    #[test]
    fn une_provenance_ou_une_longueur_corrompue_refuse_le_jeton() {
        let jeton = un_jeton(Plateforme::Apns, "c0ffee");
        let mut octets = [0_u8; POUSSEE_OCTETS];

        jeton.ecrire(&mut octets);
        octets[0] = 9;
        assert_eq!(
            JetonPoussee::lire(&octets),
            Err(Faute::Etiquette { lue: 9 })
        );

        // L'estampille aussi.
        jeton.ecrire(&mut octets);
        octets[PROVENANCE_OCTETS + 8] = Genre::Machine.prefixe();
        assert_eq!(
            JetonPoussee::lire(&octets),
            Err(Faute::Genre {
                attendu: Genre::Annuaire
            })
        );

        // **UNE LONGUEUR ALLONGÉE NE DÉPASSE JAMAIS 255**, donc `Court` ne peut
        // pas la refuser ; ce sont les zéros qu'elle fait entrer dans le texte
        // qui la dénoncent.
        jeton.ecrire(&mut octets);
        octets[PLATEFORME + 1] = 255;
        assert_eq!(
            JetonPoussee::lire(&octets),
            Err(Faute::NonImprimable { position: 6 })
        );

        // **UNE LONGUEUR RACCOURCIE, ELLE, SE VOIT** : le texte qu'elle exclut
        // reste dans le tampon, et n'y est plus du bourrage nul. C'est le seul
        // sens dans lequel `Court` sache encore se défendre à 255 octets de
        // borne — l'autre, la longueur allongée, ne peut pas dépasser le tableau.
        jeton.ecrire(&mut octets);
        octets[PLATEFORME + 1] = 3;
        assert_eq!(JetonPoussee::lire(&octets), Err(Faute::Bourrage));

        // Et l'espace n'est pas imprimable au sens qui nous intéresse : un jeton
        // n'en porte pas, et en accepter un ferait passer un tampon mal rempli.
        jeton.ecrire(&mut octets);
        octets[PLATEFORME + 2] = b' ';
        assert_eq!(
            JetonPoussee::lire(&octets),
            Err(Faute::NonImprimable { position: 0 })
        );
    }

    #[test]
    fn un_jeton_ancien_se_reprend_avec_l_estampille_qu_on_lui_donne() {
        let attendu = JetonPoussee {
            estampille: e(40),
            ..un_jeton(Plateforme::Fcm, "d0d0")
        };
        let mut neuf = [0_u8; POUSSEE_OCTETS];
        attendu.ecrire(&mut neuf);
        let vieux: [u8; ancien::POUSSEE_OCTETS] = ancien(&neuf, 1);
        assert_eq!(JetonPoussee::lire_ancien(&vieux, e(40)), Ok(attendu));

        let mut vieux = [0_u8; ancien::POUSSEE_OCTETS];
        vieux[0] = 9;
        assert_eq!(
            JetonPoussee::lire_ancien(&vieux, e(1)),
            Err(Faute::Etiquette { lue: 9 })
        );
    }

    // ── La description d'un appareil ────────────────────────────────────────

    /// Une description, reproductible.
    fn une_description(systeme: Systeme, modele: &str) -> Description {
        Description {
            provenance: Provenance::Ici,
            estampille: e(15),
            systeme,
            modele: nom_de_machine(modele),
        }
    }

    /// Où le système se trouve dans une description.
    const SYSTEME: usize = PROVENANCE_OCTETS + ESTAMPILLE_OCTETS;

    #[test]
    fn une_description_fait_l_aller_retour() {
        for systeme in [Systeme::Ios, Systeme::Android, Systeme::Macos] {
            let description = une_description(systeme, "MacBook Pro (2019)");
            let mut octets = [0_u8; DESCRIPTION_OCTETS];
            description.ecrire(&mut octets);
            assert_eq!(Description::lire(&octets), Ok(description), "{systeme:?}");
        }
    }

    #[test]
    fn une_description_venue_d_un_pair_fait_l_aller_retour() {
        // C17 : elle porte son origine comme tout le reste.
        let description = Description {
            provenance: Provenance::Annuaire(un(Genre::Annuaire, 2)),
            ..une_description(Systeme::Android, "Pixel 9")
        };
        let mut octets = [0_u8; DESCRIPTION_OCTETS];
        description.ecrire(&mut octets);
        assert_eq!(Description::lire(&octets), Ok(description));
    }

    #[test]
    fn un_modele_porte_du_texte_libre_jusqu_a_la_borne() {
        // **LES MÊMES RÈGLES QU'UN NOM DE MACHINE** : tout l'UTF-8, en octets.
        let description = une_description(Systeme::Ios, "iPhone 17 — édition « été » 📱");
        let mut octets = [0_u8; DESCRIPTION_OCTETS];
        description.ecrire(&mut octets);
        assert_eq!(Description::lire(&octets), Ok(description));

        let long = "m".repeat(NOM_OCTETS_MAX);
        let description = une_description(Systeme::Macos, &long);
        description.ecrire(&mut octets);
        assert_eq!(Description::lire(&octets), Ok(description));
        assert_eq!(description.modele.longueur(), NOM_OCTETS_MAX);
    }

    #[test]
    fn un_systeme_inconnu_refuse_la_description() {
        let description = une_description(Systeme::Ios, "iPhone 17");
        let mut octets = [0_u8; DESCRIPTION_OCTETS];
        description.ecrire(&mut octets);
        // **ZÉRO EN FAIT PARTIE** : un tampon réemployé vaut zéro, et ne doit
        // désigner aucun système.
        for lue in [0_u8, 4, 200] {
            octets[SYSTEME] = lue;
            assert_eq!(
                Description::lire(&octets),
                Err(Faute::Etiquette { lue }),
                "{lue}"
            );
        }
    }

    #[test]
    fn une_provenance_ou_un_modele_corrompu_refuse_la_description() {
        let description = une_description(Systeme::Ios, "iPhone 17");
        let mut octets = [0_u8; DESCRIPTION_OCTETS];

        description.ecrire(&mut octets);
        octets[0] = 9;
        assert_eq!(Description::lire(&octets), Err(Faute::Etiquette { lue: 9 }));

        // L'estampille aussi.
        description.ecrire(&mut octets);
        octets[PROVENANCE_OCTETS + 8] = Genre::Machine.prefixe();
        assert_eq!(
            Description::lire(&octets),
            Err(Faute::Genre {
                attendu: Genre::Annuaire
            })
        );

        // Une longueur au-delà du tableau se voit : la borne du modèle est
        // celle d'un nom, et 64 tient dans un octet avec de la marge.
        description.ecrire(&mut octets);
        octets[SYSTEME + 1] = 250;
        assert_eq!(
            Description::lire(&octets),
            Err(Faute::Longueur {
                annoncee: 250,
                maximum: NOM_OCTETS_MAX,
            })
        );

        // Une longueur raccourcie laisse du texte dans le bourrage.
        description.ecrire(&mut octets);
        octets[SYSTEME + 1] = 3;
        assert_eq!(Description::lire(&octets), Err(Faute::Bourrage));
    }

    #[test]
    fn une_description_fait_la_taille_annoncee() {
        // Provenance, estampille, système, longueur du modèle, modèle.
        assert_eq!(
            DESCRIPTION_OCTETS,
            PROVENANCE_OCTETS + ESTAMPILLE_OCTETS + 1 + 1 + NOM_OCTETS_MAX
        );
    }

    #[test]
    fn une_description_ancienne_se_reprend_avec_l_estampille_qu_on_lui_donne() {
        let attendue = Description {
            estampille: e(40),
            ..une_description(Systeme::Macos, "MacBook Pro (2019)")
        };
        let mut neuf = [0_u8; DESCRIPTION_OCTETS];
        attendue.ecrire(&mut neuf);
        let vieux: [u8; ancien::DESCRIPTION_OCTETS] = ancien(&neuf, 1);
        assert_eq!(Description::lire_ancien(&vieux, e(40)), Ok(attendue));

        let mut vieux = [0_u8; ancien::DESCRIPTION_OCTETS];
        vieux[0] = 9;
        assert_eq!(
            Description::lire_ancien(&vieux, e(1)),
            Err(Faute::Etiquette { lue: 9 })
        );
    }

    // ── L'appareil et l'enrôlement ──────────────────────────────────────────

    #[test]
    fn un_appareil_fait_l_aller_retour() {
        let appareil = un_appareil(Attestation::Apple, false);
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
            cle: [0; CLE_APPAREIL_OCTETS],
            // **ENTRÉ SANS PREUVE**, sous une posture facultative, et
            // **RÉVOQUÉ**, pour que les deux états fassent l'aller-retour.
            ..un_appareil(Attestation::Aucune, true)
        };
        let mut octets = [0_u8; APPAREIL_OCTETS];
        appareil.ecrire(&mut octets);
        assert_eq!(Appareil::lire(&octets), Ok(appareil));
    }

    #[test]
    fn un_proprietaire_d_appareil_qui_n_est_pas_un_utilisateur_est_refuse() {
        let mut octets = [0_u8; APPAREIL_OCTETS];
        un_appareil(Attestation::Apple, false).ecrire(&mut octets);
        octets[PROVENANCE_OCTETS + ESTAMPILLE_OCTETS] = Genre::Machine.prefixe();
        assert_eq!(
            Appareil::lire(&octets),
            Err(Faute::Genre {
                attendu: Genre::Utilisateur
            })
        );
    }

    #[test]
    fn un_appareil_ancien_se_reprend_avec_l_estampille_qu_on_lui_donne() {
        let attendu = Appareil {
            estampille: e(40),
            ..un_appareil(Attestation::Android, true)
        };
        let mut neuf = [0_u8; APPAREIL_OCTETS];
        attendu.ecrire(&mut neuf);
        let vieux: [u8; ancien::APPAREIL_OCTETS] = ancien(&neuf, 1);
        assert_eq!(Appareil::lire_ancien(&vieux, e(40)), Ok(attendu));

        let mut vieux = [0_u8; ancien::APPAREIL_OCTETS];
        vieux[0] = 9;
        assert_eq!(
            Appareil::lire_ancien(&vieux, e(1)),
            Err(Faute::Etiquette { lue: 9 })
        );
    }

    #[test]
    fn un_enrolement_fait_l_aller_retour() {
        let enrolement = un_enrolement(Provenance::Ici, 1_757_000_000_000);
        let mut octets = [0_u8; ENROLEMENT_OCTETS];
        enrolement.ecrire(&mut octets);
        assert_eq!(Enrolement::lire(&octets), Ok(enrolement));
    }

    #[test]
    fn un_enrolement_venu_d_un_pair_fait_l_aller_retour() {
        let enrolement = un_enrolement(Provenance::Annuaire(un(Genre::Annuaire, 9)), 0);
        let mut octets = [0_u8; ENROLEMENT_OCTETS];
        enrolement.ecrire(&mut octets);
        assert_eq!(Enrolement::lire(&octets), Ok(enrolement));
    }

    #[test]
    fn un_enrolement_qui_ne_designe_pas_une_machine_est_refuse() {
        let mut octets = [0_u8; ENROLEMENT_OCTETS];
        un_enrolement(Provenance::Ici, 1).ecrire(&mut octets);
        octets[PROVENANCE_OCTETS + ESTAMPILLE_OCTETS] = Genre::Service.prefixe();
        assert_eq!(
            Enrolement::lire(&octets),
            Err(Faute::Genre {
                attendu: Genre::Machine
            })
        );
    }

    #[test]
    fn un_enrolement_ancien_se_reprend_avec_l_estampille_qu_on_lui_donne() {
        let attendu = Enrolement {
            estampille: e(40),
            ..un_enrolement(Provenance::Ici, 1_800_000_000_000)
        };
        let mut neuf = [0_u8; ENROLEMENT_OCTETS];
        attendu.ecrire(&mut neuf);
        let vieux: [u8; ancien::ENROLEMENT_OCTETS] = ancien(&neuf, 1);
        assert_eq!(Enrolement::lire_ancien(&vieux, e(40)), Ok(attendu));

        let mut vieux = [0_u8; ancien::ENROLEMENT_OCTETS];
        vieux[0] = 9;
        assert_eq!(
            Enrolement::lire_ancien(&vieux, e(1)),
            Err(Faute::Etiquette { lue: 9 })
        );
    }

    #[test]
    fn une_machine_dont_le_nom_est_illisible_est_refusee() {
        // La longueur annoncée du nom dépasse la place : c'est une corruption,
        // et elle se lit plutôt qu'elle ne se devine.
        let machine = une_machine(Some(cle_liee(9)), true, true, "grenier");
        let mut octets = [0_u8; MACHINE_OCTETS];
        machine.ecrire(&mut octets);
        octets[DRAPEAUX + 1] = 200;
        assert_eq!(
            Machine::lire(&octets),
            Err(Faute::Longueur {
                annoncee: 200,
                maximum: NOM_OCTETS_MAX
            })
        );
    }

    #[test]
    fn une_provenance_ou_une_estampille_illisible_est_refusee_sur_l_appareil_et_l_enrolement() {
        // L'étiquette de provenance vient en tête : elle est le premier refus.
        let mut appareil = [0_u8; APPAREIL_OCTETS];
        appareil[0] = 0x7F;
        assert_eq!(
            Appareil::lire(&appareil),
            Err(Faute::Etiquette { lue: 0x7F })
        );
        un_appareil(Attestation::Aucune, false).ecrire(&mut appareil);
        appareil[PROVENANCE_OCTETS + 8] = Genre::Machine.prefixe();
        assert_eq!(
            Appareil::lire(&appareil),
            Err(Faute::Genre {
                attendu: Genre::Annuaire
            })
        );

        let mut enrolement = [0_u8; ENROLEMENT_OCTETS];
        enrolement[0] = 0x7F;
        assert_eq!(
            Enrolement::lire(&enrolement),
            Err(Faute::Etiquette { lue: 0x7F })
        );
        un_enrolement(Provenance::Ici, 1).ecrire(&mut enrolement);
        enrolement[PROVENANCE_OCTETS + 8] = Genre::Machine.prefixe();
        assert_eq!(
            Enrolement::lire(&enrolement),
            Err(Faute::Genre {
                attendu: Genre::Annuaire
            })
        );
    }

    #[test]
    fn un_drapeau_de_revocation_qui_n_est_ni_zero_ni_un_est_refuse() {
        // **UN BOOLÉEN N'A QUE DEUX ÉCRITURES.** En accepter une troisième
        // rendrait l'encodage non canonique : un enregistrement relu se
        // réécrirait différemment de lui-même, et c'est le fuzz qui le dirait.
        let appareil = un_appareil(Attestation::Android, false);
        let mut octets = [0_u8; APPAREIL_OCTETS];
        appareil.ecrire(&mut octets);
        let dernier = APPAREIL_OCTETS.saturating_sub(1);
        octets[dernier] = 2;
        assert_eq!(Appareil::lire(&octets), Err(Faute::Etiquette { lue: 2 }));
    }

    #[test]
    fn les_trois_attestations_font_l_aller_retour() {
        for atteste in [
            Attestation::Aucune,
            Attestation::Apple,
            Attestation::Android,
        ] {
            let appareil = un_appareil(atteste, false);
            let mut octets = [0_u8; APPAREIL_OCTETS];
            appareil.ecrire(&mut octets);
            assert_eq!(Appareil::lire(&octets), Ok(appareil), "pour {atteste:?}");
        }
    }

    #[test]
    fn une_etiquette_d_attestation_a_zero_est_refusee() {
        // **ZÉRO NE DÉSIGNE PERSONNE**, ici, à la différence du fil : un octet
        // oublié dans un tampon réemployé vaut zéro, et un appareil à demi
        // écrit ne doit pas se relire comme un appareil non attesté.
        let appareil = un_appareil(Attestation::Aucune, false);
        let mut octets = [0_u8; APPAREIL_OCTETS];
        appareil.ecrire(&mut octets);
        // L'octet d'attestation est juste après la clé.
        let place =
            PROVENANCE_OCTETS + ESTAMPILLE_OCTETS + IDENTIFIANT_OCTETS + CLE_APPAREIL_OCTETS;
        octets[place] = 0;
        assert_eq!(Appareil::lire(&octets), Err(Faute::Etiquette { lue: 0 }));
        octets[place] = 4;
        assert_eq!(Appareil::lire(&octets), Err(Faute::Etiquette { lue: 4 }));
    }

    // ── Les opérations ──────────────────────────────────────────────────────

    /// Une opération de chaque genre, dans l'ordre de `replication.md` §5.2.
    fn une_de_chaque() -> [Operation; 14] {
        [
            Operation::Compte {
                compte: un(Genre::Utilisateur, 1),
                enregistrement: un_compte(Provenance::Ici, Some("thierry")),
            },
            Operation::Alias {
                compte: un(Genre::Utilisateur, 1),
                alias: Some(AliasRange::nouveau("thierry").unwrap()),
            },
            Operation::Appareil {
                appareil: un(Genre::Appareil, 2),
                enregistrement: un_appareil(Attestation::Apple, false),
            },
            Operation::AppareilRevoque {
                appareil: un(Genre::Appareil, 2),
            },
            Operation::Description {
                appareil: un(Genre::Appareil, 2),
                enregistrement: une_description(Systeme::Ios, "iPhone 17"),
            },
            Operation::Poussee {
                appareil: un(Genre::Appareil, 2),
                enregistrement: un_jeton(Plateforme::Apns, "c0ffee"),
            },
            Operation::Machine {
                machine: un(Genre::Machine, 3),
                enregistrement: une_machine(None, true, true, "grenier"),
            },
            Operation::MachineModifiee {
                machine: un(Genre::Machine, 3),
                nom: Some(nom_de_machine("cave")),
                capacites: Some(Capacites {
                    annonce: false,
                    lecture: true,
                }),
            },
            Operation::Enrolement {
                empreinte: [0xC0; EMPREINTE_OCTETS],
                enregistrement: un_enrolement(Provenance::Ici, 1_800_000_000_000),
            },
            Operation::CleMachine {
                machine: un(Genre::Machine, 3),
                cle: [0x42; CLE_OCTETS],
                empreinte: [0xC0; EMPREINTE_OCTETS],
                code: e(11),
            },
            Operation::CleMachineRevoquee {
                machine: un(Genre::Machine, 3),
                cle: [0x42; CLE_OCTETS],
            },
            Operation::Service {
                service: un(Genre::Service, 4),
                enregistrement: un_service(Provenance::Ici, "depot"),
            },
            Operation::Autorisation {
                autorisation: un(Genre::Autorisation, 5),
                enregistrement: une_autorisation(Portee::ToutLeCompte),
            },
            Operation::AutorisationRevoquee {
                autorisation: un(Genre::Autorisation, 5),
            },
        ]
    }

    #[test]
    fn chaque_genre_fait_l_aller_retour_et_dit_ce_qu_il_occupe() {
        for (rang, operation) in une_de_chaque().into_iter().enumerate() {
            let genre = operation.genre();
            assert_eq!(genre, GenreOperation::TOUS[rang], "{operation:?}");
            assert_eq!(
                usize::from(genre.etiquette()),
                rang + 1,
                "les étiquettes suivent l'ordre de la table"
            );
            assert_eq!(GenreOperation::depuis(genre.etiquette()), Ok(genre));

            let mut sortie = [0xFF_u8; OPERATION_OCTETS_MAX];
            let combien = operation.ecrire(e(4_812), &mut sortie);
            assert_eq!(combien, genre.octets(), "{genre:?}");
            assert_eq!(sortie[0], genre.etiquette());
            // Ce que la charge ne couvre pas est nul : le tampon était sale.
            assert!(
                sortie[combien..].iter().all(|octet| *octet == 0),
                "{genre:?} laisse du bourrage derrière lui"
            );

            // Et ce qui suit n'est pas regardé : un second cadre, ou du bruit.
            let mut avec_suite = sortie.to_vec();
            avec_suite.extend_from_slice(&[0xAB; 3]);
            assert_eq!(
                Operation::lire(&avec_suite),
                Ok((e(4_812), operation, combien)),
                "{genre:?}"
            );
        }
    }

    #[test]
    fn un_alias_lache_et_un_patch_partiel_font_l_aller_retour() {
        // Les deux genres qui portent un « ou rien » : chaque absence a sa
        // forme, et chacune doit revenir.
        let variantes = [
            Operation::Alias {
                compte: un(Genre::Utilisateur, 1),
                alias: None,
            },
            Operation::MachineModifiee {
                machine: un(Genre::Machine, 3),
                nom: None,
                capacites: Some(Capacites {
                    annonce: true,
                    lecture: false,
                }),
            },
            Operation::MachineModifiee {
                machine: un(Genre::Machine, 3),
                nom: Some(nom_de_machine("cave")),
                capacites: None,
            },
            Operation::MachineModifiee {
                machine: un(Genre::Machine, 3),
                nom: None,
                capacites: None,
            },
        ];
        for operation in variantes {
            let mut sortie = [0xFF_u8; OPERATION_OCTETS_MAX];
            let combien = operation.ecrire(e(1), &mut sortie);
            assert_eq!(
                Operation::lire(&sortie[..combien]),
                Ok((e(1), operation, combien)),
                "{operation:?}"
            );
        }
    }

    #[test]
    fn un_genre_inconnu_est_refuse_zero_compris() {
        for lue in [0_u8, 15, 200] {
            let mut octets = [0_u8; OPERATION_OCTETS_MAX];
            octets[0] = lue;
            assert_eq!(Operation::lire(&octets), Err(Faute::Etiquette { lue }));
            assert_eq!(GenreOperation::depuis(lue), Err(Faute::Etiquette { lue }));
        }
    }

    #[test]
    fn une_operation_tronquee_est_refusee_et_dit_ce_qui_manque() {
        // **C'EST LA SEULE LONGUEUR DU FIL, ET ELLE VIENT DU GENRE.** Une
        // tranche plus courte n'est pas une opération, et l'on ne devine pas
        // ce qui manque.
        for operation in une_de_chaque() {
            let mut sortie = [0_u8; OPERATION_OCTETS_MAX];
            let combien = operation.ecrire(e(1), &mut sortie);
            assert_eq!(
                Operation::lire(&sortie[..combien - 1]),
                Err(Faute::Tronquee {
                    attendus: combien,
                    obtenus: combien - 1,
                }),
                "{operation:?}"
            );
        }
        // Un seul octet — le genre — n'est pas une opération non plus.
        assert_eq!(
            Operation::lire(&[GenreOperation::AppareilRevoque.etiquette()]),
            Err(Faute::Tronquee {
                attendus: OPERATION_ENTETE_OCTETS + IDENTIFIANT_OCTETS,
                obtenus: 1,
            })
        );
    }

    #[test]
    fn une_estampille_d_en_tete_corrompue_refuse_l_operation() {
        let mut sortie = [0_u8; OPERATION_OCTETS_MAX];
        une_de_chaque()[3].ecrire(e(1), &mut sortie);
        sortie[1 + 8] = Genre::Machine.prefixe();
        assert_eq!(
            Operation::lire(&sortie),
            Err(Faute::Genre {
                attendu: Genre::Annuaire
            })
        );
    }

    #[test]
    fn un_identifiant_d_un_autre_genre_refuse_l_operation() {
        // Chaque genre exige le genre d'identifiant de ce qu'il porte : un
        // `compte` qui nommerait une machine n'est pas un compte.
        let attendus = [
            Genre::Utilisateur,
            Genre::Utilisateur,
            Genre::Appareil,
            Genre::Appareil,
            Genre::Appareil,
            Genre::Appareil,
            Genre::Machine,
            Genre::Machine,
            Genre::Machine, // l'enrôlement : c'est l'enregistrement qui nomme
            Genre::Machine,
            Genre::Machine,
            Genre::Service,
            Genre::Autorisation,
            Genre::Autorisation,
        ];
        for (operation, attendu) in une_de_chaque().into_iter().zip(attendus) {
            let mut sortie = [0_u8; OPERATION_OCTETS_MAX];
            operation.ecrire(e(1), &mut sortie);
            let place = match operation {
                // L'empreinte vient d'abord ; l'identifiant est dans
                // l'enregistrement, après sa provenance et son estampille.
                Operation::Enrolement { .. } => {
                    OPERATION_ENTETE_OCTETS
                        + EMPREINTE_OCTETS
                        + PROVENANCE_OCTETS
                        + ESTAMPILLE_OCTETS
                }
                _ => OPERATION_ENTETE_OCTETS,
            };
            sortie[place] = b'z';
            assert_eq!(
                Operation::lire(&sortie),
                Err(Faute::Genre { attendu }),
                "{operation:?}"
            );
        }
    }

    #[test]
    fn un_enregistrement_corrompu_refuse_l_operation_qui_le_porte() {
        // La provenance de l'enregistrement porté, mise à une étiquette
        // inconnue : la faute de l'enregistrement est celle de l'opération.
        for operation in une_de_chaque() {
            let debut = match operation {
                Operation::Compte { .. }
                | Operation::Appareil { .. }
                | Operation::Description { .. }
                | Operation::Poussee { .. }
                | Operation::Machine { .. }
                | Operation::Service { .. }
                | Operation::Autorisation { .. } => OPERATION_ENTETE_OCTETS + IDENTIFIANT_OCTETS,
                Operation::Enrolement { .. } => OPERATION_ENTETE_OCTETS + EMPREINTE_OCTETS,
                _ => continue,
            };
            let mut sortie = [0_u8; OPERATION_OCTETS_MAX];
            operation.ecrire(e(1), &mut sortie);
            sortie[debut] = 9;
            assert_eq!(
                Operation::lire(&sortie),
                Err(Faute::Etiquette { lue: 9 }),
                "{operation:?}"
            );
        }
    }

    #[test]
    fn une_cle_liee_dont_l_estampille_du_code_est_corrompue_est_refusee() {
        let mut sortie = [0_u8; OPERATION_OCTETS_MAX];
        une_de_chaque()[9].ecrire(e(1), &mut sortie);
        let place =
            OPERATION_ENTETE_OCTETS + IDENTIFIANT_OCTETS + CLE_OCTETS + EMPREINTE_OCTETS + 8;
        sortie[place] = Genre::Machine.prefixe();
        assert_eq!(
            Operation::lire(&sortie),
            Err(Faute::Genre {
                attendu: Genre::Annuaire
            })
        );
    }

    #[test]
    fn une_reclamation_d_alias_corrompue_est_refusee() {
        let mut sortie = [0_u8; OPERATION_OCTETS_MAX];
        une_de_chaque()[1].ecrire(e(1), &mut sortie);
        let present = OPERATION_ENTETE_OCTETS + IDENTIFIANT_OCTETS;

        // Une étiquette qui n'est ni « rien » ni « un alias ».
        let mut corrompue = sortie;
        corrompue[present] = 2;
        assert_eq!(
            Operation::lire(&corrompue),
            Err(Faute::Etiquette { lue: 2 })
        );

        // « Rien », mais du texte derrière.
        corrompue[present] = 0;
        assert_eq!(Operation::lire(&corrompue), Err(Faute::Bourrage));

        // Un alias dont la longueur déborde.
        let mut corrompue = sortie;
        corrompue[present + 1] = 200;
        assert_eq!(
            Operation::lire(&corrompue),
            Err(Faute::Longueur {
                annoncee: 200,
                maximum: ALIAS_OCTETS_MAX,
            })
        );
    }

    #[test]
    fn un_patch_de_machine_corrompu_est_refuse() {
        let mut sortie = [0_u8; OPERATION_OCTETS_MAX];
        une_de_chaque()[7].ecrire(e(1), &mut sortie);
        let presents = OPERATION_ENTETE_OCTETS + IDENTIFIANT_OCTETS;
        let capacites = presents + 1 + 1 + NOM_OCTETS_MAX;

        // Un champ qu'on ne connaît pas.
        let mut corrompue = sortie;
        corrompue[presents] = 0b0000_0100;
        assert_eq!(
            Operation::lire(&corrompue),
            Err(Faute::Etiquette { lue: 0b0000_0100 })
        );

        // Un nom absent, mais du texte à sa place.
        let mut corrompue = sortie;
        corrompue[presents] = Operation::PRESENT_CAPACITES;
        assert_eq!(Operation::lire(&corrompue), Err(Faute::Bourrage));

        // Des capacités absentes, mais un octet à leur place.
        let mut corrompue = sortie;
        corrompue[presents] = Operation::PRESENT_NOM;
        assert_eq!(Operation::lire(&corrompue), Err(Faute::Bourrage));

        // Un nom dont la longueur déborde.
        let mut corrompue = sortie;
        corrompue[presents + 1] = 200;
        assert_eq!(
            Operation::lire(&corrompue),
            Err(Faute::Longueur {
                annoncee: 200,
                maximum: NOM_OCTETS_MAX,
            })
        );

        // Une capacité qu'on ne connaît pas — le bit de la clé n'en est pas
        // une, et n'a rien à faire dans un `PATCH`.
        let mut corrompue = sortie;
        corrompue[capacites] = 0b0000_0100;
        assert_eq!(
            Operation::lire(&corrompue),
            Err(Faute::Etiquette { lue: 0b0000_0100 })
        );
    }

    #[test]
    fn la_plus_grande_charge_est_celle_du_jeton_et_le_tampon_la_tient() {
        // `OPERATION_OCTETS_MAX` est la taille du tampon d'écriture : si un
        // genre l'excédait, `ecrire` tronquerait en silence.
        for genre in GenreOperation::TOUS {
            assert!(genre.octets() <= OPERATION_OCTETS_MAX, "{genre:?}");
        }
        assert_eq!(GenreOperation::Poussee.octets(), OPERATION_OCTETS_MAX);
    }

    // ── Le cadre de fin d'un instantané ─────────────────────────────────────

    #[test]
    fn le_cadre_de_fin_se_relit_et_n_est_pas_une_operation() {
        // **LA QUINZIÈME ÉTIQUETTE N'EST PAS UN GENRE** : ce qui applique ne
        // doit jamais la prendre pour un fait.
        assert_eq!(
            GenreOperation::depuis(ETIQUETTE_DE_FIN),
            Err(Faute::Etiquette {
                lue: ETIQUETTE_DE_FIN
            })
        );
        for genre in GenreOperation::TOUS {
            assert_ne!(genre.etiquette(), ETIQUETTE_DE_FIN);
        }

        let fin = Cadre::Fin { coupe: e(4_812) };
        let mut sortie = [0_u8; OPERATION_OCTETS_MAX];
        let combien = fin.ecrire(&mut sortie);
        assert_eq!(combien, CADRE_DE_FIN_OCTETS);
        assert_eq!(sortie[0], ETIQUETTE_DE_FIN);
        assert_eq!(&sortie[1..9], &4_812_u64.to_be_bytes());
        assert_eq!(sortie[9], b'n');
        // Le bourrage derrière est nul : le tampon est réemployé.
        assert!(sortie[combien..].iter().all(|octet| *octet == 0));

        assert_eq!(
            Cadre::lire(&sortie[..combien]),
            Ok((fin, CADRE_DE_FIN_OCTETS))
        );
        // Ce qui suit n'est pas regardé : sur le fil, c'est le cadre suivant.
        assert_eq!(Cadre::lire(&sortie), Ok((fin, CADRE_DE_FIN_OCTETS)));
        // Et une opération ne sait pas le lire.
        assert_eq!(
            Operation::lire(&sortie[..combien]),
            Err(Faute::Etiquette {
                lue: ETIQUETTE_DE_FIN
            })
        );
    }

    #[test]
    fn un_cadre_de_fin_tronque_ou_a_la_racine_fausse_est_refuse() {
        let fin = Cadre::Fin { coupe: e(1) };
        let mut sortie = [0_u8; OPERATION_OCTETS_MAX];
        let combien = fin.ecrire(&mut sortie);
        assert_eq!(
            Cadre::lire(&sortie[..combien - 1]),
            Err(Faute::Tronquee {
                attendus: CADRE_DE_FIN_OCTETS,
                obtenus: combien - 1,
            })
        );
        assert_eq!(
            Cadre::lire(&[ETIQUETTE_DE_FIN]),
            Err(Faute::Tronquee {
                attendus: CADRE_DE_FIN_OCTETS,
                obtenus: 1,
            })
        );
        // La racine de coupe est un annuaire, et rien d'autre.
        let mut corrompue = sortie;
        corrompue[9] = b'm';
        assert_eq!(
            Cadre::lire(&corrompue[..combien]),
            Err(Faute::Genre {
                attendu: Genre::Annuaire,
            })
        );
    }

    #[test]
    fn un_cadre_qui_porte_une_operation_est_l_operation_meme() {
        // Le cadre d'une opération est exactement ce qu'`Operation::ecrire`
        // écrit : un seul format sur le fil, et le lecteur d'un instantané lit
        // ce que le lecteur du flux lit.
        let operation = Operation::AppareilRevoque {
            appareil: un(Genre::Appareil, 3),
        };
        let cadre = Cadre::Operation {
            estampille: e(2),
            operation,
        };
        let mut par_le_cadre = [0_u8; OPERATION_OCTETS_MAX];
        let mut par_l_operation = [0_u8; OPERATION_OCTETS_MAX];
        let combien = cadre.ecrire(&mut par_le_cadre);
        assert_eq!(operation.ecrire(e(2), &mut par_l_operation), combien);
        assert_eq!(par_le_cadre, par_l_operation);
        assert_eq!(Cadre::lire(&par_le_cadre[..combien]), Ok((cadre, combien)));
        // Et une faute d'opération remonte telle quelle.
        assert_eq!(Cadre::lire(&[0]), Err(Faute::Etiquette { lue: 0 }));
        assert_eq!(Cadre::lire(&[]), Err(Faute::Etiquette { lue: 0 }));
    }
}
