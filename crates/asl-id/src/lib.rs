//! Les identifiants **publics** d'air-service-locator : utilisateur, appareil,
//! machine, service, autorisation, annuaire.
//!
//! # Pourquoi ils sont « publics », et ce que ce mot engage
//!
//! Un identifiant de machine circule : il est posé dans le fichier de
//! configuration d'un daemon, lu par un administrateur, parfois recopié à la
//! main. Il est donc VISIBLE, et le traiter comme un secret serait bâtir sur une
//! propriété qu'il n'a pas. Ce qui autorise une opération est une clé
//! (`asl-auth`) ou une autorisation entre comptes, jamais un identifiant.
//!
//! **Il n'y a PAS d'identifiant de secret dans cette liste**, et c'est le point :
//! aucune authentification de ce produit ne repose sur un secret partagé
//! (contrainte C14). Une machine détient une paire de clés Ed25519 ; ce qui se
//! recopie à la main est un CODE D'ENRÔLEMENT à usage unique, qui vit quelques
//! minutes et n'ouvre qu'une opération.
//!
//! # La forme, arrêtée par `docs/modele.md` §2
//!
//! Un préfixe d'une lettre, un tiret, puis **26 symboles portant 128 bits** :
//! `u-` utilisateur, `a-` appareil, `m-` machine, `s-` service, `g-`
//! autorisation, `n-` annuaire.
//!
//! **L'alphabet est le base32 de Crockford**, et ce n'est pas un goût : ces
//! chaînes se recopient à la main. Crockford retire `I`, `L`, `O` et `U` — les
//! quatre que l'œil confond avec `1`, `0` et `V` — et, à la lecture, **rattrape
//! la faute** : `I` et `L` valent `1`, `O` vaut `0`. C'est la raison d'être de
//! cet alphabet, et non un détail d'encodage.
//!
//! **128 bits ne se devinent pas**, ce qui ferme l'énumération.
//!
//! # La conséquence du rattrapage, et la règle qui en découle
//!
//! Rattraper une faute de transcription veut dire que **plusieurs textes
//! désignent le même identifiant**. `m-1…` et `m-I…` sont le même.
//!
//! **UN IDENTIFIANT NE SE COMPARE DONC JAMAIS COMME UNE CHAÎNE.** Deux textes
//! égaux désignent le même identifiant, mais deux textes différents peuvent
//! aussi le désigner — et un `==` sur des chaînes conclurait à tort qu'il s'agit
//! de deux machines.
//!
//! C'est pourquoi ce module ne rend jamais de chaîne à comparer : il rend un
//! [`Identifiant`], qui porte **seize octets** et se compare sur eux. Le texte
//! n'existe qu'à l'affichage, et [`Identifiant::texte`] le rend toujours sous sa
//! forme canonique — corps en majuscules, sans ambiguïté.
//!
//! # Pourquoi cette crate est à l'étage 1
//!
//! Elle décrit une FORME et rien de plus. **Elle ne tire aucun octet d'aléa
//! elle-même** : [`Identifiant::depuis_entropie`] les reçoit en paramètre, ce
//! qui la rend éprouvable depuis un essai et la laisse hors de toute
//! entrée-sortie (contrainte C1).
//!
//! Elle est liée AUSSI BIEN par le serveur que par `asl-client`, donc par des
//! daemons tiers. D'où le `#![no_std]` : tout ce qu'on met ici, un tiers
//! l'embarque.
//!
//! # Ce que cette crate ne fait PAS, et qu'il ne faut pas y ajouter
//!
//! **Aucune comparaison en temps constant.** Un identifiant est public
//! (ci-dessus) : le comparer en temps constant protégerait une propriété qu'il
//! n'a pas, et laisserait croire qu'il en est une. C9 porte sur les RÉPONSES de
//! l'annuaire et sur les clés, pas sur ces seize octets.

#![no_std]

use core::fmt;

/// Ce qu'un identifiant désigne.
///
/// Le genre est porté par le préfixe, et il est **vérifié à la lecture** : un
/// identifiant de machine placé là où l'on attend un service est une erreur,
/// pas une valeur à interpréter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Genre {
    /// Un compte. C'est celui qu'on transmet à un ami pour qu'il vous autorise.
    Utilisateur,
    /// Un téléphone enrôlé.
    Appareil,
    /// Une machine — celle qui sert un service comme celle qui le consomme.
    Machine,
    /// Un service annoncé par un daemon.
    Service,
    /// Une autorisation entre deux comptes.
    Autorisation,
    /// Un annuaire.
    Annuaire,
}

impl Genre {
    /// La lettre qui précède le tiret.
    #[must_use]
    pub const fn prefixe(self) -> u8 {
        match self {
            Self::Utilisateur => b'u',
            Self::Appareil => b'a',
            Self::Machine => b'm',
            Self::Service => b's',
            Self::Autorisation => b'g',
            Self::Annuaire => b'n',
        }
    }

    /// Le genre désigné par une lettre, `None` si elle n'en désigne aucun.
    ///
    /// La casse est indifférente, comme pour le corps : quelqu'un qui recopie à
    /// la main ne distingue pas les deux.
    #[must_use]
    pub const fn depuis_prefixe(lettre: u8) -> Option<Self> {
        match lettre {
            b'u' | b'U' => Some(Self::Utilisateur),
            b'a' | b'A' => Some(Self::Appareil),
            b'm' | b'M' => Some(Self::Machine),
            b's' | b'S' => Some(Self::Service),
            b'g' | b'G' => Some(Self::Autorisation),
            b'n' | b'N' => Some(Self::Annuaire),
            _ => None,
        }
    }
}

/// Ce qui peut clocher dans un texte qu'on prend pour un identifiant.
///
/// Chaque variante porte de quoi **désigner la faute à un humain** : ces
/// chaînes se recopient à la main, et « identifiant invalide » n'aide personne à
/// trouver le caractère qu'il a mal lu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erreur {
    /// Le texte n'a pas les 28 octets attendus.
    Longueur {
        /// Ce qui était attendu.
        attendue: usize,
        /// Ce qui a été reçu.
        obtenue: usize,
    },
    /// La première lettre ne désigne aucun genre.
    PrefixeInconnu,
    /// Le deuxième caractère n'est pas un tiret.
    SeparateurAbsent,
    /// Le genre lu n'est pas celui qu'on attendait à cet endroit.
    GenreInattendu {
        /// Le genre exigé par l'appelant.
        attendu: Genre,
        /// Le genre réellement écrit.
        obtenu: Genre,
    },
    /// Un octet hors de l'alphabet, à cette position dans le corps (0..26).
    SymboleInvalide {
        /// La position dans le corps, pour la désigner à qui a recopié.
        position: usize,
    },
    /// Le texte est bien formé mais désigne une valeur au-delà de 128 bits.
    ///
    /// **Le corps porte 130 bits pour 128 utiles** : les deux bits en trop
    /// obligent le premier symbole à rester sous `8`. Un texte qui les emploie
    /// n'est donc pas un identifiant tronqué, c'est un texte qui n'en a jamais
    /// été un.
    Debordement,
}

impl fmt::Display for Erreur {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Longueur { attendue, obtenue } => {
                write!(f, "longueur {obtenue}, attendue {attendue}")
            }
            Self::PrefixeInconnu => f.write_str("préfixe inconnu"),
            Self::SeparateurAbsent => f.write_str("tiret manquant après le préfixe"),
            Self::GenreInattendu { attendu, obtenu } => {
                write!(f, "genre {obtenu:?} là où {attendu:?} est attendu")
            }
            Self::SymboleInvalide { position } => {
                write!(f, "caractère invalide en position {position} du corps")
            }
            Self::Debordement => f.write_str("valeur au-delà de 128 bits"),
        }
    }
}

/// Le nombre de symboles du corps.
///
/// `26 × 5 = 130` bits pour 128 utiles : deux bits de rabiot, qui contraignent
/// le premier symbole (voir [`Erreur::Debordement`]).
pub const SYMBOLES: usize = 26;

/// La longueur totale du texte, en octets : préfixe, tiret, corps.
pub const LONGUEUR: usize = 2 + SYMBOLES;

/// L'alphabet de Crockford, dans l'ordre des valeurs 0 à 31.
///
/// Ni `I`, ni `L`, ni `O` — l'œil les confond avec `1` et `0`. Ni `U`, que
/// Crockford retire pour qu'aucun tirage ne compose de mot fâcheux.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// La valeur d'un octet, ou `None` s'il n'appartient pas à l'alphabet.
///
/// **C'est ici que le rattrapage de Crockford a lieu** : `I` et `L` valent `1`,
/// `O` vaut `0`. Une faute de transcription ne coûte donc pas une machine
/// perdue — c'est la raison d'être de cet alphabet.
///
/// `U` est REFUSÉ, et non rattrapé : Crockford l'exclut de l'alphabet, et rien
/// ne dit vers quoi il faudrait le corriger.
///
/// # Pourquoi `wrapping_sub` sur un chemin qui ne peut pas déborder
///
/// Le bras du `match` borne déjà l'octet : `octet - b'0'` est exact pour
/// `b'0'..=b'9'`. Mais `arithmetic_side_effects` est `deny` dans ce workspace, et
/// **c'est voulu** — les octets viennent du réseau, et la règle ne souffre pas
/// d'exception « celle-ci est sûre », parce que la suivante ne le sera pas.
/// `wrapping_sub` dit explicitement qu'aucun débordement n'est attendu ici, et le
/// bras du `match` en est la preuve.
const fn valeur(octet: u8) -> Option<u8> {
    match octet {
        b'0'..=b'9' => Some(octet.wrapping_sub(b'0')),
        b'A'..=b'H' | b'a'..=b'h' => Some(
            octet
                .to_ascii_uppercase()
                .wrapping_sub(b'A')
                .wrapping_add(10),
        ),
        b'J' | b'j' => Some(18),
        b'K' | b'k' => Some(19),
        b'M' | b'm' => Some(20),
        b'N' | b'n' => Some(21),
        b'P' | b'p' => Some(22),
        b'Q' | b'q' => Some(23),
        b'R' | b'r' => Some(24),
        b'S' | b's' => Some(25),
        b'T' | b't' => Some(26),
        b'V' | b'v' => Some(27),
        b'W' | b'w' => Some(28),
        b'X' | b'x' => Some(29),
        b'Y' | b'y' => Some(30),
        b'Z' | b'z' => Some(31),
        // Le rattrapage de Crockford.
        b'I' | b'i' | b'L' | b'l' => Some(1),
        b'O' | b'o' => Some(0),
        _ => None,
    }
}

/// Le texte canonique d'un identifiant, sans allocation.
///
/// Rendu par [`Identifiant::texte`]. Il existe parce que cette crate est
/// `no_std` et qu'un `String` y serait impossible — mais aussi parce qu'un
/// identifiant n'a **pas** vocation à circuler sous forme de chaîne : le rendre
/// dans un type à part rappelle qu'on l'affiche, et qu'on ne le compare pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Texte([u8; LONGUEUR]);

impl Texte {
    /// Le texte, toujours valide en UTF-8 puisqu'il est ASCII par construction.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // L'alphabet et les préfixes sont ASCII ; ce tampon ne peut pas contenir
        // autre chose. `unwrap_or` plutôt qu'un `unwrap` : une crate embarquée
        // par des daemons tiers ne panique pas, même sur un chemin impossible.
        core::str::from_utf8(&self.0).unwrap_or("")
    }
}

impl fmt::Display for Texte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Un identifiant public : un genre, et seize octets.
///
/// **Il porte des octets, pas un texte**, et c'est ce qui rend la comparaison
/// juste : plusieurs textes désignent le même identifiant (voir le module).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Identifiant {
    genre: Genre,
    octets: [u8; 16],
}

impl Identifiant {
    /// Construit un identifiant à partir de seize octets d'entropie.
    ///
    /// **L'aléa vient de l'appelant**, et jamais d'ici : cette crate est à
    /// l'étage 1 et ne lit rien (contrainte C1). C'est aussi ce qui permet à un
    /// essai de fabriquer un identifiant connu d'avance.
    ///
    /// La qualité de l'aléa est la responsabilité de qui appelle. Seize octets
    /// tirés d'un compteur produiraient des identifiants devinables, et toute la
    /// non-énumérabilité de l'annuaire repose là-dessus.
    #[must_use]
    pub const fn depuis_entropie(genre: Genre, entropie: [u8; 16]) -> Self {
        Self {
            genre,
            octets: entropie,
        }
    }

    /// Ce que cet identifiant désigne.
    #[must_use]
    pub const fn genre(&self) -> Genre {
        self.genre
    }

    /// Les seize octets.
    #[must_use]
    pub const fn octets(&self) -> &[u8; 16] {
        &self.octets
    }

    /// Le texte canonique : préfixe minuscule, tiret, corps en majuscules.
    ///
    /// **Toujours la même forme pour la même valeur**, quelle que soit celle
    /// qu'on a lue. C'est ce qui rend un journal comparable à lui-même.
    #[must_use]
    pub fn texte(&self) -> Texte {
        let mut sortie = [0_u8; LONGUEUR];
        sortie[0] = self.genre.prefixe();
        sortie[1] = b'-';

        let mut accumulateur = u128::from_be_bytes(self.octets);
        // Une PLAGE plutôt qu'un compteur décrémenté : `position -= 1` est une
        // opération arithmétique, et ce workspace les refuse (voir `valeur`).
        // La plage dit la même chose sans en faire une.
        for position in (2..LONGUEUR).rev() {
            // `& 31` borne à 0..=31, donc l'indice est toujours dans l'alphabet
            // et la conversion ne peut pas tronquer. Clippy ne peut pas le
            // déduire ; on le lui dit ici, et nulle part ailleurs.
            #[allow(
                clippy::cast_possible_truncation,
                reason = "le masque `& 31` borne la valeur à 0..=31"
            )]
            let indice = (accumulateur & 31) as usize;
            sortie[position] = ALPHABET[indice];
            accumulateur >>= 5;
        }

        Texte(sortie)
    }

    /// Lit un identifiant, quel que soit son genre.
    ///
    /// La casse est indifférente, et les confusions de Crockford sont
    /// rattrapées : `I` et `L` valent `1`, `O` vaut `0`.
    ///
    /// # Erreurs
    ///
    /// Voir [`Erreur`] : longueur, préfixe, séparateur, symbole, débordement.
    pub fn analyser(texte: &str) -> Result<Self, Erreur> {
        let octets = texte.as_bytes();
        if octets.len() != LONGUEUR {
            return Err(Erreur::Longueur {
                attendue: LONGUEUR,
                obtenue: octets.len(),
            });
        }

        let genre = Genre::depuis_prefixe(octets[0]).ok_or(Erreur::PrefixeInconnu)?;
        if octets[1] != b'-' {
            return Err(Erreur::SeparateurAbsent);
        }

        let mut accumulateur: u128 = 0;
        for (position, &octet) in octets[2..].iter().enumerate() {
            let chiffre = valeur(octet).ok_or(Erreur::SymboleInvalide { position })?;
            // `checked_mul` puis `checked_add` plutôt qu'un décalage : le seul
            // cas de débordement possible est un premier symbole ≥ 8, et cette
            // forme le dit sans qu'on ait à le démontrer.
            accumulateur = accumulateur
                .checked_mul(32)
                .and_then(|valeur| valeur.checked_add(u128::from(chiffre)))
                .ok_or(Erreur::Debordement)?;
        }

        Ok(Self {
            genre,
            octets: accumulateur.to_be_bytes(),
        })
    }

    /// Lit un identifiant en **exigeant** son genre.
    ///
    /// **C'est la forme à préférer partout où le genre est connu.** Un
    /// identifiant de machine passé là où l'on attend un service doit être
    /// refusé à la lecture, et non traité comme un service introuvable — les
    /// deux fautes n'appellent pas la même correction chez qui les lit.
    ///
    /// # Erreurs
    ///
    /// Celles d'[`Identifiant::analyser`], plus [`Erreur::GenreInattendu`].
    pub fn analyser_genre(attendu: Genre, texte: &str) -> Result<Self, Erreur> {
        let identifiant = Self::analyser(texte)?;
        if identifiant.genre != attendu {
            return Err(Erreur::GenreInattendu {
                attendu,
                obtenu: identifiant.genre,
            });
        }
        Ok(identifiant)
    }
}

impl fmt::Display for Identifiant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.texte().as_str())
    }
}

/// `Debug` rend le texte canonique, et non les seize octets.
///
/// Un tableau d'octets dans un message d'essai en échec ne se rattache à rien ;
/// le texte, si — c'est celui qu'on lira dans un journal ou dans un fichier de
/// configuration.
impl fmt::Debug for Identifiant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identifiant({})", self.texte())
    }
}
