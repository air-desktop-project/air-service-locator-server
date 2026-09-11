//! Le lecteur CBOR, borné, sans allocation, et volontairement incomplet.
//!
//! # CE QU'IL SERT, ET RIEN D'AUTRE
//!
//! Cinq types majeurs sur huit : entier non signé (0), chaîne d'octets (2),
//! chaîne de texte (3), tableau (4), carte (5). Les trois autres — entier
//! négatif (1), étiquette (6), valeur simple et flottant (7) — sont REFUSÉS,
//! pas ignorés.
//!
//! Un objet d'App Attest n'en emploie aucun. Les servir, ce serait écrire du
//! code que rien n'exerce, sur le chemin qui décide d'un accès.
//!
//! # IL N'ALLOUE PAS, DONC IL NE CONSTRUIT PAS D'ARBRE
//!
//! [`Lecteur`] est un CURSEUR. `valeur()` lit UNE tête et avance ; pour un
//! tableau ou une carte il rend le NOMBRE d'éléments, et c'est à l'appelant de
//! les lire. Rendre un arbre demanderait un tas, et ce dépôt lit ses grammaires
//! sans en avoir un.
//!
//! # CE QUI EST REFUSÉ, ET POURQUOI CHAQUE REFUS A SON NOM
//!
//! Les fautes ne sont pas fondues dans un « mal formé » unique. Ce lecteur
//! lira LE PREMIER objet d'attestation réel que ce produit verra ; le jour où il
//! le refuse, la question sera « quelle règle a mordu », et un message unique ne
//! répondrait pas.
//!
//! La plus discutable est [`Erreur::EncodageNonMinimal`] : l'encodage canonique
//! de RFC 8949 §4.2.1 impose la forme la plus courte, et CTAP2 — que suit
//! l'objet d'Apple — l'impose aussi. **Mais je ne l'ai jamais vérifié sur une
//! capture réelle.** Si un vrai appareil se faisait refuser ici, la faute
//! nommerait la règle, et il suffirait de la lever.

use crate::Erreur;

/// La plus profonde imbrication qu'un objet d'attestation demande.
///
/// L'objet d'Apple en emploie trois : la carte du dessus, la carte `attStmt`,
/// le tableau `x5c`. Huit laisse de la marge sans laisser de porte.
///
/// **SANS CETTE BORNE, LA PILE EST LA BORNE.**
pub const PROFONDEUR_MAX: usize = 8;

/// La plus grande longueur qu'une tête puisse annoncer.
///
/// Une chaîne de certificats tient très largement dedans. Au-delà, on n'a plus
/// affaire à une attestation, et il vaut mieux le dire tout de suite que de
/// laisser la lecture s'épuiser octet par octet.
pub const LONGUEUR_MAX: u64 = 1 << 20;

/// Une valeur CBOR lue, telle qu'elle est dans les octets.
///
/// Elle EMPRUNTE : rien n'est copié, et les tranches vivent aussi longtemps que
/// les octets d'origine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Valeur<'a> {
    /// Type majeur 0 — un entier non signé.
    Entier(u64),
    /// Type majeur 2 — une chaîne d'octets.
    Octets(&'a [u8]),
    /// Type majeur 3 — une chaîne de texte, UTF-8 déjà validé.
    Texte(&'a str),
    /// Type majeur 4 — un tableau, et le nombre d'éléments QUI SUIVENT.
    ///
    /// Les éléments ne sont pas lus : l'appelant les lit, ou les saute.
    Tableau(usize),
    /// Type majeur 5 — une carte, et le nombre de COUPLES qui suivent.
    Carte(usize),
}

/// Un curseur sur des octets CBOR.
#[derive(Debug, Clone)]
pub struct Lecteur<'a> {
    octets: &'a [u8],
    position: usize,
}

impl<'a> Lecteur<'a> {
    /// Pose un curseur au début de ces octets.
    #[must_use]
    pub const fn nouveau(octets: &'a [u8]) -> Self {
        Self {
            octets,
            position: 0,
        }
    }

    /// Où en est la lecture.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.position
    }

    /// Combien d'octets restent à lire.
    #[must_use]
    pub const fn restants(&self) -> usize {
        self.octets.len().saturating_sub(self.position)
    }

    /// Refuse s'il reste quoi que ce soit.
    ///
    /// **À APPELER APRÈS AVOIR LU L'OBJET.** Des octets en trop derrière un
    /// objet bien formé, c'est la place exacte où l'on glisse une seconde
    /// attestation que le vérificateur ne regardera pas.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::DonneesEnTrop`] s'il reste des octets.
    pub const fn rien_de_plus(&self) -> Result<(), Erreur> {
        if self.restants() == 0 {
            Ok(())
        } else {
            Err(Erreur::DonneesEnTrop {
                position: self.position,
            })
        }
    }

    /// Lit l'argument d'une tête : l'entier qu'elle porte, quelle que soit la
    /// largeur sur laquelle il est écrit.
    ///
    /// **ELLE NE CONNAÎT PAS LE TYPE MAJEUR**, et c'est voulu : le type se
    /// refuse AVANT qu'on lise l'argument, sinon un flottant — dont
    /// l'information additionnelle 27 ne veut pas dire « huit octets d'entier »
    /// — se ferait refuser pour « encodage non minimal ». La faute nommerait
    /// alors une règle qui n'a rien à voir, et c'est exactement ce qu'un essai
    /// sur les graines a attrapé.
    fn argument(&mut self, info: u8, debut: usize) -> Result<u64, Erreur> {
        match info {
            0..=23 => Ok(u64::from(info)),
            24 => self.mot(1, debut),
            25 => self.mot(2, debut),
            26 => self.mot(4, debut),
            27 => self.mot(8, debut),
            31 => Err(Erreur::LongueurIndefinie { position: debut }),
            _ => Err(Erreur::EnteteReserve { position: debut }),
        }
    }

    /// Lit un entier gros-boutien de `combien` octets, et exige la forme
    /// la plus courte.
    fn mot(&mut self, combien: usize, debut: usize) -> Result<u64, Erreur> {
        let tranche = self.tranche(combien, debut)?;
        let mut brut = 0_u64;
        for octet in tranche {
            brut = brut.wrapping_shl(8) | u64::from(*octet);
        }
        if brut < minimum(combien) {
            return Err(Erreur::EncodageNonMinimal { position: debut });
        }
        Ok(brut)
    }

    /// Prend `combien` octets et avance.
    fn tranche(&mut self, combien: usize, debut: usize) -> Result<&'a [u8], Erreur> {
        let fin = self.position.saturating_add(combien);
        let tranche = self
            .octets
            .get(self.position..fin)
            .ok_or(Erreur::Tronque { position: debut })?;
        self.position = fin;
        Ok(tranche)
    }

    /// Une longueur d'octets ou de texte, bornée.
    fn longueur(&self, brut: u64, debut: usize) -> Result<usize, Erreur> {
        if brut > LONGUEUR_MAX {
            return Err(Erreur::LongueurDemesuree {
                annoncee: brut,
                position: debut,
            });
        }
        Ok(usize::try_from(brut).unwrap_or(usize::MAX))
    }

    /// Un nombre d'éléments de conteneur.
    ///
    /// Il est borné par ce qui RESTE À LIRE : le plus petit élément CBOR tient
    /// en un octet, donc un tableau qui en annonce plus qu'il ne reste d'octets
    /// est déjà tronqué. Sans cela, un en-tête de cinq octets ferait tourner
    /// l'appelant un million de fois pour rien.
    fn elements(&self, brut: u64, debut: usize) -> Result<usize, Erreur> {
        let combien = self.longueur(brut, debut)?;
        if combien > self.restants() {
            return Err(Erreur::Tronque { position: debut });
        }
        Ok(combien)
    }

    /// Lit une valeur, quelle qu'elle soit.
    ///
    /// # Erreurs
    ///
    /// Toute [`Erreur`] de grammaire.
    pub fn valeur(&mut self) -> Result<Valeur<'a>, Erreur> {
        let debut = self.position;
        let premier = *self
            .octets
            .get(debut)
            .ok_or(Erreur::Tronque { position: debut })?;
        self.position = debut.saturating_add(1);
        let majeur = premier >> 5;
        // LE TYPE SE REFUSE AVANT QU'ON LISE L'ARGUMENT. Voir `argument`.
        if !matches!(majeur, 0 | 2..=5) {
            return Err(Erreur::TypeRefuse {
                majeur,
                position: debut,
            });
        }
        let brut = self.argument(premier & 0x1f, debut)?;
        match majeur {
            0 => Ok(Valeur::Entier(brut)),
            2 => {
                let combien = self.longueur(brut, debut)?;
                Ok(Valeur::Octets(self.tranche(combien, debut)?))
            }
            3 => {
                let combien = self.longueur(brut, debut)?;
                let tranche = self.tranche(combien, debut)?;
                let texte = core::str::from_utf8(tranche)
                    .map_err(|_| Erreur::TexteInvalide { position: debut })?;
                Ok(Valeur::Texte(texte))
            }
            4 => Ok(Valeur::Tableau(self.elements(brut, debut)?)),
            // Le seul qui reste : 5, la carte.
            _ => Ok(Valeur::Carte(self.elements(brut, debut)?)),
        }
    }

    /// Lit un entier, et refuse toute autre valeur.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::PasLeBonType`] si ce n'en est pas un.
    pub fn entier(&mut self) -> Result<u64, Erreur> {
        let debut = self.position;
        match self.valeur()? {
            Valeur::Entier(brut) => Ok(brut),
            _ => Err(Erreur::PasLeBonType { position: debut }),
        }
    }

    /// Lit une chaîne d'octets, et refuse toute autre valeur.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::PasLeBonType`] si ce n'en est pas une.
    pub fn octets(&mut self) -> Result<&'a [u8], Erreur> {
        let debut = self.position;
        match self.valeur()? {
            Valeur::Octets(tranche) => Ok(tranche),
            _ => Err(Erreur::PasLeBonType { position: debut }),
        }
    }

    /// Lit une chaîne de texte, et refuse toute autre valeur.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::PasLeBonType`] si ce n'en est pas une.
    pub fn texte(&mut self) -> Result<&'a str, Erreur> {
        let debut = self.position;
        match self.valeur()? {
            Valeur::Texte(texte) => Ok(texte),
            _ => Err(Erreur::PasLeBonType { position: debut }),
        }
    }

    /// Ouvre un tableau et rend le nombre d'éléments qui suivent.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::PasLeBonType`] si ce n'en est pas un.
    pub fn tableau(&mut self) -> Result<usize, Erreur> {
        let debut = self.position;
        match self.valeur()? {
            Valeur::Tableau(combien) => Ok(combien),
            _ => Err(Erreur::PasLeBonType { position: debut }),
        }
    }

    /// Ouvre une carte et rend le nombre de COUPLES qui suivent.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::PasLeBonType`] si ce n'en est pas une.
    pub fn carte(&mut self) -> Result<usize, Erreur> {
        let debut = self.position;
        match self.valeur()? {
            Valeur::Carte(combien) => Ok(combien),
            _ => Err(Erreur::PasLeBonType { position: debut }),
        }
    }

    /// Saute une valeur entière, conteneurs compris.
    ///
    /// C'est ce dont on a besoin pour ignorer une clé inconnue sans la
    /// comprendre — et c'est le seul endroit où la profondeur compte.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TropProfond`] au-delà de [`PROFONDEUR_MAX`], et toute erreur
    /// de grammaire rencontrée en chemin.
    pub fn sauter(&mut self) -> Result<(), Erreur> {
        self.sauter_a(0)
    }

    fn sauter_a(&mut self, profondeur: usize) -> Result<(), Erreur> {
        let debut = self.position;
        if profondeur >= PROFONDEUR_MAX {
            return Err(Erreur::TropProfond { position: debut });
        }
        let dessous = profondeur.saturating_add(1);
        match self.valeur()? {
            Valeur::Entier(_) | Valeur::Octets(_) | Valeur::Texte(_) => Ok(()),
            Valeur::Tableau(combien) => {
                for _ in 0..combien {
                    self.sauter_a(dessous)?;
                }
                Ok(())
            }
            Valeur::Carte(combien) => {
                for _ in 0..combien {
                    self.sauter_a(dessous)?;
                    self.sauter_a(dessous)?;
                }
                Ok(())
            }
        }
    }
}

/// La plus petite valeur qu'une tête de `combien` octets ait le droit de
/// porter. En dessous, une tête plus courte disait la même chose.
const fn minimum(combien: usize) -> u64 {
    match combien {
        1 => 24,
        2 => 0x100,
        4 => 0x1_0000,
        _ => 0x1_0000_0000,
    }
}
