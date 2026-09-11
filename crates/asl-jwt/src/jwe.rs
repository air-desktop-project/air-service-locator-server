//! Le découpage d'un JWE compact : `en-tête.clé.iv.chiffré.étiquette`.
//!
//! Un jeton Play Integrity « standard » n'est pas un JWS nu : c'est un JWS
//! CHIFFRÉ, enveloppé dans un JWE (RFC 7516 §3). Cinq segments base64url, et le
//! premier — l'en-tête protégé — sert deux fois : il dit comment déchiffrer, et
//! il est la donnée authentifiée additionnelle du GCM.
//!
//! **Comme [`crate::Jws`], cette crate ne déchiffre rien.** Elle découpe. Le
//! déballage de la clé, le déchiffrement et la lecture de l'en-tête sont à
//! l'étage au-dessus.

use crate::{Erreur, base64url};

/// Un jeton JWE compact, découpé mais pas déchiffré.
///
/// Tout EMPRUNTE au jeton d'origine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Jwe<'a> {
    jeton: &'a [u8],
    /// Les quatre positions de point.
    points: [usize; 4],
}

impl<'a> Jwe<'a> {
    /// Découpe un JWE compact.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::PasCinqSegments`] si le jeton n'a pas exactement quatre points,
    /// [`Erreur::SegmentVide`] si l'en-tête, l'iv, le chiffré ou l'étiquette est
    /// vide. **La clé chiffrée, elle, PEUT être vide** — c'est le cas du mode
    /// `dir`, où il n'y a pas de clé à déballer —, et c'est à l'étage au-dessus
    /// de dire si ce mode est accepté.
    pub fn lire(jeton: &'a [u8]) -> Result<Self, Erreur> {
        let mut points = [0_usize; 4];
        let mut combien = 0;
        for (i, octet) in jeton.iter().enumerate() {
            if *octet == b'.' {
                if let Some(place) = points.get_mut(combien) {
                    *place = i;
                }
                combien = combien.saturating_add(1);
            }
        }
        if combien != 4 {
            return Err(Erreur::PasCinqSegments {
                comptes: combien.saturating_add(1),
            });
        }
        let jwe = Self { jeton, points };
        // L'en-tête, l'iv, le chiffré et l'étiquette ne sont pas vides ; la clé
        // (rang 1) peut l'être.
        for rang in [0, 2, 3, 4] {
            if jwe.segment(rang).is_empty() {
                return Err(Erreur::SegmentVide { rang });
            }
        }
        Ok(jwe)
    }

    /// La tranche du segment de ce rang, en base64url.
    fn segment(&self, rang: usize) -> &'a [u8] {
        let debut = match rang {
            0 => 0,
            _ => self
                .points
                .get(rang.saturating_sub(1))
                .map_or(0, |p| p.saturating_add(1)),
        };
        let fin = self.points.get(rang).copied().unwrap_or(self.jeton.len());
        self.jeton.get(debut..fin).unwrap_or(&[])
    }

    /// L'en-tête protégé, en base64url, tel quel.
    ///
    /// **IL EST LA DONNÉE AUTHENTIFIÉE DU GCM**, telle qu'écrite sur le fil
    /// (RFC 7516 §5.1) : c'est cette tranche-ci, pas les octets décodés, qui
    /// entre dans le déchiffrement. La rendre au lieu de la reconstruire évite
    /// qu'un réencodage divergent fasse échouer l'authentification.
    #[must_use]
    pub fn entete_b64(&self) -> &'a [u8] {
        self.segment(0)
    }

    /// Décode l'en-tête protégé.
    ///
    /// # Erreurs
    ///
    /// Celles de [`base64url::decoder`].
    pub fn decoder_entete(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        base64url::decoder(self.segment(0), sortie, 0, 0)
    }

    /// Décode la clé chiffrée (déballée par l'étage au-dessus).
    ///
    /// # Erreurs
    ///
    /// Celles de [`base64url::decoder`].
    pub fn decoder_cle(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        base64url::decoder(self.segment(1), sortie, 1, self.debut(1))
    }

    /// Décode l'iv.
    ///
    /// # Erreurs
    ///
    /// Celles de [`base64url::decoder`].
    pub fn decoder_iv(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        base64url::decoder(self.segment(2), sortie, 2, self.debut(2))
    }

    /// Décode le texte chiffré.
    ///
    /// # Erreurs
    ///
    /// Celles de [`base64url::decoder`].
    pub fn decoder_chiffre(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        base64url::decoder(self.segment(3), sortie, 3, self.debut(3))
    }

    /// Décode l'étiquette d'authentification.
    ///
    /// # Erreurs
    ///
    /// Celles de [`base64url::decoder`].
    pub fn decoder_etiquette(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        base64url::decoder(self.segment(4), sortie, 4, self.debut(4))
    }

    /// Où commence le segment de ce rang dans le jeton, pour situer une faute.
    fn debut(&self, rang: usize) -> usize {
        self.points
            .get(rang.saturating_sub(1))
            .map_or(0, |p| p.saturating_add(1))
    }
}
