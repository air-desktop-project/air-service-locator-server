//! Le découpage d'un JWS compact : `en-tête.charge.signature`.

use crate::{Erreur, base64url};

/// Un jeton JWS compact, découpé mais pas décodé.
///
/// Tout EMPRUNTE au jeton d'origine : rien n'est copié, et les segments sont des
/// tranches de ce qu'on a reçu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Jws<'a> {
    /// Le jeton entier.
    jeton: &'a [u8],
    /// Où finit l'en-tête (position du premier point).
    fin_entete: usize,
    /// Où commence la signature (position après le second point).
    debut_signature: usize,
}

impl<'a> Jws<'a> {
    /// Découpe un JWS compact.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::PasTroisSegments`] si le jeton n'a pas exactement deux points,
    /// [`Erreur::SegmentVide`] si l'un des trois segments est vide.
    pub fn lire(jeton: &'a [u8]) -> Result<Self, Erreur> {
        let mut points = jeton.iter().enumerate().filter(|(_, o)| **o == b'.');
        let (Some((premier, _)), Some((second, _)), None) =
            (points.next(), points.next(), points.next())
        else {
            let comptes = jeton
                .iter()
                .filter(|o| **o == b'.')
                .count()
                .saturating_add(1);
            return Err(Erreur::PasTroisSegments { comptes });
        };

        let fin_entete = premier;
        let debut_signature = second.saturating_add(1);
        // Trois segments non vides : `[0..premier]`, `[premier+1..second]`,
        // `[second+1..]`. Un point en tête, en queue, ou deux collés les vide.
        if fin_entete == 0 {
            return Err(Erreur::SegmentVide { rang: 0 });
        }
        if second <= premier.saturating_add(1) {
            return Err(Erreur::SegmentVide { rang: 1 });
        }
        if debut_signature >= jeton.len() {
            return Err(Erreur::SegmentVide { rang: 2 });
        }
        Ok(Self {
            jeton,
            fin_entete,
            debut_signature,
        })
    }

    /// L'en-tête, en base64url, tel quel.
    #[must_use]
    pub fn entete_b64(&self) -> &'a [u8] {
        self.jeton.get(..self.fin_entete).unwrap_or(&[])
    }

    /// La charge, en base64url, telle quelle.
    #[must_use]
    pub fn charge_b64(&self) -> &'a [u8] {
        let debut = self.fin_entete.saturating_add(1);
        let fin = self.debut_signature.saturating_sub(1);
        self.jeton.get(debut..fin).unwrap_or(&[])
    }

    /// La signature, en base64url, telle quelle.
    #[must_use]
    pub fn signature_b64(&self) -> &'a [u8] {
        self.jeton.get(self.debut_signature..).unwrap_or(&[])
    }

    /// **CE QUE LA SIGNATURE COUVRE** : `en-tête.charge`, en base64url ASCII, tel
    /// qu'il est sur le fil (RFC 7515 §5.1).
    ///
    /// C'est cette tranche-ci, et pas les octets décodés, qu'ES256 hache. La
    /// rendre telle quelle évite d'avoir à la reconstruire — et une
    /// reconstruction qui réencoderait autrement ferait échouer toute
    /// vérification.
    #[must_use]
    pub fn signe(&self) -> &'a [u8] {
        self.jeton
            .get(..self.debut_signature.saturating_sub(1))
            .unwrap_or(&[])
    }

    /// Décode l'en-tête dans `sortie`, et rend les octets écrits.
    ///
    /// # Erreurs
    ///
    /// Celles de [`base64url::decoder`].
    pub fn decoder_entete(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        base64url::decoder(self.entete_b64(), sortie, 0, 0)
    }

    /// Décode la charge dans `sortie`, et rend les octets écrits.
    ///
    /// # Erreurs
    ///
    /// Celles de [`base64url::decoder`].
    pub fn decoder_charge(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        base64url::decoder(
            self.charge_b64(),
            sortie,
            1,
            self.fin_entete.saturating_add(1),
        )
    }

    /// Décode la signature dans `sortie`, et rend les octets écrits.
    ///
    /// # Erreurs
    ///
    /// Celles de [`base64url::decoder`].
    pub fn decoder_signature(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        base64url::decoder(self.signature_b64(), sortie, 2, self.debut_signature)
    }
}
