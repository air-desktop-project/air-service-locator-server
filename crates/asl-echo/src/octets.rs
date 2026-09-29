//! Lire et écrire des champs de longueur fixe, sans indexer ni compter.
//!
//! **Aucune arithmétique, aucun index** : un champ se prend dans un itérateur
//! sur un tableau dont la longueur a déjà été vérifiée — ou fixée par son
//! type. Un décalage calculé à la main est l'endroit où une borne s'oublie ;
//! ici, il n'y en a pas à calculer. Les assertions de compilation de chaque
//! message tiennent la somme des champs égale à sa longueur.

use core::slice::{Iter, IterMut};

/// Un curseur de lecture.
pub(crate) struct Lecteur<'a>(Iter<'a, u8>);

impl<'a> Lecteur<'a> {
    /// Sur ces octets.
    pub(crate) fn nouveau(octets: &'a [u8]) -> Self {
        Self(octets.iter())
    }

    /// Les `K` octets suivants.
    ///
    /// Le champ mène le `zip` : le curseur n'est tiré que pour une place qui
    /// existe (voir [`Ecrivain::poser`]).
    pub(crate) fn prendre<const K: usize>(&mut self) -> [u8; K] {
        let mut champ = [0_u8; K];
        for (place, octet) in champ.iter_mut().zip(&mut self.0) {
            *place = *octet;
        }
        champ
    }

    /// L'octet suivant.
    pub(crate) fn octet(&mut self) -> u8 {
        let [octet] = self.prendre::<1>();
        octet
    }

    /// Un entier de huit octets, de réseau.
    pub(crate) fn entier(&mut self) -> u64 {
        u64::from_be_bytes(self.prendre::<8>())
    }

    /// Ce qui reste est-il fait de zéros ?
    pub(crate) fn reste_nul(self) -> bool {
        self.0.as_slice().iter().all(|octet| *octet == 0)
    }
}

/// Un curseur d'écriture.
pub(crate) struct Ecrivain<'a>(IterMut<'a, u8>);

impl<'a> Ecrivain<'a> {
    /// Dans ce tampon.
    pub(crate) fn nouveau(tampon: &'a mut [u8]) -> Self {
        Self(tampon.iter_mut())
    }

    /// Pose ces octets à la suite.
    ///
    /// **La source mène le `zip`, et c'est la seule chose qui compte ici** :
    /// `zip` tire de son premier itérateur AVANT de savoir si le second est
    /// épuisé. Le curseur en premier perdait donc une place à chaque champ —
    /// ce que les vecteurs figés ont attrapé, et qu'un aller-retour par le
    /// même code n'aurait jamais vu.
    pub(crate) fn poser(&mut self, octets: &[u8]) {
        for (octet, place) in octets.iter().zip(&mut self.0) {
            *place = *octet;
        }
    }
}
