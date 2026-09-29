//! Le jeton d'écho — `POST /v1/echo/jetons` (décision 91).
//!
//! ```text
//! version (1, 0x01) ‖ racine n-… (16) ‖ cible m-… (16) ‖ clé de la cible (32)
//!   ‖ sondeur m-… (16) ‖ clé du sondeur (32) ‖ émis_a (8) ‖ expire_a (8)
//!   ‖ signature (64)
//! signature = Ed25519, clé d'identité de la racine, sur
//!   "air-service-locator/v1/echo-jeton\x00" ‖ tout ce qui précède la signature
//! ```
//!
//! **Ce n'est pas un jeton porteur** (C10) : il nomme la clé du sondeur, et la
//! sonde qui le porte doit être signée par elle. Intercepté, il ne sert à rien
//! sans la clé privée qu'il nomme. **Il porte la clé de la cible**, signée par
//! la racine : c'est contre elle qu'`asl ping` vérifie la réponse, et c'est
//! elle que l'écho compare à la sienne — un jeton délivré avant un
//! ré-enrôlement meurt avec l'ancienne clé.

use asl_cle::{
    CLE_PUBLIQUE_OCTETS, ClePublique, CleSecrete, DomaineEcho, SIGNATURE_OCTETS, Signature,
    identifiant_de_racine,
};
use asl_id::{Genre, Identifiant};

use crate::octets::{Ecrivain, Lecteur};
use crate::{DUREE_JETON_MS, JETON_OCTETS, MauvaisGenre, Refus, VERSION_JETON, dans_la_fenetre};

/// Ce que la racine signe : tout ce qui précède la signature.
const CONTENU_OCTETS: usize = 1 + 16 + 16 + CLE_PUBLIQUE_OCTETS + 16 + CLE_PUBLIQUE_OCTETS + 8 + 8;

const _: () = assert!(
    CONTENU_OCTETS + SIGNATURE_OCTETS == JETON_OCTETS,
    "les champs du jeton ne font plus ses 193 octets"
);

/// La longueur d'un jeton en hexadécimal, tel que `POST /v1/echo/jetons` le
/// rend.
pub const JETON_HEX_OCTETS: usize = 2 * JETON_OCTETS;

/// Un jeton d'écho, lu ou émis.
///
/// **Un jeton qui existe est bien formé** — version connue, deux clés qui sont
/// des points de la courbe —, pas encore CRU : c'est [`Jeton::verifier`] qui
/// dit si l'écho doit l'accepter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Jeton {
    racine: Identifiant,
    cible: Identifiant,
    cle_cible: ClePublique,
    sondeur: Identifiant,
    cle_sondeur: ClePublique,
    emis_a: u64,
    expire_a: u64,
    signature: Signature,
}

/// Pourquoi l'écho ne croit pas un jeton.
///
/// **Tous mènent au même silence** : l'écho ne répond pas. La raison sert au
/// journal et aux essais.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusJeton {
    /// Le jeton vise une autre machine, ou cette machine sous une autre clé.
    AutreCible,
    /// Sa validité n'est pas comprise entre zéro (exclu) et
    /// [`DUREE_JETON_MS`] : aucune racine n'en délivre de tel.
    Duree,
    /// Expiré depuis plus que la tolérance d'horloge.
    Expire,
    /// Émis plus loin dans l'avenir que la tolérance d'horloge.
    PasEncoreEmis,
    /// Il nomme une racine que l'écho ne connaît pas.
    RacineInconnue,
    /// La signature ne tient pas sous la clé de la racine nommée.
    Signature,
}

impl Jeton {
    /// Émet un jeton, signé par la clé d'identité d'une racine.
    ///
    /// L'identifiant de la racine se DÉDUIT de sa clé
    /// ([`identifiant_de_racine`]) : il ne peut pas être faux. L'expiration est
    /// l'émission plus [`DUREE_JETON_MS`].
    ///
    /// # Erreurs
    ///
    /// [`MauvaisGenre`] si la cible ou le sondeur n'est pas un `m-…`.
    pub fn emettre(
        cle_racine: &CleSecrete,
        cible: Identifiant,
        cle_cible: ClePublique,
        sondeur: Identifiant,
        cle_sondeur: ClePublique,
        emis_a: u64,
    ) -> Result<Self, MauvaisGenre> {
        crate::exiger(cible, Genre::Machine)?;
        crate::exiger(sondeur, Genre::Machine)?;
        let mut jeton = Self {
            racine: identifiant_de_racine(&cle_racine.publique()),
            cible,
            cle_cible,
            sondeur,
            cle_sondeur,
            emis_a,
            expire_a: emis_a.saturating_add(DUREE_JETON_MS),
            signature: Signature::depuis_octets([0; SIGNATURE_OCTETS]),
        };
        jeton.signature = cle_racine.signer_echo(DomaineEcho::Jeton, &jeton.contenu());
        Ok(jeton)
    }

    /// Lit un jeton de ses 193 octets.
    ///
    /// # Erreurs
    ///
    /// [`Refus::Longueur`], [`Refus::VersionDeJeton`], [`Refus::CleInvalide`].
    pub fn lire(octets: &[u8]) -> Result<Self, Refus> {
        let octets: &[u8; JETON_OCTETS] = octets.try_into().map_err(|_| Refus::Longueur {
            attendue: JETON_OCTETS,
            obtenue: octets.len(),
        })?;
        Self::depuis_octets(octets)
    }

    /// Lit un jeton de ses 193 octets, la longueur tenue par le type.
    ///
    /// # Erreurs
    ///
    /// [`Refus::VersionDeJeton`], [`Refus::CleInvalide`].
    pub fn depuis_octets(octets: &[u8; JETON_OCTETS]) -> Result<Self, Refus> {
        let mut lecteur = Lecteur::nouveau(octets);
        let version = lecteur.octet();
        if version != VERSION_JETON {
            return Err(Refus::VersionDeJeton { version });
        }
        let racine = Identifiant::depuis_entropie(Genre::Annuaire, lecteur.prendre());
        let cible = Identifiant::depuis_entropie(Genre::Machine, lecteur.prendre());
        let cle_cible = cle(lecteur.prendre())?;
        let sondeur = Identifiant::depuis_entropie(Genre::Machine, lecteur.prendre());
        let cle_sondeur = cle(lecteur.prendre())?;
        let emis_a = lecteur.entier();
        let expire_a = lecteur.entier();
        let signature = Signature::depuis_octets(lecteur.prendre());
        Ok(Self {
            racine,
            cible,
            cle_cible,
            sondeur,
            cle_sondeur,
            emis_a,
            expire_a,
            signature,
        })
    }

    /// Lit un jeton de ses 386 chiffres hexadécimaux, minuscules ou
    /// majuscules — le champ `jeton` de `POST /v1/echo/jetons`.
    ///
    /// # Erreurs
    ///
    /// [`Refus::Longueur`] (comptée en chiffres), [`Refus::Hexadecimal`], puis
    /// ceux de [`Jeton::depuis_octets`].
    pub fn lire_hex(texte: &str) -> Result<Self, Refus> {
        let chiffres = texte.as_bytes();
        if chiffres.len() != JETON_HEX_OCTETS {
            return Err(Refus::Longueur {
                attendue: JETON_HEX_OCTETS,
                obtenue: chiffres.len(),
            });
        }
        let mut octets = [0_u8; JETON_OCTETS];
        let hauts = chiffres.iter().step_by(2);
        let bas = chiffres.iter().skip(1).step_by(2);
        for (place, (haut, bas)) in octets.iter_mut().zip(hauts.zip(bas)) {
            let (Some(haut), Some(bas)) = (valeur_hex(*haut), valeur_hex(*bas)) else {
                return Err(Refus::Hexadecimal);
            };
            *place = (haut << 4) | bas;
        }
        Self::depuis_octets(&octets)
    }

    /// Les 193 octets.
    #[must_use]
    pub fn octets(&self) -> [u8; JETON_OCTETS] {
        let mut sortie = [0_u8; JETON_OCTETS];
        let mut ecrivain = Ecrivain::nouveau(&mut sortie);
        ecrivain.poser(&self.contenu());
        ecrivain.poser(self.signature.octets());
        sortie
    }

    /// Les 386 chiffres hexadécimaux, en minuscules.
    #[must_use]
    pub fn hex(&self) -> JetonHex {
        const CHIFFRES: &[u8; 16] = b"0123456789abcdef";
        let mut sortie = [0_u8; JETON_HEX_OCTETS];
        let (paires, _) = sortie.as_chunks_mut::<2>();
        for (paire, octet) in paires.iter_mut().zip(self.octets()) {
            *paire = [
                CHIFFRES[usize::from(octet >> 4)],
                CHIFFRES[usize::from(octet & 0x0F)],
            ];
        }
        JetonHex(sortie)
    }

    /// La racine qui l'a signé.
    #[must_use]
    pub const fn racine(&self) -> Identifiant {
        self.racine
    }

    /// La machine visée.
    #[must_use]
    pub const fn cible(&self) -> Identifiant {
        self.cible
    }

    /// La clé de la machine visée, selon la racine — celle contre laquelle
    /// `asl ping` vérifie la réponse.
    #[must_use]
    pub const fn cle_cible(&self) -> ClePublique {
        self.cle_cible
    }

    /// La machine à qui le jeton a été délivré.
    #[must_use]
    pub const fn sondeur(&self) -> Identifiant {
        self.sondeur
    }

    /// La clé qui doit signer la sonde.
    #[must_use]
    pub const fn cle_sondeur(&self) -> ClePublique {
        self.cle_sondeur
    }

    /// L'émission, en millisecondes d'époque.
    #[must_use]
    pub const fn emis_a(&self) -> u64 {
        self.emis_a
    }

    /// L'expiration, en millisecondes d'époque.
    #[must_use]
    pub const fn expire_a(&self) -> u64 {
        self.expire_a
    }

    /// L'écho doit-il croire ce jeton ? **Hors ligne** : il n'appelle personne.
    ///
    /// Dans l'ordre (`protocole.md` §3 quater, « Qui l'écho croit ») :
    ///
    /// 1. la cible est `moi`, sous `ma_cle` ;
    /// 2. sa validité est d'au plus [`DUREE_JETON_MS`], et non nulle ;
    /// 3. `maintenant` est dans `[émis_a − 2 min, expire_a + 2 min]` ;
    /// 4. la racine nommée est connue — `cle_de_racine` rend sa clé, et c'est
    ///    l'appelant qui sait lesquelles sont embarquées ;
    /// 5. la signature tient sous cette clé.
    ///
    /// **Ce qui coûte vient en dernier** : une signature se vérifie en
    /// dizaines de microsecondes, une comparaison en quelques nanosecondes. Le
    /// débit par source, lui, a été borné AVANT d'arriver ici.
    ///
    /// # Erreurs
    ///
    /// [`RefusJeton`], la première raison qui s'applique.
    pub fn verifier(
        &self,
        moi: Identifiant,
        ma_cle: &ClePublique,
        cle_de_racine: &dyn Fn(Identifiant) -> Option<ClePublique>,
        maintenant: u64,
    ) -> Result<(), RefusJeton> {
        if self.cible != moi || self.cle_cible != *ma_cle {
            return Err(RefusJeton::AutreCible);
        }
        match self.expire_a.checked_sub(self.emis_a) {
            Some(duree) if duree > 0 && duree <= DUREE_JETON_MS => {}
            _ => return Err(RefusJeton::Duree),
        }
        if maintenant > self.expire_a && !dans_la_fenetre(maintenant, self.expire_a) {
            return Err(RefusJeton::Expire);
        }
        if maintenant < self.emis_a && !dans_la_fenetre(maintenant, self.emis_a) {
            return Err(RefusJeton::PasEncoreEmis);
        }
        let cle_racine = cle_de_racine(self.racine).ok_or(RefusJeton::RacineInconnue)?;
        if !self.signature_tient(&cle_racine) {
            return Err(RefusJeton::Signature);
        }
        Ok(())
    }

    /// La signature tient-elle sous cette clé ?
    #[must_use]
    pub fn signature_tient(&self, cle_racine: &ClePublique) -> bool {
        cle_racine.verifie_echo(DomaineEcho::Jeton, &self.contenu(), &self.signature)
    }

    /// Ce que la racine signe.
    fn contenu(&self) -> [u8; CONTENU_OCTETS] {
        let mut contenu = [0_u8; CONTENU_OCTETS];
        let mut ecrivain = Ecrivain::nouveau(&mut contenu);
        ecrivain.poser(&[VERSION_JETON]);
        ecrivain.poser(self.racine.octets());
        ecrivain.poser(self.cible.octets());
        ecrivain.poser(&self.cle_cible.octets());
        ecrivain.poser(self.sondeur.octets());
        ecrivain.poser(&self.cle_sondeur.octets());
        ecrivain.poser(&self.emis_a.to_be_bytes());
        ecrivain.poser(&self.expire_a.to_be_bytes());
        contenu
    }
}

/// Un jeton écrit en hexadécimal.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct JetonHex([u8; JETON_HEX_OCTETS]);

impl JetonHex {
    /// Le texte.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Que des chiffres ASCII : la conversion ne peut pas échouer, et un
        // échec rendrait une chaîne vide plutôt qu'une panique.
        core::str::from_utf8(&self.0).unwrap_or_default()
    }
}

impl core::fmt::Debug for JetonHex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Trente-deux octets, lus comme une clé.
fn cle(octets: [u8; CLE_PUBLIQUE_OCTETS]) -> Result<ClePublique, Refus> {
    ClePublique::depuis_octets(octets).map_err(|_| Refus::CleInvalide)
}

/// La valeur d'un chiffre hexadécimal, minuscule ou majuscule.
const fn valeur_hex(chiffre: u8) -> Option<u8> {
    match chiffre {
        b'0'..=b'9' => Some(chiffre.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(chiffre.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(chiffre.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}
