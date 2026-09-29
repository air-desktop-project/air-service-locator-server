//! La réponse de l'écho, et ce que le sondeur en vérifie.
//!
//! ```text
//! 0x0A ‖ 0x81 ‖ défi (16) ‖ machine m-… (16) ‖ adresse observée du sondeur (18)
//!      ‖ sondeur (16) ‖ signature (64)
//! signature = Ed25519, clé de la machine, sur
//!   "air-service-locator/v1/echo-reponse\x00" ‖ défi ‖ machine ‖ adresse observée ‖ sondeur
//! ```
//!
//! **Ce que la réponse signe, et pourquoi** (décision 90 ; E3) : le défi fait
//! la fraîcheur ; le `m-…` dit qui répond ; l'adresse observée dit d'où l'écho
//! a vu la sonde — un relais qui rejouerait la réponse sur un autre chemin se
//! trahirait ; l'identité du sondeur fait qu'une preuve obtenue par l'un ne se
//! présente pas comme faite pour un autre. **Pas l'heure** : le défi suffit,
//! et elle dirait l'horloge de la machine à qui l'interroge.
//!
//! **Le sondeur est seize octets, sans genre** : un `n-…` pour une sonde
//! d'annuaire, un `m-…` pour `asl ping`. Le genre ne voyage pas ; c'est le
//! sondeur qui sait qui il est, et il compare ses propres seize octets.

use asl_cle::{ClePublique, CleSecrete, DomaineEcho, SIGNATURE_OCTETS, Signature};
use asl_id::{Genre, Identifiant};

use crate::octets::{Ecrivain, Lecteur};
use crate::{
    ADRESSE_OCTETS, Adresse, DEFI_OCTETS, DefiEcho, GENRE_REPONSE, MauvaisGenre, REPONSE_OCTETS,
    Refus, VERSION, lire_en_tete,
};

/// Ce que la machine signe.
const CONTENU_OCTETS: usize = DEFI_OCTETS + 16 + ADRESSE_OCTETS + 16;

const _: () = assert!(
    2 + CONTENU_OCTETS + SIGNATURE_OCTETS == REPONSE_OCTETS,
    "les champs de la réponse ne font plus ses 132 octets"
);

/// Une réponse d'écho.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reponse {
    defi: DefiEcho,
    machine: Identifiant,
    adresse: Adresse,
    sondeur: [u8; 16],
    signature: Signature,
}

/// Ce que le sondeur conclut d'une réponse bien formée qui ne prouve pas ce
/// qu'il attendait.
///
/// **Les raisons ne se valent pas**, et `asl ping` ne les dit pas pareil
/// (`protocole.md` §3 quater) : un autre défi ou un autre sondeur est une
/// réponse qui ne lui est pas destinée — on l'ignore et l'on attend ; une
/// autre machine ou une signature qui ne tient pas, c'est **quelqu'un d'autre
/// qui répond à cette adresse** — l'état `autre_cle`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusReponse {
    /// Ce n'est pas la réponse à CETTE sonde.
    AutreDefi,
    /// La réponse a été faite pour un autre sondeur.
    AutreSondeur,
    /// Une autre machine répond.
    AutreMachine,
    /// La signature ne tient pas sous la clé attendue.
    Signature,
}

impl Reponse {
    /// Compose et signe une réponse.
    ///
    /// L'écho passe d'ordinaire par
    /// [`SondeAcceptee::repondre`](crate::SondeAcceptee::repondre), qui ne
    /// peut pas se tromper de genre ; ceci sert à qui compose sans sonde —
    /// un essai, un banc.
    ///
    /// # Erreurs
    ///
    /// [`MauvaisGenre`] si `machine` n'est pas un `m-…`, ou `sondeur` ni un
    /// `n-…` ni un `m-…`.
    pub fn signer(
        defi: DefiEcho,
        machine: Identifiant,
        adresse: Adresse,
        sondeur: Identifiant,
        cle_machine: &CleSecrete,
    ) -> Result<Self, MauvaisGenre> {
        crate::exiger(machine, Genre::Machine)?;
        if !matches!(sondeur.genre(), Genre::Annuaire | Genre::Machine) {
            return Err(MauvaisGenre {
                obtenu: sondeur.genre(),
            });
        }
        Ok(Self::composer(defi, machine, adresse, sondeur, cle_machine))
    }

    /// Compose et signe, les genres déjà tenus par l'appelant.
    pub(crate) fn composer(
        defi: DefiEcho,
        machine: Identifiant,
        adresse: Adresse,
        sondeur: Identifiant,
        cle_machine: &CleSecrete,
    ) -> Self {
        let mut reponse = Self {
            defi,
            machine,
            adresse,
            sondeur: *sondeur.octets(),
            signature: Signature::depuis_octets([0; SIGNATURE_OCTETS]),
        };
        reponse.signature = cle_machine.signer_echo(DomaineEcho::Reponse, &reponse.contenu());
        reponse
    }

    /// Lit une réponse.
    ///
    /// # Erreurs
    ///
    /// [`Refus`] : l'en-tête, la longueur, une adresse au port nul.
    pub fn lire(datagramme: &[u8]) -> Result<Self, Refus> {
        lire_en_tete(datagramme, GENRE_REPONSE, REPONSE_OCTETS)?;
        let mut lecteur = Lecteur::nouveau(datagramme);
        let _en_tete: [u8; 2] = lecteur.prendre();
        let defi = DefiEcho::depuis_octets(lecteur.prendre());
        let machine = Identifiant::depuis_entropie(Genre::Machine, lecteur.prendre());
        let adresse = Adresse::depuis_octets(&lecteur.prendre())?;
        let sondeur = lecteur.prendre();
        let signature = Signature::depuis_octets(lecteur.prendre());
        Ok(Self {
            defi,
            machine,
            adresse,
            sondeur,
            signature,
        })
    }

    /// Les 132 octets du fil.
    #[must_use]
    pub fn octets(&self) -> [u8; REPONSE_OCTETS] {
        let mut sortie = [0_u8; REPONSE_OCTETS];
        let mut ecrivain = Ecrivain::nouveau(&mut sortie);
        ecrivain.poser(&[VERSION, GENRE_REPONSE]);
        ecrivain.poser(&self.contenu());
        ecrivain.poser(self.signature.octets());
        sortie
    }

    /// Le défi auquel elle répond.
    #[must_use]
    pub const fn defi(&self) -> DefiEcho {
        self.defi
    }

    /// La machine qui dit répondre.
    #[must_use]
    pub const fn machine(&self) -> Identifiant {
        self.machine
    }

    /// L'adresse sous laquelle l'écho a vu la sonde — l'adresse réflexive du
    /// sondeur, signée.
    #[must_use]
    pub const fn adresse(&self) -> Adresse {
        self.adresse
    }

    /// Les seize octets du sondeur pour qui elle a été faite.
    #[must_use]
    pub const fn sondeur(&self) -> &[u8; 16] {
        &self.sondeur
    }

    /// Cette réponse prouve-t-elle ce que le sondeur attendait ?
    ///
    /// 1. le défi est le sien ;
    /// 2. le sondeur est lui ;
    /// 3. la machine est celle qu'il visait ;
    /// 4. la signature tient sous `cle` — celle que l'annuaire tient pour la
    ///    machine, ou celle que le jeton porte.
    ///
    /// # Erreurs
    ///
    /// [`RefusReponse`], la première raison qui s'applique.
    pub fn verifier(
        &self,
        defi: &DefiEcho,
        machine: Identifiant,
        sondeur: Identifiant,
        cle: &ClePublique,
    ) -> Result<(), RefusReponse> {
        if self.defi != *defi {
            return Err(RefusReponse::AutreDefi);
        }
        if self.sondeur != *sondeur.octets() {
            return Err(RefusReponse::AutreSondeur);
        }
        if self.machine != machine {
            return Err(RefusReponse::AutreMachine);
        }
        if !self.signature_tient(cle) {
            return Err(RefusReponse::Signature);
        }
        Ok(())
    }

    /// La signature tient-elle sous cette clé ?
    #[must_use]
    pub fn signature_tient(&self, cle_machine: &ClePublique) -> bool {
        cle_machine.verifie_echo(DomaineEcho::Reponse, &self.contenu(), &self.signature)
    }

    /// Ce que la machine signe.
    fn contenu(&self) -> [u8; CONTENU_OCTETS] {
        let mut contenu = [0_u8; CONTENU_OCTETS];
        let mut ecrivain = Ecrivain::nouveau(&mut contenu);
        ecrivain.poser(self.defi.octets());
        ecrivain.poser(self.machine.octets());
        ecrivain.poser(&self.adresse.octets());
        ecrivain.poser(&self.sondeur);
        contenu
    }
}
