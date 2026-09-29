//! Les deux sondes — celle de l'annuaire, celle d'`asl ping` —, et ce que
//! l'écho en accepte.
//!
//! ```text
//! 0x0A ‖ 0x01 ‖ défi (16) ‖ annuaire n-… (16) ‖ cible m-… (16)
//!      ‖ émise_a (8, millisecondes d'époque) ‖ signature (64) ‖ zéros jusqu'à 384
//! signature = Ed25519, clé d'identité de l'annuaire, sur
//!   "air-service-locator/v1/echo-sonde-annuaire\x00" ‖ tout ce qui précède la signature
//!
//! 0x0A ‖ 0x02 ‖ défi (16) ‖ jeton (193) ‖ signature du sondeur (64) ‖ zéros jusqu'à 384
//! signature du sondeur = Ed25519, clé de la machine qui sonde, sur
//!   "air-service-locator/v1/echo-sonde\x00" ‖ défi ‖ jeton
//! ```
//!
//! **Tout le reste : le silence.** Un refus n'est jamais renvoyé au fil ; vu
//! du dehors, un écho est un port UDP qui ne répond pas, comme mille autres.

use core::net::SocketAddr;

use asl_cle::{ClePublique, CleSecrete, DomaineEcho, SIGNATURE_OCTETS, Signature};
use asl_id::{Genre, Identifiant};

use crate::jeton::{Jeton, RefusJeton};
use crate::octets::{Ecrivain, Lecteur};
use crate::reponse::Reponse;
use crate::{
    Adresse, DEFI_OCTETS, DefiEcho, GENRE_SONDE_ANNUAIRE, GENRE_SONDE_JETON, JETON_OCTETS,
    MauvaisGenre, REQUETE_OCTETS, Refus, VERSION, dans_la_fenetre, lire_en_tete,
};

/// Ce que l'annuaire signe : l'en-tête et tout ce qui précède la signature.
const CONTENU_ANNUAIRE_OCTETS: usize = 2 + DEFI_OCTETS + 16 + 16 + 8;

/// Ce que le sondeur signe : le défi et le jeton.
const CONTENU_JETON_OCTETS: usize = DEFI_OCTETS + JETON_OCTETS;

const _: () = assert!(
    CONTENU_ANNUAIRE_OCTETS + SIGNATURE_OCTETS <= REQUETE_OCTETS,
    "la sonde d'annuaire ne tient plus dans une requête"
);
const _: () = assert!(
    2 + CONTENU_JETON_OCTETS + SIGNATURE_OCTETS <= REQUETE_OCTETS,
    "la sonde munie d'un jeton ne tient plus dans une requête"
);

/// La sonde d'un annuaire — celui qui tient le bail de l'écho, ou une racine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SondeAnnuaire {
    defi: DefiEcho,
    annuaire: Identifiant,
    cible: Identifiant,
    emise_a: u64,
    signature: Signature,
}

/// La sonde d'`asl ping`, munie d'un jeton.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SondeJeton {
    defi: DefiEcho,
    jeton: Jeton,
    signature: Signature,
}

/// Pourquoi l'écho se tait devant une sonde bien formée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusSonde {
    /// La sonde vise une autre machine.
    AutreCible,
    /// L'annuaire qui signe n'est ni celui du bail, ni une racine embarquée.
    AnnuaireInconnu,
    /// La signature de l'annuaire ne tient pas.
    Signature,
    /// **Une sonde d'annuaire AUTHENTIQUE, datée hors de la fenêtre** : c'est
    /// l'horloge de cette machine qui dérive, et `asl echo` le dit — la
    /// signature a tenu, donc ce n'est pas un inconnu qui ment sur l'heure.
    HorsFenetre,
    /// Le jeton n'est pas cru.
    Jeton(RefusJeton),
    /// La sonde n'est pas signée par la clé que le jeton nomme.
    SignatureDuSondeur,
}

/// Une sonde que l'écho a acceptée : il doit y répondre.
///
/// **Le défi n'a pas encore été confronté à la mémoire des défis vus** — c'est
/// un état, tenu par qui écoute. Une sonde acceptée dont le défi a déjà servi
/// dans les deux dernières minutes se tait, comme les autres.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SondeAcceptee {
    defi: DefiEcho,
    moi: Identifiant,
    sondeur: Identifiant,
}

impl SondeAcceptee {
    /// Le défi du sondeur — celui que la mémoire anti-rejeu retient.
    #[must_use]
    pub const fn defi(&self) -> DefiEcho {
        self.defi
    }

    /// Qui a sondé : le `n-…` de l'annuaire, ou le `m-…` du porteur du jeton.
    #[must_use]
    pub const fn sondeur(&self) -> Identifiant {
        self.sondeur
    }

    /// La réponse, signée par la clé de cette machine, pour la source d'où la
    /// sonde est venue.
    ///
    /// **Elle ne peut pas échouer** : la sonde n'a été acceptée que si elle
    /// visait cette machine, et son sondeur est un `n-…` ou un `m-…` par
    /// construction.
    #[must_use]
    pub fn repondre(&self, source: SocketAddr, ma_cle: &CleSecrete) -> Reponse {
        Reponse::composer(
            self.defi,
            self.moi,
            Adresse::depuis_source(source),
            self.sondeur,
            ma_cle,
        )
    }
}

impl SondeAnnuaire {
    /// Compose et signe la sonde d'un annuaire.
    ///
    /// `cle_annuaire` est la clé d'IDENTITÉ de l'annuaire, et `annuaire` le
    /// `n-…` qu'elle lui donne ; `emise_a` est l'heure de l'annuaire.
    ///
    /// # Erreurs
    ///
    /// [`MauvaisGenre`] si `annuaire` n'est pas un `n-…` ou `cible` pas un
    /// `m-…`.
    pub fn signer(
        defi: DefiEcho,
        annuaire: Identifiant,
        cible: Identifiant,
        emise_a: u64,
        cle_annuaire: &CleSecrete,
    ) -> Result<Self, MauvaisGenre> {
        crate::exiger(annuaire, Genre::Annuaire)?;
        crate::exiger(cible, Genre::Machine)?;
        let mut sonde = Self {
            defi,
            annuaire,
            cible,
            emise_a,
            signature: Signature::depuis_octets([0; SIGNATURE_OCTETS]),
        };
        sonde.signature = cle_annuaire.signer_echo(DomaineEcho::SondeAnnuaire, &sonde.contenu());
        Ok(sonde)
    }

    /// Lit une sonde d'annuaire.
    ///
    /// # Erreurs
    ///
    /// [`Refus`] : l'en-tête, la longueur, le bourrage.
    pub fn lire(datagramme: &[u8]) -> Result<Self, Refus> {
        lire_en_tete(datagramme, GENRE_SONDE_ANNUAIRE, REQUETE_OCTETS)?;
        let mut lecteur = Lecteur::nouveau(datagramme);
        let _en_tete: [u8; 2] = lecteur.prendre();
        let defi = DefiEcho::depuis_octets(lecteur.prendre());
        let annuaire = Identifiant::depuis_entropie(Genre::Annuaire, lecteur.prendre());
        let cible = Identifiant::depuis_entropie(Genre::Machine, lecteur.prendre());
        let emise_a = lecteur.entier();
        let signature = Signature::depuis_octets(lecteur.prendre());
        if !lecteur.reste_nul() {
            return Err(Refus::Bourrage);
        }
        Ok(Self {
            defi,
            annuaire,
            cible,
            emise_a,
            signature,
        })
    }

    /// Les 384 octets du fil.
    #[must_use]
    pub fn octets(&self) -> [u8; REQUETE_OCTETS] {
        let mut sortie = [0_u8; REQUETE_OCTETS];
        let mut ecrivain = Ecrivain::nouveau(&mut sortie);
        ecrivain.poser(&self.contenu());
        ecrivain.poser(self.signature.octets());
        sortie
    }

    /// Le défi.
    #[must_use]
    pub const fn defi(&self) -> DefiEcho {
        self.defi
    }

    /// L'annuaire qui sonde.
    #[must_use]
    pub const fn annuaire(&self) -> Identifiant {
        self.annuaire
    }

    /// La machine visée.
    #[must_use]
    pub const fn cible(&self) -> Identifiant {
        self.cible
    }

    /// L'heure de l'annuaire à l'émission, en millisecondes d'époque.
    #[must_use]
    pub const fn emise_a(&self) -> u64 {
        self.emise_a
    }

    /// L'écho doit-il répondre ? **Hors ligne.**
    ///
    /// 1. la cible est `moi` ;
    /// 2. l'annuaire est connu — `cle_d_annuaire` rend la clé de l'annuaire
    ///    du bail ou d'une racine embarquée, et rien pour un autre ;
    /// 3. la signature tient sous cette clé ;
    /// 4. `émise_a` est à moins de deux minutes de `maintenant`.
    ///
    /// **La date vient APRÈS la signature**, et c'est le seul écart à la
    /// règle « ce qui coûte en dernier » : un refus pour la date doit vouloir
    /// dire que l'horloge de cette machine dérive — ce qui se dit —, jamais
    /// qu'un inconnu a écrit une date fausse.
    ///
    /// # Erreurs
    ///
    /// [`RefusSonde`], la première raison qui s'applique.
    pub fn accepter(
        &self,
        moi: Identifiant,
        cle_d_annuaire: &dyn Fn(Identifiant) -> Option<ClePublique>,
        maintenant: u64,
    ) -> Result<SondeAcceptee, RefusSonde> {
        if self.cible != moi {
            return Err(RefusSonde::AutreCible);
        }
        let cle = cle_d_annuaire(self.annuaire).ok_or(RefusSonde::AnnuaireInconnu)?;
        if !self.signature_tient(&cle) {
            return Err(RefusSonde::Signature);
        }
        if !dans_la_fenetre(self.emise_a, maintenant) {
            return Err(RefusSonde::HorsFenetre);
        }
        Ok(SondeAcceptee {
            defi: self.defi,
            moi,
            sondeur: self.annuaire,
        })
    }

    /// La signature tient-elle sous cette clé ?
    #[must_use]
    pub fn signature_tient(&self, cle_annuaire: &ClePublique) -> bool {
        cle_annuaire.verifie_echo(DomaineEcho::SondeAnnuaire, &self.contenu(), &self.signature)
    }

    /// Ce que l'annuaire signe.
    fn contenu(&self) -> [u8; CONTENU_ANNUAIRE_OCTETS] {
        let mut contenu = [0_u8; CONTENU_ANNUAIRE_OCTETS];
        let mut ecrivain = Ecrivain::nouveau(&mut contenu);
        ecrivain.poser(&[VERSION, GENRE_SONDE_ANNUAIRE]);
        ecrivain.poser(self.defi.octets());
        ecrivain.poser(self.annuaire.octets());
        ecrivain.poser(self.cible.octets());
        ecrivain.poser(&self.emise_a.to_be_bytes());
        contenu
    }
}

impl SondeJeton {
    /// Compose et signe la sonde d'`asl ping`.
    ///
    /// `cle_sondeur` est la clé de la machine qui sonde — celle que le jeton
    /// nomme. **Rien ne le vérifie ici** : une sonde signée d'une autre clé se
    /// compose, et l'écho la taira.
    #[must_use]
    pub fn signer(defi: DefiEcho, jeton: Jeton, cle_sondeur: &CleSecrete) -> Self {
        let mut sonde = Self {
            defi,
            jeton,
            signature: Signature::depuis_octets([0; SIGNATURE_OCTETS]),
        };
        sonde.signature = cle_sondeur.signer_echo(DomaineEcho::Sonde, &sonde.contenu());
        sonde
    }

    /// Lit une sonde munie d'un jeton.
    ///
    /// # Erreurs
    ///
    /// [`Refus`] : l'en-tête, la longueur, le jeton, le bourrage.
    pub fn lire(datagramme: &[u8]) -> Result<Self, Refus> {
        lire_en_tete(datagramme, GENRE_SONDE_JETON, REQUETE_OCTETS)?;
        let mut lecteur = Lecteur::nouveau(datagramme);
        let _en_tete: [u8; 2] = lecteur.prendre();
        let defi = DefiEcho::depuis_octets(lecteur.prendre());
        let jeton = Jeton::depuis_octets(&lecteur.prendre())?;
        let signature = Signature::depuis_octets(lecteur.prendre());
        if !lecteur.reste_nul() {
            return Err(Refus::Bourrage);
        }
        Ok(Self {
            defi,
            jeton,
            signature,
        })
    }

    /// Les 384 octets du fil.
    #[must_use]
    pub fn octets(&self) -> [u8; REQUETE_OCTETS] {
        let mut sortie = [0_u8; REQUETE_OCTETS];
        let mut ecrivain = Ecrivain::nouveau(&mut sortie);
        ecrivain.poser(&[VERSION, GENRE_SONDE_JETON]);
        ecrivain.poser(&self.contenu());
        ecrivain.poser(self.signature.octets());
        sortie
    }

    /// Le défi.
    #[must_use]
    pub const fn defi(&self) -> DefiEcho {
        self.defi
    }

    /// Le jeton.
    #[must_use]
    pub const fn jeton(&self) -> &Jeton {
        &self.jeton
    }

    /// L'écho doit-il répondre ? **Hors ligne.**
    ///
    /// 1. le jeton est cru ([`Jeton::verifier`]) : il vise `moi` sous
    ///    `ma_cle`, il est dans sa durée, et une racine embarquée l'a signé ;
    /// 2. la sonde est signée par la clé que le jeton nomme — le jeton ne sert
    ///    qu'à qui détient la clé privée pour laquelle il a été délivré.
    ///
    /// # Erreurs
    ///
    /// [`RefusSonde::Jeton`], [`RefusSonde::SignatureDuSondeur`].
    pub fn accepter(
        &self,
        moi: Identifiant,
        ma_cle: &ClePublique,
        cle_de_racine: &dyn Fn(Identifiant) -> Option<ClePublique>,
        maintenant: u64,
    ) -> Result<SondeAcceptee, RefusSonde> {
        self.jeton
            .verifier(moi, ma_cle, cle_de_racine, maintenant)
            .map_err(RefusSonde::Jeton)?;
        if !self.signature_tient() {
            return Err(RefusSonde::SignatureDuSondeur);
        }
        Ok(SondeAcceptee {
            defi: self.defi,
            moi,
            sondeur: self.jeton.sondeur(),
        })
    }

    /// La signature tient-elle sous la clé que le jeton nomme ?
    #[must_use]
    pub fn signature_tient(&self) -> bool {
        self.jeton
            .cle_sondeur()
            .verifie_echo(DomaineEcho::Sonde, &self.contenu(), &self.signature)
    }

    /// Ce que le sondeur signe.
    fn contenu(&self) -> [u8; CONTENU_JETON_OCTETS] {
        let mut contenu = [0_u8; CONTENU_JETON_OCTETS];
        let mut ecrivain = Ecrivain::nouveau(&mut contenu);
        ecrivain.poser(self.defi.octets());
        ecrivain.poser(&self.jeton.octets());
        contenu
    }
}

/// Ce que l'écho conclut d'un datagramme : illisible, ou lisible et refusé.
///
/// **Les deux mènent au même silence.** La distinction sert au journal — et
/// à dire une horloge qui dérive ([`RefusSonde::HorsFenetre`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusRequete {
    /// Ce n'est pas une sonde lisible.
    Illisible(Refus),
    /// Une sonde lisible, que l'écho ne croit pas.
    Refusee(RefusSonde),
}

/// **Tout ce que l'écho décide d'un datagramme reçu**, en un appel : le lire
/// comme l'une ou l'autre sonde, selon son genre, puis l'accepter ou non.
/// Voir [`SondeAnnuaire::accepter`] et [`SondeJeton::accepter`].
///
/// `cle_d_annuaire` rend la clé de l'annuaire du bail et des racines
/// embarquées ; `cle_de_racine` celle des racines embarquées seulement — **un
/// annuaire local ne délivre pas de jeton** (`protocole.md` §3 quater).
///
/// Le débit par source se borne AVANT cet appel, la mémoire des défis vus
/// APRÈS : ce sont deux états, tenus par qui écoute.
///
/// # Erreurs
///
/// [`RefusRequete`] — un genre qui n'est pas une sonde (une réponse comprise)
/// est illisible, [`Refus::Genre`].
pub fn accepter(
    datagramme: &[u8],
    moi: Identifiant,
    ma_cle: &ClePublique,
    cle_d_annuaire: &dyn Fn(Identifiant) -> Option<ClePublique>,
    cle_de_racine: &dyn Fn(Identifiant) -> Option<ClePublique>,
    maintenant: u64,
) -> Result<SondeAcceptee, RefusRequete> {
    if let [VERSION, GENRE_SONDE_JETON, ..] = datagramme {
        SondeJeton::lire(datagramme)
            .map_err(RefusRequete::Illisible)?
            .accepter(moi, ma_cle, cle_de_racine, maintenant)
            .map_err(RefusRequete::Refusee)
    } else {
        SondeAnnuaire::lire(datagramme)
            .map_err(RefusRequete::Illisible)?
            .accepter(moi, cle_d_annuaire, maintenant)
            .map_err(RefusRequete::Refusee)
    }
}
