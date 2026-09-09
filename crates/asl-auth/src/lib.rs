//! Ce qui autorise : capacités, portées, autorisations entre comptes, et le
//! code d'enrôlement.
//!
//! # Ce que cette crate décide, et ce qu'elle ignore
//!
//! **Elle décide, sur des faits qu'on lui donne.** Elle ne lit aucune base, ne
//! vérifie aucune signature, ne regarde pas l'heure. Ce sont les crates de
//! l'étage 3 qui établissent les faits ; celle-ci dit ce qu'on en conclut.
//!
//! **Elle ne connaît même pas le temps.** L'expiration d'un code d'enrôlement
//! est un FAIT que l'appelant établit ([`EtatCode`]), pas une décision. Lui
//! donner une horloge aurait ajouté une source de vérité de plus à une crate
//! dont tout l'intérêt est de n'en avoir aucune.
//!
//! # CE QUI N'EST PAS ENCORE ÉCRIT, ET POURQUOI
//!
//! **La vérification des signatures Ed25519.** Elle est pure, donc elle a sa
//! place à cet étage — mais ce qu'elle vérifierait n'est pas spécifié : que
//! signe exactement une machine, comment le rejeu est empêché, et où cette
//! vérification a lieu si l'authentification est portée par la connexion QUIC
//! (`docs/protocole.md` §0). **Écrire la crypto avant ces réponses aurait figé
//! un format qu'aucune décision ne soutient.**
//!
//! # C9 EST DANS LE TYPE [`Decision`], ET C'EST DÉLIBÉRÉ
//!
//! `Refuser` **ne porte aucune raison**. Ce n'est pas un oubli : une raison
//! finirait, un jour de hâte, dans une réponse ou dans un message d'erreur — et
//! « vous n'avez pas le droit » distingué de « ce service n'existe pas » est
//! exactement la fuite que C9 ferme. L'annuaire sait où écoutent des services
//! qui ne publient pas leur port : apprendre qu'un service EXISTE est déjà ce
//! qu'un inconnu cherchait.
//!
//! Le journal, lui, enregistre « refusé » sans le pourquoi
//! ([`journal.md`](../journal/index.html)) : le VOLUME des refus suffit à
//! détecter un abus, et il ne dit rien de plus à personne.
//!
//! # C10 EST DANS LA FORME DE [`decider_resolution`]
//!
//! Elle prend la machine QUI DEMANDE, et la cible **déjà résolue**. Elle ne
//! prend jamais ce que la requête DÉSIGNE. Un chemin qui rendrait un service
//! parce que son identifiant a été fourni — plutôt que parce que le demandeur y
//! a droit — serait la faille entière de ce produit, et il passerait tous les
//! essais qui ne la cherchent pas.

#![no_std]

use asl_id::{Genre, Identifiant, base32};

// ── Ce qu'on décide ─────────────────────────────────────────────────────────

/// Le verdict d'une décision d'autorisation.
///
/// **`Refuser` ne porte aucune raison**, et l'en-tête du module dit pourquoi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Decision {
    /// L'opération est permise.
    Servir,
    /// Elle ne l'est pas. **Et on n'en dira pas plus.**
    Refuser,
}

impl Decision {
    /// L'opération est-elle permise ?
    #[must_use]
    pub const fn permet(self) -> bool {
        matches!(self, Self::Servir)
    }
}

// ── Les machines ────────────────────────────────────────────────────────────

/// Ce qu'une machine a le droit de faire.
///
/// **Les deux ne sont pas cumulées par défaut** (`docs/modele.md` §2.3), et le
/// rayon de dégât explique pourquoi : un daemon compromis sur une machine
/// `annonce` usurpe le nom d'un autre daemon de la même machine ; le même daemon
/// sur une machine `annonce + lecture` peut EN PLUS énumérer tout ce que son
/// propriétaire a le droit de voir — y compris des adresses de machines qui ne
/// lui appartiennent pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Capacites {
    /// Les daemons de cette machine peuvent annoncer.
    pub annonce: bool,
    /// Cette machine peut interroger l'annuaire.
    pub lecture: bool,
}

impl Capacites {
    /// Aucune capacité. **C'est le défaut**, et c'est voulu : une machine
    /// déclarée sans qu'on ait dit ce qu'elle fait ne fait rien.
    pub const AUCUNE: Self = Self {
        annonce: false,
        lecture: false,
    };

    /// La machine qui héberge des daemons.
    pub const ANNONCE: Self = Self {
        annonce: true,
        lecture: false,
    };

    /// La machine qui consomme des services.
    pub const LECTURE: Self = Self {
        annonce: false,
        lecture: true,
    };
}

/// Une machine, telle que l'annuaire la connaît.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Machine {
    identifiant: Identifiant,
    proprietaire: Identifiant,
    capacites: Capacites,
}

impl Machine {
    /// Construit l'enregistrement d'une machine.
    ///
    /// # Erreurs
    ///
    /// [`Faute::PasUneMachine`], [`Faute::PasUnUtilisateur`].
    pub fn nouvelle(
        identifiant: Identifiant,
        proprietaire: Identifiant,
        capacites: Capacites,
    ) -> Result<Self, Faute> {
        if identifiant.genre() != Genre::Machine {
            return Err(Faute::PasUneMachine {
                obtenu: identifiant.genre(),
            });
        }
        if proprietaire.genre() != Genre::Utilisateur {
            return Err(Faute::PasUnUtilisateur {
                obtenu: proprietaire.genre(),
            });
        }
        Ok(Self {
            identifiant,
            proprietaire,
            capacites,
        })
    }

    /// Son identifiant.
    #[must_use]
    pub const fn identifiant(&self) -> Identifiant {
        self.identifiant
    }

    /// Le compte qui la possède.
    #[must_use]
    pub const fn proprietaire(&self) -> Identifiant {
        self.proprietaire
    }

    /// Ce qu'elle a le droit de faire.
    #[must_use]
    pub const fn capacites(&self) -> Capacites {
        self.capacites
    }
}

// ── Les autorisations ───────────────────────────────────────────────────────

/// Ce qu'une autorisation couvre.
///
/// Elle suit la chaîne de possession : un utilisateur possède ses machines, ses
/// machines possèdent leurs services (`docs/annuaires.md` §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Portee {
    /// Tous les services de toutes les machines du compte qui accorde.
    ToutLeCompte,
    /// Tous les services d'une machine.
    UneMachine(Identifiant),
    /// Un service précis.
    UnService(Identifiant),
}

/// Une arête entre deux comptes.
///
/// **Ce n'est pas un jeton porteur** (`docs/modele.md` §2.5). Un jeton qu'on
/// donne à un ami ne se récupère pas ; une arête nomme le bénéficiaire, et
/// retirer suffit puisqu'il n'y a rien à reprendre.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Autorisation {
    par: Identifiant,
    a: Identifiant,
    portee: Portee,
    revoquee: bool,
}

impl Autorisation {
    /// Construit une autorisation.
    ///
    /// # Erreurs
    ///
    /// [`Faute::PasUnUtilisateur`], [`Faute::PorteeIncoherente`],
    /// [`Faute::AutorisationASoiMeme`].
    pub fn nouvelle(
        par: Identifiant,
        a: Identifiant,
        portee: Portee,
        revoquee: bool,
    ) -> Result<Self, Faute> {
        for compte in [par, a] {
            if compte.genre() != Genre::Utilisateur {
                return Err(Faute::PasUnUtilisateur {
                    obtenu: compte.genre(),
                });
            }
        }
        // **S'AUTORISER SOI-MÊME N'A PAS DE SENS**, et l'accepter en silence
        // ferait exister deux chemins vers le même droit — celui du propriétaire
        // et celui de l'arête. Deux chemins, c'est un qu'on oublie de révoquer.
        if par == a {
            return Err(Faute::AutorisationASoiMeme);
        }
        match portee {
            Portee::ToutLeCompte => {}
            Portee::UneMachine(machine) if machine.genre() == Genre::Machine => {}
            Portee::UnService(service) if service.genre() == Genre::Service => {}
            Portee::UneMachine(autre) | Portee::UnService(autre) => {
                return Err(Faute::PorteeIncoherente {
                    obtenu: autre.genre(),
                });
            }
        }
        Ok(Self {
            par,
            a,
            portee,
            revoquee,
        })
    }

    /// Le compte qui accorde.
    #[must_use]
    pub const fn par(&self) -> Identifiant {
        self.par
    }

    /// Le compte bénéficiaire.
    #[must_use]
    pub const fn a(&self) -> Identifiant {
        self.a
    }

    /// Ce qu'elle couvre.
    #[must_use]
    pub const fn portee(&self) -> Portee {
        self.portee
    }

    /// A-t-elle été retirée ?
    #[must_use]
    pub const fn revoquee(&self) -> bool {
        self.revoquee
    }
}

/// La cible d'une résolution, **déjà résolue par le magasin**.
///
/// C'est ce qui rend C10 tenable : la décision porte sur des faits établis, et
/// non sur ce qu'une requête a nommé.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cible {
    service: Identifiant,
    machine: Identifiant,
    proprietaire: Identifiant,
}

impl Cible {
    /// Construit une cible.
    ///
    /// # Erreurs
    ///
    /// [`Faute::PasUnService`], [`Faute::PasUneMachine`],
    /// [`Faute::PasUnUtilisateur`].
    pub fn nouvelle(
        service: Identifiant,
        machine: Identifiant,
        proprietaire: Identifiant,
    ) -> Result<Self, Faute> {
        if service.genre() != Genre::Service {
            return Err(Faute::PasUnService {
                obtenu: service.genre(),
            });
        }
        if machine.genre() != Genre::Machine {
            return Err(Faute::PasUneMachine {
                obtenu: machine.genre(),
            });
        }
        if proprietaire.genre() != Genre::Utilisateur {
            return Err(Faute::PasUnUtilisateur {
                obtenu: proprietaire.genre(),
            });
        }
        Ok(Self {
            service,
            machine,
            proprietaire,
        })
    }

    /// Le service visé.
    #[must_use]
    pub const fn service(&self) -> Identifiant {
        self.service
    }

    /// La machine qui le porte.
    #[must_use]
    pub const fn machine(&self) -> Identifiant {
        self.machine
    }

    /// Le compte qui la possède.
    #[must_use]
    pub const fn proprietaire(&self) -> Identifiant {
        self.proprietaire
    }
}

// ── Les décisions ───────────────────────────────────────────────────────────

/// Cette machine peut-elle annoncer un service ?
#[must_use]
pub const fn decider_annonce(demandeur: &Machine) -> Decision {
    if demandeur.capacites.annonce {
        Decision::Servir
    } else {
        Decision::Refuser
    }
}

/// Cette machine peut-elle obtenir l'adresse de ce service ?
///
/// # C10 EST DANS LA FORME DE CETTE FONCTION
///
/// Elle prend **la machine qui demande** et **la cible déjà résolue**. Tout ce
/// qu'elle décide se calcule à partir du compte propriétaire du demandeur —
/// jamais à partir de ce que la requête désigne.
///
/// # Les trois règles, dans l'ordre
///
/// 1. **La machine doit porter `lecture`.** Sans elle, rien d'autre n'est même
///    examiné : une machine qui n'a pas le droit de lire n'a pas de compte à
///    faire valoir.
/// 2. **Ses propres services passent.** Le propriétaire n'a pas besoin de
///    s'autoriser lui-même — et [`Autorisation::nouvelle`] refuse d'ailleurs
///    qu'il le fasse.
/// 3. **Sinon, il faut une arête vivante qui couvre la cible.**
///
/// # Ce que la liste d'autorisations doit être
///
/// Celles que le MAGASIN a trouvées. Cette fonction ne les cherche pas : elle
/// les examine. Une autorisation révoquée qui s'y trouverait est refusée ici, ce
/// qui rend la fonction sûre même si l'appelant a mal filtré.
#[must_use]
pub fn decider_resolution(
    demandeur: &Machine,
    cible: &Cible,
    autorisations: &[Autorisation],
) -> Decision {
    if !demandeur.capacites.lecture {
        return Decision::Refuser;
    }
    if demandeur.proprietaire == cible.proprietaire {
        return Decision::Servir;
    }
    for autorisation in autorisations {
        if autorisation.couvre(demandeur.proprietaire, cible) {
            return Decision::Servir;
        }
    }
    Decision::Refuser
}

impl Autorisation {
    /// Cette autorisation ouvre-t-elle cette cible à ce bénéficiaire ?
    fn couvre(&self, beneficiaire: Identifiant, cible: &Cible) -> bool {
        if self.revoquee {
            return false;
        }
        // **LES DEUX BOUTS SONT VÉRIFIÉS.** Une arête qui n'aurait pas été
        // accordée par le propriétaire de la cible ouvrirait les services d'un
        // compte sur la signature d'un autre — c'est-à-dire tout ce que
        // l'autorisation existe pour empêcher.
        if self.a != beneficiaire || self.par != cible.proprietaire {
            return false;
        }
        match self.portee {
            Portee::ToutLeCompte => true,
            Portee::UneMachine(machine) => machine == cible.machine,
            Portee::UnService(service) => service == cible.service,
        }
    }
}

// ── Le code d'enrôlement ────────────────────────────────────────────────────

/// Le nombre de symboles d'un code d'enrôlement.
///
/// Dix symboles de base32 font **cinquante bits**. C'est confortable pour un
/// secret qui vit quelques minutes et ne sert qu'une fois : deviner demanderait
/// des milliards d'essais, et l'annuaire en compte.
pub const CODE_SYMBOLES: usize = 10;

/// Ce que le magasin sait d'un code.
///
/// **C'est un FAIT, pas une décision.** L'expiration se constate avec une
/// horloge, que cette crate n'a pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EtatCode {
    /// Le code n'a pas encore servi et n'a pas expiré.
    Utilisable,
    /// Il a déjà servi.
    Consomme,
    /// Il a expiré.
    Expire,
}

/// Le code court qu'on tape sur une machine pour y lier une clé.
///
/// # C'EST LE SEUL SECRET PARTAGÉ DE CE PRODUIT, ET IL EST NOMMÉ COMME TEL
///
/// La contrainte C14 interdit l'authentification par secret partagé. Ce code en
/// est un — et ce qui le rend acceptable est qu'il n'authentifie RIEN sur la
/// durée : une seule fois, quelques minutes, et il n'ouvre qu'une opération,
/// lier une clé. Le justificatif durable est la clé, que personne n'a jamais
/// transmise.
///
/// Le déguiser en « jeton d'appairage » aurait été pire que de l'écrire.
#[derive(Debug, Clone, Copy)]
pub struct CodeEnrolement {
    symboles: [u8; CODE_SYMBOLES],
}

impl CodeEnrolement {
    /// Fabrique un code à partir de huit octets d'entropie.
    ///
    /// **Les cinquante bits de POIDS FORT sont employés**, et les quatorze
    /// autres ignorés. Prendre les bits de poids faible aurait donné le même
    /// résultat avec un bon générateur et un moins bon avec un mauvais : autant
    /// prendre ceux qui varient toujours.
    ///
    /// L'aléa vient de l'appelant : cette crate est à l'étage 2 et ne lit rien.
    #[must_use]
    pub fn depuis_entropie(entropie: [u8; 8]) -> Self {
        let mut valeur = u64::from_be_bytes(entropie) >> 14;
        let mut symboles = [b'0'; CODE_SYMBOLES];
        for place in symboles.iter_mut().rev() {
            // `& 31` borne à 0..=31 : l'indice est toujours dans l'alphabet.
            #[allow(
                clippy::cast_possible_truncation,
                reason = "le masque `& 31` borne la valeur à 0..=31"
            )]
            let indice = (valeur & 31) as usize;
            *place = base32::ALPHABET[indice];
            valeur >>= 5;
        }
        Self { symboles }
    }

    /// Lit un code tapé par un humain.
    ///
    /// La casse est indifférente, et les confusions de Crockford sont
    /// rattrapées : c'est la raison d'être de cet alphabet, et elle vaut ici
    /// autant que pour un identifiant.
    ///
    /// # Erreurs
    ///
    /// [`Faute::CodeLongueur`], [`Faute::CodeSymboleInvalide`].
    pub fn analyser(texte: &str) -> Result<Self, Faute> {
        let octets = texte.as_bytes();
        if octets.len() != CODE_SYMBOLES {
            return Err(Faute::CodeLongueur {
                attendue: CODE_SYMBOLES,
                obtenue: octets.len(),
            });
        }
        let mut symboles = [b'0'; CODE_SYMBOLES];
        for (position, (place, octet)) in symboles.iter_mut().zip(octets.iter()).enumerate() {
            let valeur = base32::valeur(*octet).ok_or(Faute::CodeSymboleInvalide { position })?;
            // On range la forme CANONIQUE, pas ce qui a été tapé : sans cela,
            // `0` et `O` seraient deux codes différents à la comparaison.
            *place = base32::ALPHABET[usize::from(valeur)];
        }
        Ok(Self { symboles })
    }

    /// Le texte canonique, en majuscules.
    #[must_use]
    pub fn texte(&self) -> &str {
        // Tous les octets viennent de l'alphabet, donc ASCII.
        core::str::from_utf8(&self.symboles).unwrap_or("")
    }
}

/// Deux codes sont-ils égaux ?
///
/// **La comparaison ne s'arrête pas au premier écart** (contrainte C9).
///
/// # LA DETTE QUI ÉTAIT ÉCRITE ICI EST PAYÉE
///
/// Une première version employait une boucle et `core::hint::black_box`, avec
/// cette réserve : « Rust ne garantit pas le temps constant ; un compilateur a
/// le droit de remplacer cette boucle par une comparaison qui s'arrête tôt, et
/// `black_box` le lui rend difficile, pas impossible. La garantie réelle demande
/// `subtle`, et c'est une décision de la tranche de crypto. »
///
/// **La tranche de crypto est arrivée**, et `subtle` avec elle — elle entre dans
/// le graphe par `ed25519-dalek`, qui en dépend déjà. La réserve n'a donc plus
/// lieu d'être, et la comparaison est celle d'une bibliothèque écrite pour cela.
#[must_use]
pub fn egal_en_temps_constant(a: &CodeEnrolement, b: &CodeEnrolement) -> bool {
    use subtle::ConstantTimeEq as _;
    a.symboles.ct_eq(&b.symboles).into()
}

/// Ce code permet-il de lier une clé ?
///
/// # POURQUOI LA COMPARAISON A LIEU MÊME QUAND L'ÉTAT LA REND INUTILE
///
/// Un `return` anticipé sur `Consomme` ou `Expire` rendrait la réponse PLUS
/// RAPIDE dans ces cas — et un inconnu qui mesure les temps apprendrait alors si
/// le code qu'il présente existe, ou s'il a déjà servi. C9 ferme exactement ce
/// canal.
///
/// La comparaison tourne donc toujours, et son résultat est combiné à l'état à
/// la fin.
#[must_use]
pub fn decider_enrolement(
    presente: &CodeEnrolement,
    attendu: &CodeEnrolement,
    etat: EtatCode,
) -> Decision {
    let egaux = egal_en_temps_constant(presente, attendu);
    let utilisable = matches!(etat, EtatCode::Utilisable);
    if egaux && utilisable {
        Decision::Servir
    } else {
        Decision::Refuser
    }
}

// ── Les fautes ──────────────────────────────────────────────────────────────

/// Ce qui peut clocher dans la construction d'un fait.
///
/// **Ce ne sont pas des refus d'autorisation** : ceux-là sont un
/// [`Decision::Refuser`] sans raison. Ce sont des faits mal formés, qu'un
/// appelant doit corriger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Faute {
    /// Un identifiant de machine était attendu.
    PasUneMachine {
        /// Le genre fourni.
        obtenu: Genre,
    },
    /// Un identifiant d'utilisateur était attendu.
    PasUnUtilisateur {
        /// Le genre fourni.
        obtenu: Genre,
    },
    /// Un identifiant de service était attendu.
    PasUnService {
        /// Le genre fourni.
        obtenu: Genre,
    },
    /// La portée désigne un objet du mauvais genre.
    PorteeIncoherente {
        /// Le genre fourni.
        obtenu: Genre,
    },
    /// Un compte s'autorise lui-même.
    AutorisationASoiMeme,
    /// Le code n'a pas la bonne longueur.
    CodeLongueur {
        /// Ce qui était attendu.
        attendue: usize,
        /// Ce qui a été reçu.
        obtenue: usize,
    },
    /// Le code porte un symbole hors de l'alphabet.
    CodeSymboleInvalide {
        /// La position du symbole fautif.
        position: usize,
    },
}
