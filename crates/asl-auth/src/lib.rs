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

use asl_id::{Genre, Identifiant};

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

/// Un appareil peut-il voir les services de cette machine ?
///
/// # UNE RÈGLE, ET NON UNE COMPARAISON ÉGARÉE DANS LA BOUCLE
///
/// Elle tient en une égalité, et c'est justement pourquoi elle doit être ici :
/// une règle écrite au milieu d'un rassemblement est une règle que personne ne
/// relit, et qu'aucun essai ne prend pour cible.
///
/// # ELLE NE REGARDE AUCUNE AUTORISATION, ET C'EST DÉLIBÉRÉ
///
/// `GET /v1/machines/{m}/services` appartient à l'administration d'un compte
/// (`protocole.md` §2.2) : c'est l'écran qui montre MES machines. Le chemin
/// inter-comptes est `GET /v1/ou`, qui passe par [`decider_resolution`] et ses
/// autorisations.
///
/// Les confondre donnerait à une autorisation de LECTURE — accordée pour joindre
/// un service — le droit d'énumérer le parc de celui qui l'a accordée. **Ce n'est
/// pas ce qu'il a accordé.**
// `const fn` serait plus joli, et `PartialEq` ne l'est pas encore : la
// comparaison de deux identifiants passe par un `==` ordinaire.
#[must_use]
pub fn decider_services_de_machine(demandeur: Identifiant, proprietaire: Identifiant) -> Decision {
    if demandeur == proprietaire {
        Decision::Servir
    } else {
        Decision::Refuser
    }
}

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

/// Combien de temps un code vaut, en secondes.
///
/// # C'EST UNE POLITIQUE, ET ELLE RESTE ICI
///
/// La GRAMMAIRE d'un code — son alphabet, sa forme canonique, son empreinte —
/// a rejoint `asl-cle` : c'est un justificatif, et le daemon doit savoir la
/// composer sans embarquer les décisions de l'annuaire. **Sa durée, elle, est
/// une décision**, et elle n'appartient qu'au serveur.
///
/// Dix minutes : le temps d'aller du téléphone au terminal, et pas davantage.
/// **Un code qui traîne est un secret qui traîne** — c'est la seule chose qui
/// borne les essais d'un inconnu, avec ses cinquante bits.
pub const VALIDITE_CODE_SECONDES: u64 = 600;

/// Ce que le magasin sait d'un code.
///
/// **C'est un FAIT, pas une décision.** L'expiration se constate avec une
/// horloge, que cette crate n'a pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EtatCode {
    /// Le code n'a pas encore servi et n'a pas expiré.
    Utilisable,
    /// Aucun code ne répond à cette empreinte.
    ///
    /// **Il a peut-être servi, il n'a peut-être jamais existé**, et l'annuaire
    /// ne fait pas la différence : un code consommé est SUPPRIMÉ, pas marqué.
    /// Garder les codes morts pour distinguer les deux cas aurait fait pousser
    /// une table de secrets périmés, et n'aurait rien appris à personne
    /// d'utile — sinon à qui essaie des codes au hasard.
    Inconnu,
    /// Il existe, mais sa date est passée.
    Expire,
}

/// Ce code permet-il de lier une clé ?
///
/// # IL N'Y A PLUS QU'UN FAIT À EXAMINER, ET C'EST UN PROGRÈS
///
/// Cette fonction comparait le code présenté au code attendu, en temps
/// constant, parce que l'annuaire gardait les codes. Il garde désormais leurs
/// EMPREINTES et cherche par elles (`CodeEnrolement::empreinte`) : il n'y a plus
/// de code attendu à comparer, et l'état résume tout ce qu'on sait.
///
/// **Ce que C9 exigeait tient toujours, et autrement** : `Inconnu` et `Expire`
/// donnent le même refus, et rien dans la réponse ne les distingue. Ce qui les
/// distinguait dans le TEMPS — un `return` anticipé — n'existe plus, puisqu'il
/// n'y a plus de comparaison à écourter. Reste l'écart entre une recherche qui
/// trouve et une qui ne trouve pas ; il porte sur une empreinte de 256 bits que
/// personne ne sait approcher par tâtonnement.
#[must_use]
pub const fn decider_enrolement(etat: EtatCode) -> Decision {
    match etat {
        EtatCode::Utilisable => Decision::Servir,
        EtatCode::Inconnu | EtatCode::Expire => Decision::Refuser,
    }
}

// ── Ce qu'un compte a le droit d'administrer ────────────────────────────────

/// Ce compte peut-il administrer ce qui appartient à ce propriétaire ?
///
/// # LA RÈGLE TIENT EN UNE LIGNE, ET C'EST POUR CELA QU'ELLE EST ICI
///
/// Un compte administre ce qu'il possède, et rien d'autre. La règle est si
/// simple qu'on serait tenté de l'écrire à l'appel — **et c'est exactement
/// pourquoi elle ne doit pas l'être** : écrite à l'appel, elle serait écrite
/// autant de fois qu'il y a de verbes d'administration, et c'est celui qu'on
/// oublie qui ouvrirait les machines d'un autre.
///
/// Elle prend deux comptes DÉJÀ ÉTABLIS, jamais ce qu'une requête a nommé :
/// c'est C10, et c'est la même forme que [`decider_resolution`].
#[must_use]
pub fn decider_gestion(demandeur: Identifiant, proprietaire: Identifiant) -> Decision {
    if demandeur == proprietaire {
        Decision::Servir
    } else {
        Decision::Refuser
    }
}

/// Cet appareil peut-il en révoquer un autre ?
///
/// # UN APPAREIL NE SE RÉVOQUE PAS LUI-MÊME, ET CE N'EST PAS UNE COMMODITÉ
///
/// `protocole.md` §2.2 le dit : **sinon un téléphone volé et déverrouillé
/// révoque les autres et confisque le compte.** Le voleur tiendrait alors le
/// seul justificatif restant, et le propriétaire n'aurait plus rien pour le lui
/// reprendre. La règle inverse — « n'importe quel appareil enrôlé peut révoquer
/// n'importe quel autre, sauf lui-même » — laisse toujours au propriétaire un
/// appareil pour se défendre.
///
/// # ET ELLE FAIT TOMBER UN AUTRE PROBLÈME, SANS QU'ON AIT À LE TRAITER
///
/// **Un compte ne peut pas se retrouver sans aucun appareil.** Il en faut deux
/// pour qu'une révocation soit possible, et il en reste donc au moins un après.
/// Un compte à un seul appareil ne peut que tenter de se révoquer lui-même, et
/// c'est refusé — il n'y a pas de compte à confisquer par mégarde.
#[must_use]
pub fn decider_revocation_d_appareil(demandeur: Identifiant, vise: Identifiant) -> Decision {
    if demandeur == vise {
        Decision::Refuser
    } else {
        Decision::Servir
    }
}

// ── L'attestation de plate-forme ────────────────────────────────────────────

/// Ce que l'annuaire exige d'un appareil qui s'enrôle.
///
/// # POURQUOI CE CHOIX EST UN RÉGLAGE, ET NON UNE CONSTANTE
///
/// `protocole.md` §2.1 tranche : « La v1 REFUSE, et journalise, parce qu'un
/// refus se relâche plus tard alors qu'une acceptation ne se resserre jamais
/// sans casser des comptes existants. »
///
/// **Mais la vérification n'est pas écrite** — App Attest et Play Integrity
/// demandent les racines d'Apple et de Google, du CBOR, et une chaîne à valider.
/// Exiger l'attestation aujourd'hui, c'est donc refuser TOUS les enrôlements.
///
/// Les deux postures sont défendables et **aucune ne peut être le défaut** :
/// exiger livre un produit qui ne crée aucun compte, dispenser livre en silence
/// la posture faible. `asl-server` n'a donc pas de valeur par défaut — il refuse
/// de démarrer tant qu'on ne lui a pas dit laquelle il tient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Politique {
    /// L'attestation est exigée. **Aucun appareil ne s'enrôle** tant que sa
    /// vérification n'est pas écrite, et c'est la posture de `protocole.md`.
    AttestationExigee,
    /// L'attestation n'est pas exigée. **N'importe qui crée un compte**, et le
    /// journal d'exploitation doit le dire au démarrage.
    AttestationFacultative,
}

/// Cet appareil peut-il s'enrôler ?
///
/// `atteste` est un FAIT que l'étage 3 établit — aujourd'hui toujours `false`,
/// parce que rien ne sait encore le vérifier. **Il est en paramètre plutôt
/// qu'absent** pour que le jour où la vérification s'écrit, elle se branche ici
/// et nulle part ailleurs.
#[must_use]
pub const fn decider_attestation(atteste: bool, politique: Politique) -> Decision {
    match politique {
        Politique::AttestationFacultative => Decision::Servir,
        Politique::AttestationExigee => {
            if atteste {
                Decision::Servir
            } else {
                Decision::Refuser
            }
        }
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
}
