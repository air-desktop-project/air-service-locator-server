//! L'annuaire lui-même : ce qu'il décide, et rien de ce qu'il exécute.
//!
//! # Une machine à états, et pas un service
//!
//! Elle reçoit des messages déjà décodés et **l'heure** ; elle rend des réponses
//! et des ACTIONS. Elle n'attend jamais, n'ouvre rien, n'écrit nulle part
//! (contrainte C1).
//!
//! **L'heure est un paramètre, et c'est la décision de conception qui compte
//! ici.** L'état d'un daemon n'est pas un fait qu'on stocke, c'est une
//! conclusion qu'on tire d'une connexion et d'une horloge. Si l'horloge était un
//! appel système au fond d'une boucle, éprouver une expiration coûterait
//! d'attendre réellement le délai ; en paramètre, un essai la pilote en trois
//! lignes — et peut la pousser à la dernière milliseconde, ce qu'aucune suite
//! d'essais ne ferait autrement.
//!
//! # DEUX HORLOGES, ET LES CONFONDRE SERAIT LA FAUTE
//!
//! Les spécifications parlent d'« instant » sans distinguer, et il y en a DEUX
//! qui n'ont ni la même source ni les mêmes garanties.
//!
//! | | [`Instant`] | [`Horodatage`] |
//! |---|---|---|
//! | Ce que c'est | Une horloge **monotone**, d'origine arbitraire | Des millisecondes depuis l'époque Unix |
//! | À quoi elle sert | **DÉCIDER** : un bail a-t-il expiré ? | **ÉCRIRE** : la date d'une mesure, dans un message |
//! | Peut-elle reculer ? | Non, jamais | **Oui** — un ajustement NTP la fait sauter |
//!
//! **Décider d'une expiration avec une horloge murale serait un défaut à
//! retardement** : un pas de NTP vers l'arrière ressusciterait des baux expirés,
//! et un pas vers l'avant tuerait d'un coup tous les daemons sains d'une
//! machine. Ces ajustements arrivent, et ils n'arrivent jamais au bon moment.
//!
//! Cette crate décide donc avec [`Instant`] et n'écrit qu'avec [`Horodatage`].
//! **Les deux viennent de l'appelant** : elle n'en lit aucun.
//!
//! # Ce qu'elle contient, et ce qu'elle ne contient pas
//!
//! **Une [`Session`] est la vie d'UN service sur UNE connexion tenue.** C'est
//! tout ce que cette crate décide.
//!
//! Elle ne tient PAS la table des services de l'annuaire : cela demande de
//! stocker, donc appartient à `asl-store`. Le découpage n'est pas arbitraire —
//! une session n'a besoin de rien connaître des autres, et lui donner accès à
//! la table l'aurait rendue inéprouvable sans base de données.

#![no_std]

use core::net::IpAddr;

use asl_id::{Genre, Identifiant};
use asl_proto::{
    ADRESSES_MAX, Annonce, Bail, Candidat, Horodatage, Joignabilite, Origine, POINTS_MAX,
    Passerelle, PointEcoute, Port, Poussee, Protocole, RaisonNonSonde, Reponse, Verdict,
    VerdictNat, VuDepuis, ordonner,
};

/// Le nombre maximal de candidats pour un point d'écoute.
///
/// Le réflexif, plus une par adresse annoncée — et, pour l'écho, celui de sa
/// passerelle (décision 97).
pub const CANDIDATS_MAX: usize = 2 + ADRESSES_MAX;

// ── L'horloge monotone ──────────────────────────────────────────────────────

/// Un instant d'une horloge **monotone**, en millisecondes depuis une origine
/// arbitraire.
///
/// Voir l'en-tête du module pour la raison de sa séparation d'avec
/// [`Horodatage`]. En deux mots : **on décide avec celle-ci, on écrit avec
/// l'autre**, parce qu'une horloge murale recule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Instant(u64);

impl Instant {
    /// Depuis des millisecondes d'une origine quelconque.
    #[must_use]
    pub const fn depuis_millisecondes(millisecondes: u64) -> Self {
        Self(millisecondes)
    }

    /// Les millisecondes.
    #[must_use]
    pub const fn millisecondes(self) -> u64 {
        self.0
    }

    /// Le temps écoulé depuis `debut`, en millisecondes.
    ///
    /// **Rend `0` si `debut` est postérieur**, et ne panique pas. Un écoulement
    /// négatif n'a pas de sens ; le refuser ici obligerait chaque appelant à
    /// traiter un cas que [`Session`] refuse déjà à l'entrée.
    #[must_use]
    pub const fn depuis(self, debut: Self) -> u64 {
        self.0.saturating_sub(debut.0)
    }
}

// ── Les fautes ──────────────────────────────────────────────────────────────

/// Ce qui peut clocher dans la conduite d'une session.
///
/// **Ce ne sont pas des fautes de protocole** — celles-là sont dans
/// `asl_proto::Erreur`. Ce sont des fautes de CONDUITE : un événement qui arrive
/// là où il n'a pas de sens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Faute {
    /// L'instant fourni est antérieur au précédent.
    ///
    /// **Avec une horloge monotone, cela ne peut pas arriver** : c'est donc une
    /// faute de l'appelant, qui a mélangé deux horloges ou rejoué un événement.
    /// La signaler vaut mieux que l'absorber — une session qui accepterait un
    /// temps qui recule tiendrait un bail sur une mesure qu'elle ne comprend
    /// pas.
    TempsRecule {
        /// Le dernier instant connu.
        precedent: Instant,
        /// Celui qu'on vient de recevoir.
        recu: Instant,
    },
    /// Un résultat de sonde désigne un point que ce service n'annonce pas.
    PointInconnu {
        /// Le point désigné.
        point: PointEcoute,
    },
    /// Un résultat de sonde porte sur un point qui ne se sonde pas.
    ///
    /// C'est C6 : l'annuaire ne peut rien affirmer d'un point UDP.
    PointNonSondable {
        /// Le point désigné.
        point: PointEcoute,
    },
    /// L'identifiant attribué au service n'est pas de genre service.
    PasUnService {
        /// Le genre fourni.
        obtenu: Genre,
    },
    /// L'événement arrive sur une session déjà expirée.
    ///
    /// # POURQUOI UNE EXPIRATION NE SE DÉFAIT PAS
    ///
    /// **Un keepalive tardif ne ressuscite pas un daemon.** Sans ce refus, une
    /// session expirée redevenait vivante au premier signe de vie, et l'état du
    /// service passait de `parti` à `annoncé` puis de nouveau à `parti` — un
    /// service qui clignote, alors qu'on a déjà dit à ses clients qu'il était
    /// parti.
    ///
    /// **C'est aussi une faute de CONDUITE de l'appelant** : l'étage 3 aurait dû
    /// fermer la connexion en constatant l'expiration. La signaler vaut mieux
    /// que l'absorber.
    ///
    /// Trouvé par le fuzz, pas par la relecture.
    SessionExpiree {
        /// Le dernier signe de vie reçu.
        dernier_signe: Instant,
    },
}

// ── L'état d'un service ─────────────────────────────────────────────────────

/// Pourquoi une session s'est terminée.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MotifDeDepart {
    /// Le daemon a fermé sa connexion proprement.
    ///
    /// L'extinction QUIC en deux temps le distingue d'une coupure, et **celui
    /// qui regarde ne traitera pas les deux pareil** : un arrêt volontaire
    /// n'appelle aucune enquête, une coupure si.
    Volontaire,
    /// Le délai d'inactivité a expiré sans keepalive.
    Inactivite,
}

/// Ce que l'annuaire peut dire d'un service.
///
/// **Le mot « en ligne » n'y figure pas** (contrainte C6) : il confondrait « le
/// daemon parle » avec « on peut l'atteindre », et c'est exactement ce que le
/// NAT sépare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Etat {
    /// La connexion est tenue. **Le daemon dit qu'il écoute**, et l'annuaire
    /// n'a rien vérifié — ou rien constaté.
    Annonce,
    /// L'annuaire a lui-même atteint ce candidat, à cette date.
    ///
    /// **La date et le candidat sont DANS la variante** : il n'existe aucune
    /// façon d'affirmer « joignable » sans dire depuis quand ni par où.
    Joignable {
        /// Par où.
        candidat: Candidat,
        /// Quand.
        a: Horodatage,
    },
    /// La connexion est fermée.
    Parti {
        /// Proprement, ou par expiration.
        motif: MotifDeDepart,
    },
}

// ── La session ──────────────────────────────────────────────────────────────

/// La vie d'un service sur une connexion tenue.
///
/// **Elle ne stocke pas le nom du service**, seulement son identifiant : le nom
/// sert à retrouver un service dans la table de l'annuaire, ce qui est le
/// travail d'`asl-store`. L'y garder aurait obligé cette crate à posséder une
/// chaîne, donc à allouer.
#[derive(Debug, Clone, Copy)]
pub struct Session {
    service: Identifiant,
    bail: Bail,
    dernier_signe: Instant,
    vu_depuis: VuDepuis,
    derriere_nat: VerdictNat,
    adresses: [IpAddr; ADRESSES_MAX],
    nombre_adresses: usize,
    joignabilite: [Joignabilite; POINTS_MAX],
    nombre_points: usize,
    depart: Option<MotifDeDepart>,
    /// **Est-ce l'`asl-echo` ?** (`protocole.md` §3 quater, décisions 90 et
    /// 92.) Alors son point UDP se sonde — par l'écho, qui répond d'une
    /// signature —, et son candidat réflexif porte le port OBSERVÉ : l'écho
    /// tient son bail sur la socket où il écoute.
    echo: bool,
    /// **Le port que la box a accordé à l'écho** (décision 97 ; E21) — son
    /// candidat passe en tête, avec l'adresse OBSERVÉE : l'annuaire ne parle
    /// qu'à l'adresse qui lui a parlé.
    passerelle: Option<Passerelle>,
}

/// Ce que l'annuaire doit FAIRE après avoir décidé.
///
/// **Ce ne sont pas des effets, ce sont des ordres.** L'étage 3 les exécute ;
/// cette crate ne sait pas ouvrir une socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ordres {
    /// Les points à sonder, dans l'ordre où ils figurent dans la session.
    a_sonder: [Option<PointEcoute>; POINTS_MAX],
}

impl Ordres {
    /// Aucun ordre.
    const RIEN: Self = Self {
        a_sonder: [None; POINTS_MAX],
    };

    /// Les points à sonder.
    pub fn a_sonder(&self) -> impl Iterator<Item = PointEcoute> + '_ {
        self.a_sonder.iter().filter_map(|point| *point)
    }

    /// Y a-t-il quelque chose à faire ?
    #[must_use]
    pub fn est_vide(&self) -> bool {
        self.a_sonder.iter().all(Option::is_none)
    }
}

impl Session {
    /// Ouvre une session sur une annonce.
    ///
    /// # Ce qu'elle décide, et pourquoi
    ///
    /// - **Le verdict de NAT**, en comparant l'adresse observée à celles que le
    ///   daemon annonce. C'est le seul endroit du produit où cette comparaison
    ///   peut se faire : le daemon ne sait pas comment on le voit, et l'annuaire
    ///   ne sait pas ce qu'il croit être.
    /// - **Les verdicts initiaux** : `EnCours` pour ce qui se sonde,
    ///   `NonSonde` pour l'UDP. **Jamais `Injoignable`** — n'avoir rien encore
    ///   mesuré n'est pas avoir mesuré un échec (C6).
    /// - **Les sondes à lancer**, rendues comme des ordres.
    ///
    /// # Erreurs
    ///
    /// [`Faute::PasUnService`] si l'identifiant attribué n'en est pas un.
    pub fn ouvrir(
        service: Identifiant,
        bail: Bail,
        annonce: &Annonce<'_>,
        vu_depuis: VuDepuis,
        maintenant: Instant,
    ) -> Result<(Self, Ordres), Faute> {
        if service.genre() != Genre::Service {
            return Err(Faute::PasUnService {
                obtenu: service.genre(),
            });
        }

        let mut adresses = [IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED); ADRESSES_MAX];
        let nombre_adresses = annonce.adresses_locales.len().min(ADRESSES_MAX);
        for (place, adresse) in adresses.iter_mut().zip(annonce.adresses_locales) {
            *place = *adresse;
        }

        let mut session = Self {
            service,
            bail,
            dernier_signe: maintenant,
            vu_depuis,
            derriere_nat: verdict_nat(vu_depuis, &adresses[..nombre_adresses]),
            adresses,
            nombre_adresses,
            joignabilite: [Joignabilite {
                point: PointEcoute::nouveau(Protocole::Tcp, Port::UN),
                verdict: Verdict::EnCours,
            }; POINTS_MAX],
            nombre_points: 0,
            depart: None,
            echo: annonce.service.as_str() == asl_proto::NOM_ASL_ECHO,
            passerelle: annonce.passerelle,
        };

        let ordres = session.poser_points(annonce.points);
        Ok((session, ordres))
    }

    /// Le service a changé d'identifiant sous elle : la session le suit.
    ///
    /// # POURQUOI UNE SESSION CHANGE D'IDENTIFIANT (0.36.0, décision 69)
    ///
    /// Entre deux membres d'une paire — ou deux racines —, le même
    /// `(machine, nom)` peut avoir été déclaré des deux côtés sous deux `s-…`.
    /// La réplication garde le plus ancien (`replication.md` §3.2). Si le
    /// perdant était celui sous lequel un daemon est connecté ICI, sa session
    /// doit passer sous le gagnant : sinon on le chercherait sous le gagnant,
    /// on ne le trouverait pas, et il serait dit `parti` alors qu'il est là.
    ///
    /// **Rien d'autre ne change** : ni le bail, ni les verdicts, ni les
    /// adresses. La réponse que rend [`Session::reponse`] porte désormais le
    /// nouvel identifiant ; le daemon l'apprend à sa prochaine annonce.
    ///
    /// # Erreurs
    ///
    /// [`Faute::PasUnService`] si l'identifiant n'en est pas un — la session
    /// reste alors sous l'ancien.
    pub fn renommer(&mut self, service: Identifiant) -> Result<(), Faute> {
        if service.genre() != Genre::Service {
            return Err(Faute::PasUnService {
                obtenu: service.genre(),
            });
        }
        self.service = service;
        Ok(())
    }

    /// Le daemon a donné signe de vie.
    ///
    /// # Erreurs
    ///
    /// [`Faute::TempsRecule`], [`Faute::SessionExpiree`].
    pub fn keepalive(&mut self, maintenant: Instant) -> Result<(), Faute> {
        self.avancer(maintenant)
    }

    /// Le daemon réannonce dans la même connexion.
    ///
    /// # ON NE RESONDE QUE CE QUI A CHANGÉ
    ///
    /// `docs/modele.md` §4.3 dit que la sonde a lieu « à l'annonce et à chaque
    /// changement de candidat ». Un point dont ni le protocole ni le port ne
    /// bougent garde donc son verdict : **le remettre à `EnCours` perdrait une
    /// mesure déjà faite**, et ferait clignoter l'état d'un service à chaque
    /// fois qu'un daemon en ajoute un autre.
    ///
    /// En revanche, si l'adresse observée a changé — migration de connexion —,
    /// **tout est resondé** : les candidats ne sont plus les mêmes.
    ///
    /// # Erreurs
    ///
    /// [`Faute::TempsRecule`], [`Faute::SessionExpiree`].
    pub fn reannoncer(
        &mut self,
        annonce: &Annonce<'_>,
        vu_depuis: VuDepuis,
        maintenant: Instant,
    ) -> Result<Ordres, Faute> {
        self.avancer(maintenant)?;

        // **UNE PASSERELLE NOUVELLE SE SONDE** : c'est la réannonce qu'`asl
        // echo` fait une fois la box interrogée (décision 97), et c'est le
        // candidat qu'elle ajoute qu'il faut mesurer.
        let migration = vu_depuis != self.vu_depuis || annonce.passerelle != self.passerelle;
        self.echo = annonce.service.as_str() == asl_proto::NOM_ASL_ECHO;
        self.passerelle = annonce.passerelle;
        self.vu_depuis = vu_depuis;

        let nombre_adresses = annonce.adresses_locales.len().min(ADRESSES_MAX);
        let mut adresses = [IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED); ADRESSES_MAX];
        for (place, adresse) in adresses.iter_mut().zip(annonce.adresses_locales) {
            *place = *adresse;
        }
        let changement_d_adresses =
            adresses[..nombre_adresses] != self.adresses[..self.nombre_adresses];
        self.adresses = adresses;
        self.nombre_adresses = nombre_adresses;
        self.derriere_nat = verdict_nat(vu_depuis, &self.adresses[..self.nombre_adresses]);

        if migration || changement_d_adresses {
            Ok(self.poser_points(annonce.points))
        } else {
            Ok(self.poser_points_en_gardant(annonce.points))
        }
    }

    /// Une sonde a rendu son verdict.
    ///
    /// Rend `true` si l'état a changé, donc s'il faut pousser une mise à jour au
    /// daemon.
    ///
    /// # Erreurs
    ///
    /// [`Faute::TempsRecule`], [`Faute::SessionExpiree`],
    /// [`Faute::PointInconnu`], [`Faute::PointNonSondable`].
    pub fn verdict_de_sonde(
        &mut self,
        point: PointEcoute,
        aboutie: Option<Candidat>,
        a: Horodatage,
        maintenant: Instant,
    ) -> Result<bool, Faute> {
        self.avancer(maintenant)?;

        if !self.se_sonde(point) {
            return Err(Faute::PointNonSondable { point });
        }

        let place = self
            .joignabilite
            .get_mut(..self.nombre_points)
            .unwrap_or(&mut [])
            .iter_mut()
            .find(|entree| entree.point == point)
            .ok_or(Faute::PointInconnu { point })?;

        let nouveau = match aboutie {
            Some(candidat) => Verdict::Joignable { candidat, a },
            None => Verdict::Injoignable { a },
        };
        let change = place.verdict != nouveau;
        place.verdict = nouveau;
        Ok(change)
    }

    /// Le daemon a fermé.
    pub const fn fermer(&mut self, motif: MotifDeDepart) {
        self.depart = Some(motif);
    }

    /// La session a-t-elle expiré, faute de keepalive ?
    ///
    /// **La question ne se pose que pour une session ouverte** : une session
    /// close est partie, et pour un motif qu'on connaît déjà.
    #[must_use]
    pub fn expiree(&self, maintenant: Instant) -> bool {
        if self.depart.is_some() {
            return false;
        }
        let ecoule = maintenant.depuis(self.dernier_signe);
        ecoule > u64::from(self.bail.inactivite_secondes()).saturating_mul(1_000)
    }

    /// Ce que l'annuaire peut dire de ce service, à cet instant.
    ///
    /// **Trois états, et jamais « en ligne »** (C6). `Joignable` gagne sur
    /// `Annonce` dès qu'un point a été atteint : c'est la seule affirmation
    /// qu'on ait mesurée, et c'est celle qui intéresse un client.
    #[must_use]
    pub fn etat(&self, maintenant: Instant) -> Etat {
        if let Some(motif) = self.depart {
            return Etat::Parti { motif };
        }
        if self.expiree(maintenant) {
            return Etat::Parti {
                motif: MotifDeDepart::Inactivite,
            };
        }
        for entree in self.joignabilite.get(..self.nombre_points).unwrap_or(&[]) {
            if let Verdict::Joignable { candidat, a } = entree.verdict {
                return Etat::Joignable { candidat, a };
            }
        }
        Etat::Annonce
    }

    /// La réponse à rendre au daemon.
    ///
    /// # Erreurs
    ///
    /// Celles de `Reponse::nouvelle`. **Elles ne devraient pas arriver** — une
    /// session valide porte des verdicts valides — mais les propager vaut mieux
    /// que les taire : si elles arrivaient, c'est que cette crate aurait
    /// construit un état que le protocole refuse.
    pub fn reponse(&self) -> Result<Reponse<'_>, asl_proto::Erreur> {
        Reponse::nouvelle(
            self.service,
            self.bail,
            self.vu_depuis,
            self.derriere_nat,
            self.joignabilite.get(..self.nombre_points).unwrap_or(&[]),
        )
    }

    /// La poussée à envoyer au daemon.
    ///
    /// # Erreurs
    ///
    /// Voir [`Session::reponse`].
    pub fn poussee(&self) -> Result<Poussee<'_>, asl_proto::Erreur> {
        Poussee::nouvelle(
            self.vu_depuis,
            self.derriere_nat,
            self.joignabilite.get(..self.nombre_points).unwrap_or(&[]),
        )
    }

    /// L'identifiant du service.
    #[must_use]
    pub const fn service(&self) -> Identifiant {
        self.service
    }

    /// Est-ce l'`asl-echo` ?
    #[must_use]
    pub const fn est_un_echo(&self) -> bool {
        self.echo
    }

    /// D'où l'annuaire voit ce pair.
    #[must_use]
    pub const fn vu_depuis(&self) -> VuDepuis {
        self.vu_depuis
    }

    /// Ce point se sonde-t-il, pour cette session ?
    #[must_use]
    pub const fn se_sonde(&self, point: PointEcoute) -> bool {
        se_sonde(self.echo, point)
    }

    /// **Les points à resonder** — ceux de l'écho seulement, toutes les
    /// quinze minutes tant que le bail tient (décision 92 ; E9). Le verdict
    /// d'avant reste rendu jusqu'à ce que le nouveau arrive : « constaté à »
    /// vieillit, il ne s'efface pas.
    #[must_use]
    pub fn a_resonder(&self) -> Ordres {
        let mut ordres = Ordres::RIEN;
        if self.echo {
            for (ordre, entree) in ordres
                .a_sonder
                .iter_mut()
                .zip(self.joignabilite.get(..self.nombre_points).unwrap_or(&[]))
            {
                *ordre = Some(entree.point);
            }
        }
        ordres
    }

    /// Le verdict de NAT.
    #[must_use]
    pub const fn derriere_nat(&self) -> VerdictNat {
        self.derriere_nat
    }

    /// Les candidats à essayer pour ce point, **du meilleur au pire**.
    ///
    /// IPv6 avant IPv4, réflexif avant annoncé (`asl_proto::ordonner`).
    ///
    /// # Le candidat réflexif n'a pas le même sens selon le protocole
    ///
    /// Il porte l'adresse OBSERVÉE et le port ANNONCÉ — jamais le port observé.
    /// Le port source d'une connexion QUIC n'est pas celui du service, et
    /// l'employer désignerait la socket du client (`docs/modele.md` §3).
    ///
    /// Rend le nombre de candidats écrits.
    pub fn candidats(&self, point: PointEcoute, sortie: &mut [Candidat]) -> usize {
        let mut compte = 0_usize;

        let mut poser = |candidat: Candidat, compte: &mut usize| {
            if let Some(place) = sortie.get_mut(*compte) {
                *place = candidat;
                *compte = compte.saturating_add(1);
            }
        };

        // **POUR L'ÉCHO, LE PORT OBSERVÉ** (décision 90) : sa socket est
        // celle du bail, et c'est ce port que le NAT a ouvert. Pour tout
        // autre service, la règle d'en tête tient.
        poser(
            Candidat {
                protocole: point.protocole,
                adresse: self.vu_depuis.adresse,
                port: if self.echo {
                    self.vu_depuis.port
                } else {
                    point.port
                },
                origine: Origine::Reflexif,
            },
            &mut compte,
        );
        // **LA PASSERELLE EN TÊTE** (décision 97) : l'adresse observée, le
        // port accordé — s'il n'est pas déjà celui du bail.
        let passerelle = self
            .passerelle
            .filter(|passerelle| self.echo && passerelle.port != self.vu_depuis.port);
        if let Some(passerelle) = passerelle {
            poser(
                Candidat {
                    protocole: point.protocole,
                    adresse: self.vu_depuis.adresse,
                    port: passerelle.port,
                    origine: Origine::Reflexif,
                },
                &mut compte,
            );
        }
        for adresse in self.adresses.get(..self.nombre_adresses).unwrap_or(&[]) {
            poser(
                Candidat {
                    protocole: point.protocole,
                    adresse: *adresse,
                    port: point.port,
                    origine: Origine::Annonce,
                },
                &mut compte,
            );
        }

        // `..compte` est toujours valide : `compte` n'a été incrémenté que
        // lorsque l'écriture a réussi. Un `if let` aurait posé une branche
        // inatteignable, donc du code qu'aucun essai ne peut atteindre et que
        // tout le monde croirait éprouvé.
        let ordonnes = sortie.get_mut(..compte).unwrap_or(&mut []);
        ordonner(ordonnes);
        // L'ordre ordinaire trie par port ; la passerelle, elle, se sonde la
        // première, et on la remet en tête.
        if let Some(passerelle) = passerelle {
            let rang = ordonnes
                .iter()
                .position(|candidat| {
                    candidat.origine == Origine::Reflexif && candidat.port == passerelle.port
                })
                .unwrap_or(0);
            // `..=rang` est toujours valide : la passerelle a été posée, donc
            // la tranche n'est pas vide et `rang` y est.
            let tete = ordonnes.get_mut(..=rang).unwrap_or_default();
            let pas = tete.len().min(1);
            tete.rotate_right(pas);
        }
        compte
    }

    /// Le port que la box a accordé à l'écho, s'il en a un.
    #[must_use]
    pub const fn passerelle(&self) -> Option<Passerelle> {
        self.passerelle
    }

    // ── L'intérieur ─────────────────────────────────────────────────────────

    /// Avance l'horloge : refuse qu'elle recule, et refuse de faire revivre une
    /// session expirée.
    ///
    /// **L'ORDRE DES DEUX CONTRÔLES COMPTE.** Le temps qui recule est examiné
    /// d'abord : sur une horloge monotone il ne peut pas arriver, donc c'est le
    /// symptôme le plus grave — un appelant qui mélange deux horloges. Le
    /// signaler comme une expiration enverrait chercher au mauvais endroit.
    fn avancer(&mut self, maintenant: Instant) -> Result<(), Faute> {
        if maintenant < self.dernier_signe {
            return Err(Faute::TempsRecule {
                precedent: self.dernier_signe,
                recu: maintenant,
            });
        }
        if self.expiree(maintenant) {
            return Err(Faute::SessionExpiree {
                dernier_signe: self.dernier_signe,
            });
        }
        self.dernier_signe = maintenant;
        Ok(())
    }

    /// Remplace tous les points, et les met tous à sonder.
    ///
    /// **`zip` plutôt qu'un index**, et ce n'est pas un goût : il borne
    /// naturellement à la plus courte des trois suites, donc à `POINTS_MAX`.
    /// Indexer aurait demandé un `if let` sur chaque écriture — une branche
    /// `None` inatteignable, c'est-à-dire du code qu'aucun essai ne peut
    /// atteindre et que tout le monde croirait éprouvé.
    fn poser_points(&mut self, points: &[PointEcoute]) -> Ordres {
        let mut ordres = Ordres::RIEN;
        let mut compte = 0_usize;
        for ((place, ordre), point) in self
            .joignabilite
            .iter_mut()
            .zip(ordres.a_sonder.iter_mut())
            .zip(points.iter())
        {
            let verdict = if se_sonde(self.echo, *point) {
                *ordre = Some(*point);
                Verdict::EnCours
            } else {
                Verdict::NonSonde {
                    raison: RaisonNonSonde::ProtocoleNonSondable,
                }
            };
            *place = Joignabilite {
                point: *point,
                verdict,
            };
            compte = compte.saturating_add(1);
        }
        self.nombre_points = compte;
        ordres
    }

    /// Remplace les points en GARDANT le verdict de ceux qui n'ont pas bougé.
    fn poser_points_en_gardant(&mut self, points: &[PointEcoute]) -> Ordres {
        let echo = self.echo;
        let anciens = self.joignabilite;
        let anciens_nombre = self.nombre_points;

        let mut ordres = Ordres::RIEN;
        let mut compte = 0_usize;
        for ((place, ordre), point) in self
            .joignabilite
            .iter_mut()
            .zip(ordres.a_sonder.iter_mut())
            .zip(points.iter())
        {
            let connu = anciens
                .get(..anciens_nombre)
                .unwrap_or(&[])
                .iter()
                .find(|entree| entree.point == *point);

            let verdict = match connu {
                // Le point n'a pas bougé : son verdict non plus. Le remettre à
                // `EnCours` perdrait une mesure déjà faite.
                Some(entree) => entree.verdict,
                None if se_sonde(echo, *point) => {
                    *ordre = Some(*point);
                    Verdict::EnCours
                }
                None => Verdict::NonSonde {
                    raison: RaisonNonSonde::ProtocoleNonSondable,
                },
            };

            *place = Joignabilite {
                point: *point,
                verdict,
            };
            compte = compte.saturating_add(1);
        }
        self.nombre_points = compte;
        ordres
    }
}

/// Ce point se sonde-t-il ? TCP toujours ; UDP pour l'écho seulement — c'est
/// l'exception de C6 (`contraintes.md`), et elle tient ici.
const fn se_sonde(echo: bool, point: PointEcoute) -> bool {
    // Deux protocoles : ce qui n'est pas TCP est UDP.
    point.protocole.se_sonde() || echo
}

/// Toutes les combien l'annuaire resonde un écho tant que son bail tient, et
/// toutes les combien, au plus, une racine sonde du dehors l'écho d'une
/// machine d'un domaine hébergé : **quinze minutes** (décision 92 ; E8, E9).
pub const CADENCE_D_ECHO_MS: u64 = 15 * 60 * 1_000;

/// Cette adresse est-elle **globale** — joignable de l'Internet ? Ni privée,
/// ni de bouclage, ni lien-local, ni ULA, ni partagée (`100.64.0.0/10`), ni
/// non spécifiée ou multidiffusion ; une IPv4 enfouie (`::ffff:a.b.c.d`) se
/// juge comme elle-même ; en IPv6, `2000::/3` seulement.
///
/// **C'est la borne des sondes des racines vers un écho qu'un annuaire local
/// leur rapporte** (décision 92) : l'adresse est désignée par un tiers, et
/// une racine n'envoie rien vers ce qui n'est pas l'Internet.
#[must_use]
pub fn adresse_globale(adresse: IpAddr) -> bool {
    match adresse.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || a == 0
                || (a == 100 && (b & 0xC0) == 64))
        }
        IpAddr::V6(v6) => {
            let [premier, ..] = v6.segments();
            (premier & 0xE000) == 0x2000
        }
    }
}

/// **Une racine doit-elle sonder, du dehors, l'écho à cette adresse ?**
/// (Décision 92 ; E8.) Seulement vers une adresse globale, et une fois par
/// changement — une autre adresse, un autre port — ou au plus toutes les
/// [`CADENCE_D_ECHO_MS`].
#[must_use]
pub fn sonder_du_dehors(
    cible: core::net::SocketAddr,
    derniere: Option<(core::net::SocketAddr, Instant)>,
    maintenant: Instant,
) -> bool {
    if !adresse_globale(cible.ip()) {
        return false;
    }
    match derniere {
        None => true,
        Some((avant, quand)) => avant != cible || maintenant.depuis(quand) >= CADENCE_D_ECHO_MS,
    }
}

/// Le daemon est-il derrière un NAT ?
///
/// # LA COMPARAISON QUE PERSONNE D'AUTRE NE PEUT FAIRE
///
/// Le daemon ne sait pas comment on le voit ; l'annuaire ne sait pas ce que le
/// daemon croit être. C'est ici, et seulement ici, que les deux se rencontrent.
///
/// **Aucune adresse annoncée veut dire INDÉTERMINÉ, pas « non ».** Répondre
/// « non » sans avoir comparé serait affirmer une chose qu'on n'a pas mesurée —
/// et un daemon derrière un NAT qui lirait « non » chercherait la panne partout
/// sauf là où elle est (contrainte C6).
fn verdict_nat(vu_depuis: VuDepuis, adresses: &[IpAddr]) -> VerdictNat {
    if adresses.is_empty() {
        return VerdictNat::Indetermine;
    }
    if adresses.contains(&vu_depuis.adresse) {
        VerdictNat::Non
    } else {
        VerdictNat::Oui
    }
}
