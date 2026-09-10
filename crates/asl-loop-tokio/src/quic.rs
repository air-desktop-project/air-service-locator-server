//! L'écoute QUIC : une socket, une carte, une boucle.
//!
//! # CE MODULE NE DÉCIDE RIEN, ET C'EST TOUT L'INTÉRÊT
//!
//! Le tri d'un datagramme est dans `ams_quic::Incoming`, la protection de paquet
//! dans `ams-quic-crypto`, la poignée de main dans `ams-quic-tls`, et ce qu'une
//! connexion répond dans `ams_quic_tls::Connection`. **Tout cela est couvert à
//! 100 % chez l'amont** parce que rien de tout cela ne touche à une socket.
//!
//! Il reste ici trois choses, et elles ne sont que du rangement :
//!
//!   1. **une socket**, et de quoi lire et écrire des datagrammes ;
//!   2. **une carte** des identifiants de connexion vers les connexions ;
//!   3. **une boucle** qui attend le prochain datagramme ou le prochain délai.
//!
//! # UNE SEULE TÂCHE, ET NON UNE PAR CONNEXION
//!
//! TCP donne une socket par connexion ; UDP n'en donne qu'une pour tout le
//! monde. Une tâche par connexion demanderait de recopier chaque datagramme vers
//! une file, et de partager la socket d'émission — **deux synchronisations pour
//! un travail qui tient dans une boucle**.
//!
//! La contrepartie est écrite : une connexion coûteuse retarde les autres. C'est
//! tenable tant qu'aucune ne fait d'entrée-sortie bloquante, ce qui est le cas —
//! l'étage 2 ne touche ni au disque ni au réseau, par construction.
//!
//! # LA CONNEXION EST LE BAIL, ET CETTE BOUCLE EST DONC LE CŒUR DU PRODUIT
//!
//! Ailleurs, une boucle réseau est de la plomberie. Ici, **la durée de vie d'une
//! connexion EST la durée de vie d'une annonce** : un daemon qui se tait cesse
//! d'être annoncé, et c'est [`Application::on_closed`] qui le constate. Ce n'est
//! pas un détail d'implémentation qu'on pourrait déplacer — c'est la mécanique
//! que `docs/modele.md` décrit.
//!
//! # ON NE SUIT PAS LES MIGRATIONS
//!
//! §9 de RFC 9000 permet à une connexion de changer d'adresse. Nous ne la
//! suivons pas : une connexion qui change d'adresse est une connexion qu'on
//! cesse de servir. Les suivre demande de valider le nouveau chemin, faute de
//! quoi un attaquant qui rejoue un paquet ferait rediriger le trafic vers sa
//! victime.
//!
//! **Et ici cela a un sens de plus** : l'adresse d'où un daemon parle est une
//! DONNÉE de l'annuaire, pas seulement un chemin de retour. Une adresse qui
//! change en silence ferait annoncer un service à une adresse que personne n'a
//! vérifiée.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use ams_proto_quic::{ConnectionId, StreamId};
use ams_quic::{Incoming, LOCAL_CONNECTION_ID_OCTETS, RecvState, Route};
use ams_quic_tls::Connection;
use rustls::ServerConfig;
use tokio::net::UdpSocket;

/// Ce qu'un datagramme peut occuper au plus.
///
/// **SOIXANTE-CINQ MILLE OCTETS, ET NON MILLE DEUX CENTS.** §14 borne ce qu'on
/// ÉMET, pas ce qu'on reçoit : un pair a le droit de nous écrire un datagramme
/// plus grand, et le tronquer ferait échouer l'authentification de son dernier
/// paquet — pour une raison qu'aucun des deux côtés ne saurait nommer.
const RECEPTION_OCTETS_MAX: usize = 65_535;

/// Combien de fois on rappelle l'application sur un même flux, en un tour.
///
/// **C'EST NOTRE BORNE, PAS LA SIENNE** : une application qui prendrait un octet
/// à la fois ferait tourner la boucle autant de fois qu'il y a d'octets, pendant
/// que les autres connexions attendent. Ce qui reste sera lu au tour suivant.
const LECTURES_MAX: u32 = 64;

/// Combien de temps on continue de servir après le signal d'arrêt, en
/// microsecondes.
///
/// §5.2 de RFC 9114 : « After allowing time for any in-flight requests or pushes
/// to arrive, the endpoint can send another GOAWAY. » Sans ce délai, une requête
/// déjà sur le fil au moment du signal serait refusée alors qu'elle aurait
/// abouti — et le client la rejouerait pour rien.
///
/// **C'est un plafond, pas une attente** : dès que toutes les connexions se sont
/// tues, on n'attend plus.
pub const GRACE_EXTINCTION_US: u64 = 5_000_000;

/// Ce qu'une écoute a compté.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Comptes {
    /// Connexions ouvertes.
    pub acceptees: u64,
    /// `Initial` refusés faute de place.
    pub refusees: u64,
    /// Datagrammes jetés, toutes raisons confondues.
    pub jetes: u64,
    /// Connexions terminées.
    pub fermees: u64,
}

/// Une connexion vivante, et l'adresse d'où elle parle.
struct Vivante {
    /// Ce qui décide, et qui ne touche à rien.
    conduite: Connection,
    /// A-t-on déjà dit à l'application que cette connexion était établie ?
    ///
    /// **UNE FOIS, ET UNE SEULE** : c'est là qu'une application ouvre ses flux
    /// de contrôle, et les rouvrir à chaque datagramme épuiserait le plafond de
    /// §4.6 en quelques tours.
    etablie_dite: bool,
    /// D'où le pair écrit.
    pair: SocketAddr,
    /// L'identifiant que le CLIENT avait inventé pour nous joindre.
    ///
    /// # SANS LUI, UN `ClientHello` EN DEUX PAQUETS NE PASSE PAS
    ///
    /// §7.2 : un client invente un identifiant de destination et le garde
    /// **jusqu'à ce qu'il ait vu le nôtre**. Tant qu'il ne l'a pas vu, tous ses
    /// paquets portent celui-là — et un `ClientHello` qui ne tient pas dans un
    /// datagramme en occupe deux, envoyés d'affilée, avant toute réponse.
    ///
    /// Une carte qui ne connaîtrait que les identifiants QU'ON A DISTRIBUÉS
    /// prendrait donc le second paquet pour une connexion neuve. Chaque moitié
    /// du `ClientHello` atterrirait dans une connexion différente, et les deux
    /// attendraient l'autre moitié pour toujours — sans faute, sans message, et
    /// sans qu'aucun essai en boucle locale ne le voie, parce qu'un banc qui ne
    /// tient qu'une connexion route tout vers elle.
    ///
    /// **C'EST LE CAS ORDINAIRE, PAS UN CAS LIMITE** : un `ClientHello` dépasse
    /// 1200 octets dès qu'il porte un échange de clés post-quantique, ce que les
    /// navigateurs font par défaut depuis 2024.
    ///
    /// Il est oublié dès que la poignée de main aboutit : le client a vu le
    /// nôtre, et il n'emploiera plus jamais celui-ci.
    origine: Option<Vec<u8>>,
}

/// Ce qu'un tour demande à l'écoute.
///
/// # POURQUOI L'APPLICATION NE FERME PAS ELLE-MÊME
///
/// Elle n'a pas les connexions : la boucle les tient, et ne les prête qu'aux
/// rendez-vous liés à L'UNE d'elles. Or une révocation ferme **une AUTRE
/// connexion que celle qui la demande** — le téléphone révoque la machine, et
/// c'est justement l'intérêt.
///
/// Elle rend donc des CONSIGNES, et l'écoute les exécute. C'est la même
/// séparation qu'entre `asl-annuaire` et l'étage 3 : ce qui décide dit quoi
/// faire, ce qui exécute le fait.
#[derive(Debug, Default)]
pub struct Consignes {
    /// Les connexions à fermer, par identifiant local.
    ///
    /// **Vide au tour ordinaire**, et un `Vec` vide n'alloue pas : ce
    /// rendez-vous passe des milliers de fois par seconde.
    pub a_fermer: Vec<Vec<u8>>,
    /// Ce qu'il faut écrire sur une connexion, par identifiant local.
    ///
    /// # POURQUOI CE N'EST PAS L'APPLICATION QUI ÉCRIT DIRECTEMENT
    ///
    /// [`Application::au_tour`] est le seul rendez-vous qui n'appartienne à
    /// aucune connexion — c'est tout son objet : recueillir le résultat d'un
    /// travail lancé ailleurs. **Il n'a donc AUCUNE connexion sous la main**,
    /// et un verdict de sonde arrive précisément là.
    ///
    /// Une consigne dit ce qu'il faut écrire et où ; l'écoute, qui tient les
    /// connexions, redonne la main à l'application avec la bonne. C'est le même
    /// mécanisme que [`Consignes::a_fermer`], et pour la même raison.
    ///
    /// **Vide au tour ordinaire**, comme l'autre.
    pub a_pousser: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Ce qu'une application fait des flux d'une connexion.
///
/// # LA BOUCLE CONDUIT LE TRANSPORT, CETTE INTERFACE DÉCIDE DU RESTE
///
/// L'écoute sait ouvrir un paquet, compter un crédit et retransmettre ; **elle
/// ne sait pas ce qu'un octet veut dire**, et n'a pas à le savoir.
///
/// Une implémentation ne fait aucune entrée-sortie : elle lit avec
/// `Connection::read`, répond avec `write` et `finish`, et c'est l'écoute qui
/// décide quand ces octets partent et comment ils sont retransmis.
///
/// # ELLE SAIT D'OÙ L'ON PARLE, ET C'EST UNE DONNÉE DU PRODUIT
///
/// Chaque rendez-vous porte l'adresse du pair. Ce n'est pas ici un signal
/// d'abus — `air-mail-server` la passe pour son garde, que nous n'avons pas —,
/// c'est **la matière première de l'annuaire** : `asl-proto` note d'où un
/// service a été vu (`Origine`, `VuDepuis`), et cette adresse-là est la seule
/// qu'on ait CONSTATÉE plutôt qu'entendue. La garder pour la boucle serait la
/// perdre.
pub trait Application {
    /// Un tour de boucle vient de passer.
    ///
    /// # POURQUOI CE RENDEZ-VOUS EXISTE
    ///
    /// Tous les autres sont liés à une connexion : un datagramme est arrivé,
    /// un flux est lisible, une connexion s'éteint. **Il manquait un endroit où
    /// faire ce qui n'appartient à personne** — recueillir le résultat d'un
    /// travail qu'on a lancé ailleurs, oublier ce qui a expiré.
    ///
    /// Il est appelé À CHAQUE TOUR, y compris ceux qu'un simple délai a
    /// réveillés : une application qui n'aurait de nouvelles que lorsqu'un pair
    /// parle ne saurait rien pendant qu'il se tait, ce qui est exactement le
    /// moment où les délais échoient.
    fn au_tour(&mut self, _maintenant: u64) -> Consignes {
        Consignes::default()
    }

    /// Une connexion vient de s'établir.
    ///
    /// **C'EST LE PREMIER INSTANT OÙ L'ON PEUT OUVRIR UN FLUX** : avant, les
    /// limites du pair ne sont pas authentifiées (§7.4). HTTP/3 y ouvre ses
    /// trois unidirectionnels — contrôle et QPACK —, que le client attend sans
    /// les avoir demandés.
    fn a_l_etablissement(&mut self, _connexion: &mut Connection, _pair: SocketAddr) {}

    /// Voici la connexion qu'une consigne désignait, et ce qu'il fallait y
    /// écrire.
    ///
    /// **C'EST LE RETOUR DE [`Consignes::a_pousser`]** : l'application a dit
    /// « écris ceci là » depuis un rendez-vous qui n'avait pas de connexion, et
    /// l'écoute la lui rend.
    fn a_pousser(&mut self, _connexion: &mut Connection, _octets: &[u8]) {}

    /// Ce flux a de quoi être lu, ou son pair vient d'en changer l'état.
    ///
    /// Appelé tant qu'il reste des octets prêts : une implémentation qui n'en
    /// lit qu'une partie sera rappelée. **L'état de réception dit le reste** —
    /// `recv_state` distingue un flux terminé d'un flux annulé, et les confondre
    /// ferait servir une requête tronquée.
    fn a_la_lecture(&mut self, connexion: &mut Connection, flux: StreamId, pair: SocketAddr);

    /// Cette connexion s'éteint.
    ///
    /// # C'EST ICI QUE LE BAIL TOMBE
    ///
    /// Pour un serveur ordinaire, ce rendez-vous libère des tampons. Ici il fait
    /// davantage : **la connexion tenue EST le bail d'un daemon**, et sa
    /// disparition est ce qui fait passer ses services de `joignable` à `parti`.
    /// Une implémentation qui l'ignorerait laisserait l'annuaire annoncer des
    /// services que plus personne ne sert.
    fn a_la_fermeture(&mut self, _connexion: &Connection, _pair: SocketAddr) {}

    /// **PREMIER TEMPS DE L'EXTINCTION** : le service s'arrête, dis-le au pair.
    ///
    /// §5.2 de RFC 9114 décrit cette manœuvre en deux temps, et l'écoute n'en
    /// tient que l'horloge : ce qu'on dit au pair appartient à l'application.
    ///
    /// Ici, on dit « n'ouvre plus rien » **sans rien condamner** de ce qui est en
    /// vol. C'est ce qui distingue un arrêt propre d'une porte claquée.
    fn a_l_arret(&mut self, _connexion: &mut Connection, _pair: SocketAddr) {}

    /// **SECOND TEMPS** : le délai de grâce est écoulé, dis jusqu'où tu es allé.
    ///
    /// **ELLE ÉCRIT, ELLE NE FERME PAS.** Une connexion en fermeture n'émet plus
    /// un seul octet de flux — seulement son `CONNECTION_CLOSE` —, donc fermer
    /// ici jetterait ce qu'on vient d'écrire. L'écoute émet d'abord, ferme
    /// ensuite, et [`Application::code_de_fermeture`] dit avec quoi.
    fn a_l_epuisement(&mut self, _connexion: &mut Connection, _pair: SocketAddr) {}

    /// Le code applicatif dont on ferme une extinction réussie (§20.2).
    ///
    /// **LE TRANSPORT N'EN CONNAÎT PAS LE SENS**, et c'est exprès : §20.2 de
    /// RFC 9000 garde l'espace des codes applicatifs pour le protocole qui roule
    /// dessus.
    fn code_de_fermeture(&self) -> u64 {
        0
    }
}

/// Une application qui ne fait rien.
///
/// **ELLE N'EST PAS UN BOUCHON** : un serveur QUIC sans application sert quand
/// même la poignée de main, les acquittements et le contrôle de flux, et c'est
/// exactement ce qu'on veut pour éprouver le transport seul.
#[derive(Debug, Clone, Copy, Default)]
pub struct SansApplication;

impl Application for SansApplication {
    fn a_la_lecture(&mut self, _connexion: &mut Connection, _flux: StreamId, _pair: SocketAddr) {}
}

/// Sert QUIC sur cette socket, jusqu'à l'arrêt.
///
/// # `connexions_max` EST UNE BORNE DE MÉMOIRE, ET DONC UNE DÉFENSE
///
/// Chaque connexion tient des fenêtres de réassemblage, des tables de paquets
/// émis et une poignée de main TLS — quelques dizaines de kibioctets. Sans
/// borne, **il suffirait d'envoyer des `Initial` pour épuiser la mémoire**, et
/// ces paquets-là ne sont authentifiés par personne (§5.2 de RFC 9001).
///
/// Elle vient de l'appelant, et ce qui est demandé est appliqué TEL QUEL : une
/// valeur qu'on raboterait en silence serait une configuration qui dit autre
/// chose que ce qui a été demandé.
///
/// # Errors
///
/// Jamais aujourd'hui — le type est là pour le jour où la socket elle-même
/// deviendra inutilisable. **Une connexion qui échoue ne regarde qu'elle** et ne
/// remonte pas ici.
pub async fn servir_quic<App, Arret>(
    socket: UdpSocket,
    tls: Arc<ServerConfig>,
    connexions_max: usize,
    inactivite_us: u64,
    application: &mut App,
    arret: Arret,
) -> std::io::Result<Comptes>
where
    App: Application,
    Arret: Future<Output = ()>,
{
    let mut ecoute = Ecoute {
        socket,
        tls,
        connexions_max,
        inactivite_us,
        connexions: Vec::new(),
        carte: HashMap::new(),
        comptes: Comptes::default(),
        graine: amorce(),
        ferme_aux_neufs: false,
    };
    let mut arret = core::pin::pin!(arret);
    let mut recu = vec![0_u8; RECEPTION_OCTETS_MAX];
    let mut place = vec![0_u8; RECEPTION_OCTETS_MAX];

    loop {
        // **DEUX LECTURES DE L'HORLOGE, ET C'EST VOULU** : la première dit
        // combien attendre, la seconde dit quand on s'est réveillé. Réemployer
        // la première ferait croire que rien n'a pris de temps, et les délais
        // n'échoiraient jamais.
        let avant = maintenant();
        let attente = ecoute.prochain_delai(avant);
        let arrivee = tokio::select! {
            // `biased` : l'arrêt est examiné EN PREMIER. Un serveur qu'on ne
            // peut pas arrêter sous charge est un serveur qu'on finit par tuer.
            biased;
            // **ON SORT, ON NE REND PAS LA MAIN** : ce qui suit la boucle est
            // l'extinction de §5.2, et rendre ici lâcherait chaque connexion
            // sans un mot.
            () = &mut arret => break,
            () = dormir(attente) => None,
            lu = ecoute.socket.recv_from(&mut recu) => Some(lu),
        };

        let maintenant = maintenant();
        let consignes = application.au_tour(maintenant);
        ecoute.executer(&consignes, application, maintenant);
        ecoute.un_tour(arrivee, &mut recu, application, maintenant);
        ecoute.emettre(&mut place, maintenant).await;
        ecoute.oublier_les_eteintes(application);
    }

    // **PREMIER TEMPS** (§5.2) : « n'ouvre plus rien », et l'on continue de
    // servir. Les octets partent tout de suite : un `GOAWAY` qui attendrait le
    // prochain réveil raccourcirait d'autant le délai de grâce.
    let debut = maintenant();
    ecoute.commencer_l_extinction(application);
    ecoute.emettre(&mut place, debut).await;

    let echeance = debut.saturating_add(GRACE_EXTINCTION_US);
    while maintenant() < echeance && ecoute.il_reste_du_monde() {
        let avant = maintenant();
        // **BORNÉE PAR L'ÉCHÉANCE** : un délai de retransmission plus lointain
        // qu'elle nous ferait dormir au-delà de l'arrêt qu'on a demandé.
        let attente = ecoute
            .prochain_delai(avant)
            .map_or(echeance.saturating_sub(avant), |delai| {
                delai.min(echeance.saturating_sub(avant))
            });
        let arrivee = tokio::select! {
            () = dormir(Some(attente)) => None,
            lu = ecoute.socket.recv_from(&mut recu) => Some(lu),
        };
        let maintenant = maintenant();
        let consignes = application.au_tour(maintenant);
        ecoute.executer(&consignes, application, maintenant);
        ecoute.un_tour(arrivee, &mut recu, application, maintenant);
        ecoute.emettre(&mut place, maintenant).await;
        ecoute.oublier_les_eteintes(application);
    }

    // **SECOND TEMPS** : le rang réel de ce qu'on a servi. Il part AVANT la
    // fermeture — une connexion en fermeture n'émet plus un octet de flux, et
    // fermer d'abord jetterait le `GOAWAY` qu'on vient d'écrire.
    let fin = maintenant();
    ecoute.achever_l_extinction(application);
    ecoute.emettre(&mut place, fin).await;
    ecoute.fermer_tout(application, fin);
    ecoute.emettre(&mut place, fin).await;
    ecoute.oublier_les_eteintes(application);
    Ok(ecoute.comptes)
}

/// L'état d'une écoute.
struct Ecoute {
    /// La socket, unique et partagée par toutes les connexions.
    socket: UdpSocket,
    /// De quoi monter une poignée de main.
    tls: Arc<ServerConfig>,
    /// Combien de connexions vivent en même temps, au plus.
    connexions_max: usize,
    /// L'inactivité qu'on annonce aux pairs, en microsecondes.
    inactivite_us: u64,
    /// Les connexions vivantes, par rang.
    connexions: Vec<Vivante>,
    /// Les identifiants qu'on a distribués, vers ces rangs.
    ///
    /// **C'EST LA CARTE QUE `ams_quic::routing` NE TIENT PAS**, et pour cause :
    /// elle alloue. Ce qu'elle contient n'est pas une décision — c'est du
    /// rangement, et le rangement va où l'on peut allouer.
    carte: HashMap<Vec<u8>, usize>,
    /// Ce qu'on a compté.
    comptes: Comptes,
    /// De quoi fabriquer des identifiants qui ne se devinent pas.
    graine: u64,
    /// N'accepte-t-on plus de connexion neuve ?
    ///
    /// **PENDANT L'EXTINCTION, ACCEPTER SERAIT MENTIR** : la connexion qu'on
    /// monterait recevrait un `GOAWAY` dans la seconde, après une poignée de
    /// main complète. Le client la refera ailleurs, et plus vite.
    ferme_aux_neufs: bool,
}

/// Ce que la socket a rendu, ou rien si c'est un délai qui nous a réveillés.
type Arrivee = Option<std::io::Result<(usize, SocketAddr)>>;

impl Ecoute {
    /// Un tour : le datagramme s'il y en a un, puis les délais.
    ///
    /// **LE SERVICE A LIEU APRÈS LE DATAGRAMME ET AVANT L'ÉMISSION**, pour que
    /// ce que l'application écrit en réponse parte dans le même tour, sans
    /// attendre un réveil de plus.
    fn un_tour<App: Application>(
        &mut self,
        arrivee: Arrivee,
        recu: &mut [u8],
        application: &mut App,
        maintenant: u64,
    ) {
        match arrivee {
            Some(Ok((combien, pair))) => {
                let datagramme = recu.get_mut(..combien).unwrap_or_default();
                self.un_datagramme(datagramme, pair, maintenant);
                self.servir(application);
            }
            // **UNE LECTURE QUI ÉCHOUE N'EST PAS UNE ÉCOUTE QUI S'ARRÊTE.** Sur
            // UDP, `recv_from` peut rendre une erreur qui appartient au
            // datagramme PRÉCÉDENT — un `ICMP port unreachable`, par exemple. La
            // remonter fermerait le service pour la faute d'un tiers.
            Some(Err(_)) => self.comptes.jetes = self.comptes.jetes.saturating_add(1),
            None => {}
        }
        self.les_delais(maintenant);
    }

    /// Un datagramme est arrivé.
    fn un_datagramme(&mut self, datagramme: &mut [u8], pair: SocketAddr, maintenant: u64) {
        let Ok(arrivee) = Incoming::read(datagramme, LOCAL_CONNECTION_ID_OCTETS) else {
            self.comptes.jetes = self.comptes.jetes.saturating_add(1);
            return;
        };
        // **L'ADRESSE FAIT PARTIE DE LA CLÉ**, et pas seulement l'identifiant :
        // c'est ce qui fait qu'on ne suit pas les migrations. Un datagramme qui
        // porte le bon identifiant depuis une autre adresse n'est pas routé.
        let connu = self
            .carte
            .get(arrivee.destination().as_bytes())
            .copied()
            .filter(|rang| self.connexions.get(*rang).is_some_and(|v| v.pair == pair));

        match arrivee.route(connu) {
            Route::Connection(rang) => self.a_une_connexion(rang, datagramme, maintenant),
            Route::New if self.ferme_aux_neufs => {
                self.comptes.jetes = self.comptes.jetes.saturating_add(1);
            }
            Route::New => self.un_client_neuf(&arrivee, datagramme, pair, maintenant),
            // §6.1 : négocier demanderait d'écrire un paquet de version, que ce
            // serveur ne sait pas fabriquer — il ne sert qu'une version. Le
            // jeter laisse le client abandonner de lui-même, ce que §6.2 prévoit.
            Route::Negotiate | Route::Drop(_) => {
                self.comptes.jetes = self.comptes.jetes.saturating_add(1);
            }
        }
    }

    /// Ce datagramme appartient à une connexion en cours.
    fn a_une_connexion(&mut self, rang: usize, datagramme: &mut [u8], maintenant: u64) {
        let Some(vivante) = self.connexions.get_mut(rang) else {
            self.comptes.jetes = self.comptes.jetes.saturating_add(1);
            return;
        };
        // **UNE FAUTE FERME CETTE CONNEXION, ET ELLE SEULE.** Le code de §20.1
        // part au pair pour qu'il sache pourquoi ; sans lui, il attendrait son
        // délai d'inactivité.
        if let Err(issue) = vivante.conduite.on_datagram(datagramme, maintenant) {
            vivante.conduite.close_with(issue.close_code(), maintenant);
        }
    }

    /// Un client neuf frappe à la porte.
    fn un_client_neuf(
        &mut self,
        arrivee: &Incoming,
        datagramme: &mut [u8],
        pair: SocketAddr,
        maintenant: u64,
    ) {
        if self.connexions.len() >= self.connexions_max {
            // §5.2.2 permet un refus explicite ; on jette. Répondre coûterait
            // autant que de servir, et c'est précisément ce qu'un attaquant
            // cherche. Un pair honnête réessaiera.
            self.comptes.refusees = self.comptes.refusees.saturating_add(1);
            return;
        }
        let local = self.un_identifiant();
        let Ok(mut conduite) = Connection::accept(
            Arc::clone(&self.tls),
            arrivee,
            local,
            arrivee.source(),
            self.inactivite_us,
            maintenant,
        ) else {
            self.comptes.jetes = self.comptes.jetes.saturating_add(1);
            return;
        };
        if conduite.on_datagram(datagramme, maintenant).is_err() {
            self.comptes.jetes = self.comptes.jetes.saturating_add(1);
            return;
        }
        let rang = self.connexions.len();
        self.carte.insert(local.as_bytes().to_vec(), rang);
        // **LES DEUX CLÉS DÉSIGNENT LA MÊME CONNEXION**, voir `Vivante::origine`.
        //
        // Deux clients qui inventeraient le même identifiant se marcheraient
        // dessus ; c'est huit octets tirés au hasard, donc un événement qu'on
        // n'observera pas, et le perdant réessaierait de toute façon.
        let origine = arrivee.destination().as_bytes().to_vec();
        self.carte.insert(origine.clone(), rang);
        self.connexions.push(Vivante {
            conduite,
            pair,
            etablie_dite: false,
            origine: Some(origine),
        });
        self.comptes.acceptees = self.comptes.acceptees.saturating_add(1);
    }

    /// Exécute ce que l'application a demandé.
    ///
    /// # FERMER EST IMMÉDIAT, ET C'EST CE QU'ON PROMET
    ///
    /// `au_tour` passe AVANT la lecture du datagramme arrivé : une connexion
    /// qu'une révocation condamne au tour N est fermée au début du tour N+1,
    /// donc **avant qu'une seule de ses requêtes ne soit servie de plus**.
    ///
    /// Un identifiant qu'on ne retrouve pas n'est pas une faute : la connexion a
    /// pu tomber d'elle-même entre la décision et son exécution, et c'est
    /// exactement le résultat qu'on voulait.
    fn executer<App: Application>(
        &mut self,
        consignes: &Consignes,
        application: &mut App,
        maintenant: u64,
    ) {
        // **LES POUSSÉES D'ABORD, LES FERMETURES ENSUITE.** Une connexion qu'on
        // ferme n'émet plus un octet de flux : pousser après fermer jetterait ce
        // qu'on vient d'écrire, sans le dire.
        for (clef, octets) in &consignes.a_pousser {
            let Some(rang) = self.carte.get(clef.as_slice()).copied() else {
                continue;
            };
            let Some(vivante) = self.connexions.get_mut(rang) else {
                continue;
            };
            if vivante.conduite.is_closed() {
                continue;
            }
            application.a_pousser(&mut vivante.conduite, octets);
        }

        if consignes.a_fermer.is_empty() {
            return;
        }
        let code = application.code_de_fermeture();
        for clef in &consignes.a_fermer {
            let Some(rang) = self.carte.get(clef.as_slice()).copied() else {
                continue;
            };
            let Some(vivante) = self.connexions.get_mut(rang) else {
                continue;
            };
            if vivante.conduite.is_closed() {
                continue;
            }
            vivante.conduite.close_with(code, maintenant);
        }
    }

    /// Le prochain délai à attendre, en microsecondes.
    fn prochain_delai(&self, maintenant: u64) -> Option<u64> {
        self.connexions
            .iter()
            .filter_map(|vivante| vivante.conduite.deadline(maintenant))
            .min()
            .map(|quand| quand.saturating_sub(maintenant))
    }

    /// Fait échoir ce qui doit l'être.
    fn les_delais(&mut self, maintenant: u64) {
        for vivante in &mut self.connexions {
            let echue = vivante
                .conduite
                .deadline(maintenant)
                .is_some_and(|quand| quand <= maintenant);
            if echue {
                vivante.conduite.on_timeout(maintenant);
            }
        }
    }

    /// Émet ce que chaque connexion a à dire.
    async fn emettre(&mut self, place: &mut [u8], maintenant: u64) {
        for vivante in &mut self.connexions {
            loop {
                let ecrit = match vivante.conduite.poll_transmit(place, maintenant) {
                    Ok(0) => break,
                    Ok(ecrit) => ecrit,
                    Err(issue) => {
                        vivante.conduite.close_with(issue.close_code(), maintenant);
                        break;
                    }
                };
                let paquet = place.get(..ecrit).unwrap_or_default();
                // **UNE ÉMISSION QUI ÉCHOUE NE FERME PAS LA CONNEXION.** Un
                // `send_to` peut refuser pour une raison qui ne la concerne pas
                // — un tampon plein, un `ICMP` en retard. Le pair réémettra, et
                // le sondage de §6.2 fera repartir ce qui manque.
                if self.socket.send_to(paquet, vivante.pair).await.is_err() {
                    break;
                }
            }
        }
    }

    /// Donne à l'application ce qui est prêt, connexion par connexion.
    ///
    /// # POURQUOI RELIRE LA LISTE DES FLUX À CHAQUE TOUR
    ///
    /// Tenir une file des flux devenus lisibles demanderait de la maintenir
    /// juste — à l'arrivée d'un octet, à la lecture d'un autre, à l'annulation
    /// d'un flux —, et un oubli s'y verrait comme un flux qui se fige sans
    /// raison. La table est courte : la relire coûte moins que de se tromper.
    ///
    /// **ON RAPPELLE TANT QU'IL RESTE DE QUOI LIRE**, mais pas indéfiniment :
    /// une application qui ne lirait rien ferait autrement tourner la boucle
    /// sans fin, et c'est nous que cela arrêterait, pas elle.
    fn servir<App: Application>(&mut self, application: &mut App) {
        for vivante in &mut self.connexions {
            if !vivante.conduite.is_established() {
                continue;
            }
            let pair = vivante.pair;
            if !vivante.etablie_dite {
                vivante.etablie_dite = true;
                // **L'IDENTIFIANT D'ORIGINE A FINI SON OFFICE.** Le client a vu
                // le nôtre — c'est ce qu'« établie » veut dire — et il ne
                // réemploiera plus celui qu'il avait inventé. Le garder
                // laisserait une seconde porte vers cette connexion, ouverte à
                // qui a vu passer le premier paquet en clair.
                if let Some(origine) = vivante.origine.take() {
                    self.carte.remove(&origine);
                }
                application.a_l_etablissement(&mut vivante.conduite, pair);
            }
            let flux: Vec<StreamId> = vivante.conduite.streams_alive().collect();
            for un in flux {
                let mut tours = 0_u32;
                while tours < LECTURES_MAX {
                    let avant = vivante.conduite.readable(un);
                    let etat = vivante.conduite.recv_state(un);
                    // Rien à lire, et rien de neuf à dire : on passe.
                    if avant == 0
                        && !matches!(etat, Some(RecvState::DataRecvd | RecvState::ResetRecvd))
                    {
                        break;
                    }
                    application.a_la_lecture(&mut vivante.conduite, un, pair);
                    // **L'APPLICATION N'A RIEN PRIS NI RIEN CONCLU** : la
                    // rappeler ne donnerait que le même appel.
                    if vivante.conduite.readable(un) == avant
                        && vivante.conduite.recv_state(un) == etat
                    {
                        break;
                    }
                    tours = tours.saturating_add(1);
                }
            }
        }
    }

    /// Dit à chaque connexion établie que le service s'arrête (§5.2).
    ///
    /// **SEULEMENT AUX ÉTABLIES** : une poignée de main en cours n'a pas de pair
    /// à qui parler, et lui écrire sur un flux qui n'existe pas encore ne dirait
    /// rien à personne.
    fn commencer_l_extinction<App: Application>(&mut self, application: &mut App) {
        self.ferme_aux_neufs = true;
        for vivante in &mut self.connexions {
            if !vivante.conduite.is_established() {
                continue;
            }
            application.a_l_arret(&mut vivante.conduite, vivante.pair);
        }
    }

    /// Le délai de grâce est écoulé : chaque connexion dit son dernier mot.
    fn achever_l_extinction<App: Application>(&mut self, application: &mut App) {
        for vivante in &mut self.connexions {
            if !vivante.conduite.is_established() {
                continue;
            }
            application.a_l_epuisement(&mut vivante.conduite, vivante.pair);
        }
    }

    /// Ferme ce qui reste, avec le code que l'application donne.
    ///
    /// **APRÈS L'ÉMISSION, ET JAMAIS AVANT** : une connexion en fermeture n'émet
    /// plus que son `CONNECTION_CLOSE`, et fermer plus tôt jetterait ce que
    /// [`Application::a_l_epuisement`] vient d'écrire.
    fn fermer_tout<App: Application>(&mut self, application: &App, maintenant: u64) {
        let code = application.code_de_fermeture();
        for vivante in &mut self.connexions {
            if vivante.conduite.is_closed() {
                continue;
            }
            vivante.conduite.close_with(code, maintenant);
        }
    }

    /// Reste-t-il une connexion à qui l'on doive quelque chose ?
    fn il_reste_du_monde(&self) -> bool {
        self.connexions.iter().any(|v| !v.conduite.is_closed())
    }

    /// Retire ce qui s'est éteint.
    ///
    /// # LES RANGS BOUGENT, ET LA CARTE AVEC
    ///
    /// On compacte le vecteur plutôt que d'y laisser des trous : un trou serait
    /// un rang qu'on peut encore trouver dans la carte, et donc un datagramme
    /// remis à une connexion qui n'existe plus.
    fn oublier_les_eteintes<App: Application>(&mut self, application: &mut App) {
        if !self.connexions.iter().any(|v| v.conduite.is_closed()) {
            return;
        }
        let mut restantes = Vec::with_capacity(self.connexions.len());
        let mut carte = HashMap::with_capacity(self.carte.len());
        for vivante in core::mem::take(&mut self.connexions) {
            if vivante.conduite.is_closed() {
                self.comptes.fermees = self.comptes.fermees.saturating_add(1);
                // **C'EST ICI QUE LE BAIL TOMBE.** Voir `Application`.
                application.a_la_fermeture(&vivante.conduite, vivante.pair);
                continue;
            }
            carte.insert(
                vivante.conduite.local_id().as_bytes().to_vec(),
                restantes.len(),
            );
            // **L'IDENTIFIANT D'ORIGINE SURVIT À LA RECONSTRUCTION**, sans quoi
            // une connexion en cours de poignée de main perdrait la moitié de
            // son `ClientHello` au premier ménage.
            if let Some(origine) = &vivante.origine {
                carte.insert(origine.clone(), restantes.len());
            }
            restantes.push(vivante);
        }
        self.connexions = restantes;
        self.carte = carte;
    }

    /// Un identifiant de connexion qui ne se devine pas.
    ///
    /// # POURQUOI IL NE DOIT PAS SE DEVINER
    ///
    /// §5.1 : « an endpoint MUST NOT use a connection ID that can be used to
    /// correlate connections. » Un identifiant prévisible laisserait un
    /// observateur relier deux connexions du même client, et laisserait un tiers
    /// fabriquer des paquets qu'on attribuerait à quelqu'un d'autre — jusqu'à
    /// l'échec de l'authentification, qui coûte un déchiffrement.
    fn un_identifiant(&mut self) -> ConnectionId {
        // Un générateur congruentiel : il ne prétend pas être cryptographique,
        // et la graine vient de l'horloge et de l'adresse de la pile. §5.1 ne
        // demande pas d'imprévisibilité cryptographique — elle demande qu'on ne
        // puisse pas CORRÉLER, et huit octets tirés ainsi n'ont pas de motif.
        loop {
            self.graine = self
                .graine
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let octets = self.graine.to_be_bytes();
            if !self.carte.contains_key(&octets[..]) {
                return ConnectionId::new(&octets).unwrap_or(ConnectionId::EMPTY);
            }
        }
    }
}

/// Attend ce délai, ou pour toujours.
async fn dormir(attente: Option<u64>) {
    match attente {
        Some(microsecondes) => {
            tokio::time::sleep(core::time::Duration::from_micros(microsecondes)).await;
        }
        // **PAS DE RÉVEIL PÉRIODIQUE.** Quand aucune connexion n'attend rien, il
        // n'y a rien à faire : se réveiller pour le constater coûterait un
        // changement de contexte par intervalle, pour toujours.
        None => core::future::pending().await,
    }
}

/// L'instant courant, en microsecondes depuis l'époque.
///
/// **EN MICROSECONDES, ET NON EN SECONDES** : les délais de QUIC se comptent en
/// fractions de trajet — un `PTO` vaut quelques dizaines de millisecondes —, et
/// une horloge à la seconde les arrondirait tous à zéro ou à un.
#[must_use]
pub fn maintenant() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |ecoule| {
            u64::try_from(ecoule.as_micros()).unwrap_or(u64::MAX)
        })
}

/// De quoi amorcer le tirage des identifiants.
fn amorce() -> u64 {
    let horloge = maintenant();
    let pile = 0_u8;
    // L'adresse d'une variable de pile varie d'un lancement à l'autre quand
    // l'ASLR est en place ; mêlée à l'horloge, elle évite que deux serveurs
    // démarrés en même temps tirent la même suite.
    let adresse = core::ptr::from_ref(&pile) as u64;
    horloge.wrapping_mul(6_364_136_223_846_793_005) ^ adresse
}
