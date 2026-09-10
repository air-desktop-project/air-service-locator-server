//! Ce qui décide d'une réponse HTTP, **sans entrée-sortie**.
//!
//! # POURQUOI CETTE CRATE EXISTE, PLUTÔT QUE CE CODE DANS LA BOUCLE
//!
//! `ams-h3` demande un `Service` : une fonction qui reçoit une tête de requête
//! et un corps, et qui rend une réponse. **Cette fonction est PURE** — elle
//! n'ouvre rien, n'attend rien, ne lit pas l'heure.
//!
//! La loger dans `asl-loop-tokio` aurait mis le traitement des requêtes du
//! produit entier hors du régime de couverture, sous prétexte que le voisin
//! tient une socket. Ce n'est pas un rangement : c'est la frontière entre
//! l'étage 2 et l'étage 3, et elle passe exactement ici.
//!
//! # CE QU'ELLE DÉCIDE AUJOURD'HUI
//!
//! Trois choses, et elles ne demandent aucun état :
//!
//!   1. **Le verbe est-il servi ?** `HEAD` est un `GET` sans corps (§9.3.2 de
//!      RFC 9110) ; `OPTIONS` ne l'est pas.
//!   2. **La cible se route-t-elle ?** C'est `asl_api::resoudre` qui répond, et
//!      la traduction de son refus en code de statut suit UNE règle : `404` pour
//!      une cible bien formée qui ne désigne rien, `400` pour une cible qui
//!      n'est pas bien formée. Confondre les deux dirait à un client de corriger
//!      son URL quand c'est sa syntaxe qui est fautive.
//!   3. **Le corps tient-il dans la borne ?** Voir [`CORPS_OCTETS_MAX`].
//!
//! # ELLE NE LIT PAS L'ENTREPÔT : ELLE DIT CE QU'IL LUI FAUT
//!
//! C'est le point d'architecture de cette crate, et il mérite d'être défendu
//! contre la solution qu'on aurait prise naturellement.
//!
//! **La solution naturelle** serait un trait `Vue` — « donne-moi un compte » —
//! que l'étage 3 implémenterait et qu'on passerait ici. Le code de cette crate
//! resterait sans entrée-sortie, et `check-etages.sh` ne verrait rien à redire.
//!
//! **Elle serait fausse quand même.** La règle de l'étage 2 n'est pas « ne pas
//! écrire d'entrée-sortie », c'est **« ne jamais attendre »**. Une décision qui
//! appelle un trait dont l'implémentation ouvre un fichier attend, et personne
//! ne le voit — ni le compilateur, ni la barrière, ni le lecteur.
//!
//! Donc [`besoin`] dit ce qu'il faut chercher, l'étage 3 va le chercher, et
//! [`repondre`] répond. **C'est le même partage qu'`asl_annuaire::Ordres`**, à
//! ceci près qu'un ordre part sans retour quand un besoin en attend un.
//!
//! # POURQUOI DEUX FONCTIONS PLUTÔT QU'UNE MACHINE À ÉTATS
//!
//! Une `Session` qui retiendrait le besoin en cours entre les deux appels
//! **mélangerait deux requêtes concurrentes** : HTTP/3 sert plusieurs flux sur
//! une même connexion, et la session est par connexion. Le besoin est donc
//! rendu à l'appelant, qui le lui rend — il vit sur la pile de la requête, et
//! nulle part ailleurs.
//!
//! # L'AUTHENTIFICATION EST PORTÉE PAR LA CONNEXION
//!
//! `protocole.md` §3 : la clé est prouvée UNE FOIS à l'établissement, et toutes
//! les requêtes de cette connexion en héritent. Il n'y a pas de jeton à joindre,
//! donc pas de jeton à intercepter, à rejouer, ni à expirer.
//!
//! C'est pourquoi la machine authentifiée vit dans la [`Session`], qui est par
//! connexion — et pourquoi le défi y vit aussi. **Les deux disparaissent avec la
//! connexion**, ce qui est exactement la durée de validité qu'on veut.
//!
//! ## LE DÉFI EST À USAGE UNIQUE, ET CE N'EST PAS UNE PRÉCAUTION DE PLUS
//!
//! La liaison de canal dont ce produit dispose aujourd'hui est l'empreinte du
//! CERTIFICAT, pas un exporteur de session (voir `asl_cle::LiaisonDeCanal`).
//! Elle ne distingue donc pas deux connexions au même serveur — **c'est le défi
//! qui les sépare**. Le relâcher rendrait une signature rejouable d'une
//! connexion à l'autre.
//!
//! Il est donc consommé qu'il vérifie ou non : une signature fausse coûte un
//! défi, et l'on recommence. Le garder après un échec laisserait un attaquant
//! essayer autant de signatures qu'il veut contre un même défi.

#![no_std]

extern crate alloc;

use ams_h3::Reponse;
use ams_proto_http::{Method, RequestHead, StatusCode};
use asl_api::corps::{
    AutorisationRendue, Capacites, DeclarationMachine, DemandeAlias, DemandeAutorisation,
    DepotJeton, ModificationMachine, Plateforme, Portee,
};
use asl_api::{Exigence, Ressource};
use asl_cle::{ClePublique, Defi, LiaisonDeCanal, Signature};
use asl_cle::{CodeEnrolement, TexteCode};
use asl_id::{Genre, Identifiant};
use asl_registre::AliasRange;

/// **CE QU'UNE GRAMMAIRE ACCEPTE, L'AUTRE DOIT POUVOIR LE RANGER.**
///
/// `asl-api` borne le nom d'une machine, `asl-registre` borne ce qu'il range, et
/// **les deux crates ne se connaissent pas**. Celle-ci connaît les deux : si les
/// bornes divergeaient, un nom bien formé serait accepté par le routage puis
/// refusé par l'entrepôt, et l'utilisateur recevrait un `500` pour une requête
/// juste. L'assertion fait échouer la COMPILATION plutôt que la requête.
const _: () = assert!(
    asl_api::corps::NOM_MACHINE_MAX == asl_registre::NOM_OCTETS_MAX,
    "le nom d'une machine ne se range pas : les deux bornes ont divergé"
);

/// Ce qu'un corps de requête peut faire, en octets.
///
/// # POURQUOI SI PETIT
///
/// `ams-h3` borne déjà un corps à 64 kibioctets, et cette borne-là protège la
/// MÉMOIRE. Celle-ci protège autre chose : **aucun corps de cette API n'est un
/// document.** On y poste un identifiant, une clé publique, une signature, un
/// alias — les plus gros tiennent en quelques centaines d'octets.
///
/// Une borne qui colle à ce qu'on attend transforme un corps aberrant en `413`
/// immédiat, avant qu'une seule ligne d'analyse ne le regarde.
pub const CORPS_OCTETS_MAX: usize = 8 * 1024;

/// Le type de média des réponses d'erreur (RFC 9457).
pub const PROBLEME_MEDIA: &[u8] = b"application/problem+json";

/// Le type de média des réponses ordinaires.
pub const JSON_MEDIA: &[u8] = b"application/json";

/// Ce qu'une preuve occupe : l'identifiant de la machine, puis sa signature.
///
/// # POURQUOI DES OCTETS BRUTS, ET NON DU JSON
///
/// C'est l'argument d'`asl_cle::message_a_signer`, appliqué au transport de la
/// preuve : **des champs de longueur fixe, aucun préfixe, aucune ambiguïté.**
/// Un cadrage JSON demanderait un analyseur, un encodage des octets de la
/// signature, et deux écritures possibles du même contenu — sur un chemin
/// cryptographique, c'est trois occasions de se tromper pour zéro gain.
///
/// Quatre-vingt-un octets, toujours : dix-sept d'identifiant, soixante-quatre de
/// signature.
pub const PREUVE_OCTETS: usize = 17 + asl_cle::SIGNATURE_OCTETS;

/// Ce qu'une **preuve de possession** occupe : la clé, puis sa signature.
///
/// # POURQUOI DES OCTETS BRUTS ICI AUSSI
///
/// C'est l'argument de [`PREUVE_OCTETS`], et il vaut pour tout corps qui porte
/// une clé ou une signature : des champs de longueur fixe, aucun préfixe, aucune
/// ambiguïté. Un cadrage JSON demanderait d'encoder ces octets, donc deux
/// écritures possibles du même contenu — sur un chemin cryptographique, trois
/// occasions de se tromper pour zéro gain.
///
/// Quatre-vingt-seize octets, toujours.
pub const POSSESSION_OCTETS: usize = asl_cle::CLE_PUBLIQUE_OCTETS + asl_cle::SIGNATURE_OCTETS;

/// Ce qu'occupe le corps de `POST /v1/appareils` : une clé publique, seule.
///
/// **Aucune preuve de possession ne l'accompagne, et c'est une règle** — voir
/// [`Besoin::CreerAppareil`].
pub const CLE_SEULE_OCTETS: usize = asl_cle::CLE_PUBLIQUE_OCTETS;

/// Ce qu'occupe le corps de `POST /v1/enrolement` : le code, la clé, la preuve.
pub const ENROLEMENT_CORPS_OCTETS: usize = asl_cle::CODE_SYMBOLES + POSSESSION_OCTETS;

/// Le type de média d'un défi et d'une preuve.
pub const OCTETS_MEDIA: &[u8] = b"application/octet-stream";

/// Ce qu'il faut aller chercher pour répondre.
///
/// **Ce n'est pas un effet, c'est un besoin.** L'étage 3 le satisfait ; cette
/// crate ne sait pas ouvrir un fichier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Besoin<'a> {
    /// Rien à chercher : la réponse est déjà décidée, et la voici.
    Deja(StatusCode),
    /// Le défi de cette connexion, à rendre au client.
    DefiATirer,
    /// La clé publique de cette machine, pour vérifier sa preuve.
    ClePourPreuve {
        /// La machine qui prétend être elle.
        machine: Identifiant,
        /// Ce qu'elle a signé.
        signature: Signature,
    },
    /// Le compte de cet identifiant.
    Compte(Identifiant),
    /// Le compte qui porte cet alias.
    CompteParAlias(&'a str),
    /// Ce daemon annonce un service.
    ///
    /// # LE CORPS N'EST PAS DÉCODÉ ICI, ET C'EST DÉLIBÉRÉ
    ///
    /// Une annonce n'est pas une lecture : elle OUVRE une session vivante, qui
    /// n'existe qu'en mémoire et n'appartient qu'à cette connexion. Cet état-là
    /// est de l'étage 3 — c'est lui qui tient le vivier, c'est lui qui le vide
    /// quand la connexion tombe.
    ///
    /// Cette crate ne fait donc que dire « c'est une annonce, et le demandeur a
    /// le droit d'en faire » ; `asl_annuaire::Session::ouvrir` décide du reste,
    /// et `asl_auth::decider_annonce` de la permission.
    Annoncer,
    /// Où se trouve ce service, sur cette machine.
    ///
    /// **CE BESOIN EN CACHE QUATRE** : le demandeur (pour ses capacités et son
    /// propriétaire), le service (par son nom sur cette machine), la machine
    /// visée (pour SON propriétaire), et les autorisations reçues par le
    /// demandeur. C'est l'étage 3 qui les rassemble — voir [`Resolution`].
    Ou {
        /// La machine qui porte le service.
        machine: Identifiant,
        /// Le nom du service.
        service: &'a str,
    },
    /// Toutes les instances d'un service portant ce nom.
    ///
    /// # C'EST LA FORME QUE LE PRODUIT EMPLOIE
    ///
    /// `protocole.md` §3 : « le scénario du produit n'est pas *un service* mais
    /// *le même daemon sur cinq machines* ». Demander une machine à la fois
    /// obligerait le demandeur à connaître les cinq identifiants, **et à les
    /// tenir à jour quand on en ajoute une sixième**.
    ///
    /// Ce besoin en cache autant que [`Besoin::Ou`], multiplié par le nombre
    /// d'instances : l'étage 3 rassemble une [`Resolution`] par candidat, et
    /// c'est ici qu'on décide, une par une, laquelle se rend.
    OuParNom {
        /// Le nom cherché.
        service: &'a str,
    },
    /// Les services d'une machine, avec leur état.
    ///
    /// **CE N'EST PAS LE MÊME PUBLIC QUE [`Besoin::Ou`]** : celui-là est parlé
    /// par une machine qui cherche un port, celui-ci par l'application mobile
    /// qui regarde SES machines. D'où deux exigences différentes — une clé de
    /// machine là-bas, un appareil ici.
    ServicesDeMachine {
        /// La machine dont on veut les services.
        machine: Identifiant,
    },
    /// Les autorisations d'un compte, **dans les deux sens**.
    ///
    /// `protocole.md` §2.2 : « ce que j'ai accordé, ce qu'on m'a accordé ».
    MesAutorisations,
    /// Ouvrir le flux par lequel les verdicts arriveront.
    ///
    /// # IL NE DEMANDE RIEN À L'ÉTAGE 3, ET C'EST POURQUOI IL EST ICI
    ///
    /// La réponse ne dépend d'aucun état : elle est vide, et c'est le FLUX qui
    /// compte. Ce qui s'y écrira ensuite ne passe pas par `repondre` — un
    /// verdict n'est pas une réponse à une requête, il arrive quand la sonde a
    /// fini.
    EcouterLesPoussees,
    /// Une preuve de possession a été présentée, et elle ne vaut pas.
    ///
    /// # POURQUOI CE N'EST PAS UN `Deja(401)`
    ///
    /// Parce que le défi doit être CONSOMMÉ. Une requête qui a dépensé un défi
    /// et n'a rien obtenu doit le dépenser quand même — sinon un attaquant
    /// essaie autant de signatures qu'il veut contre un même défi, ce que ce
    /// produit refuse depuis le premier jour. `Deja` ne le dirait pas :
    /// [`repondre`] ne saurait plus qu'un défi était en jeu.
    PreuveRefusee,
    /// Créer un compte, et enrôler l'appareil qui le demande.
    ///
    /// **LA POSSESSION EST PROUVÉE, ET C'EST UNE RÈGLE GÉNÉRALE** : celui qui
    /// PRÉSENTE une clé signe qu'il la détient. Ici l'appareil parle pour
    /// lui-même, donc il signe.
    CreerCompte {
        /// La clé de l'appareil, dont la possession est déjà prouvée.
        cle: ClePublique,
    },
    /// Enrôler un appareil de plus sur le compte de cette connexion.
    ///
    /// # ET ICI, LA POSSESSION N'EST **PAS** PROUVÉE
    ///
    /// L'autre moitié de la règle. Le nouveau téléphone ne parle pas sur cette
    /// connexion — c'est un appareil DÉJÀ enrôlé qui apporte sa clé, lue d'un
    /// code affiché à l'écran. Exiger une signature du nouveau demanderait qu'il
    /// se connecte lui-même, ce qui rendrait le geste inverse de celui que
    /// `protocole.md` §2.2 décrit : « signé par un appareil déjà enrôlé ».
    ///
    /// **Un compte qui ajoute une clé que personne ne détient n'a nui qu'à
    /// lui-même**, et il lui reste l'appareil qui vient de le faire.
    CreerAppareil {
        /// La clé du nouvel appareil.
        cle: ClePublique,
    },
    /// Déclarer une machine, et émettre son premier code d'enrôlement.
    CreerMachine {
        /// Le nom que l'humain lui donne.
        nom: &'a str,
        /// Ce qu'elle aura le droit de faire.
        capacites: Capacites,
    },
    /// Changer le nom ou les capacités d'une machine qu'on possède.
    ///
    /// # RETIRER LA CAPACITÉ D'ANNONCE FERME LES CONNEXIONS
    ///
    /// C'est l'étage 3 qui ferme — il tient les connexions —, mais la raison est
    /// ici : une capacité retirée qui laisserait courir les baux déjà posés
    /// serait un retrait qui ne retire rien. L'annuaire continuerait de publier
    /// les adresses d'une machine à qui l'on vient d'interdire d'annoncer, et
    /// l'humain qui a décoché la case verrait ses services toujours là.
    ///
    /// **Un changement de nom, lui, ne ferme rien** : il ne retire aucun droit.
    ModifierMachine {
        /// La machine visée.
        machine: Identifiant,
        /// Le nouveau nom, ou `None` pour le laisser.
        nom: Option<&'a str>,
        /// Les nouvelles capacités, ou `None` pour les laisser.
        capacites: Option<Capacites>,
    },
    /// Émettre un nouveau code pour une machine qu'on possède déjà.
    NouveauCode {
        /// La machine visée.
        machine: Identifiant,
    },
    /// Lier une clé à une machine, sur présentation d'un code.
    ///
    /// **L'EMPREINTE, ET NON LE CODE.** L'étage 3 cherche par elle et ne détient
    /// jamais le code — voir `asl_cle::CodeEnrolement::empreinte`.
    Enroler {
        /// Sous quoi le code est rangé.
        empreinte: [u8; asl_cle::EMPREINTE_OCTETS],
        /// La clé que la machine présente, dont la possession est prouvée.
        cle: ClePublique,
    },
    /// Accorder une autorisation à un autre compte.
    Autoriser {
        /// Le bénéficiaire.
        a: Identifiant,
        /// Jusqu'où elle porte.
        portee: Portee,
    },
    /// Savoir d'où l'annuaire voit cette connexion.
    ///
    /// **AUCUN ARGUMENT** : le fait demandé est celui de la connexion elle-même,
    /// et le nommer laisserait croire qu'on peut demander celui d'un autre.
    OuSuisJeVu,
    /// Déposer ou renouveler le jeton de poussée d'un appareil.
    ///
    /// # UN APPAREIL NE DÉPOSE QUE POUR LUI-MÊME
    ///
    /// Le jeton vient du système d'exploitation du téléphone qui le porte :
    /// personne d'autre ne l'a. Un appareil qui en déposerait un pour un autre
    /// détournerait donc les notifications d'un frère vers lui — c'est-à-dire
    /// vers celui qui tient un téléphone volé.
    ///
    /// **Le refus se cache derrière le `404` des autres** : dire « ce n'est pas
    /// vous » à qui vise l'identifiant d'un autre confirmerait que cet
    /// identifiant existe.
    PoserJetonDePoussee {
        /// L'appareil visé, qui doit être celui de cette connexion.
        appareil: Identifiant,
        /// À qui présenter ce jeton.
        plateforme: Plateforme,
        /// Le jeton, tel que la plate-forme l'a donné.
        jeton: &'a str,
    },
    /// Révoquer un appareil du compte de cette connexion.
    ///
    /// **JAMAIS CELUI QUI DEMANDE** : c'est `asl_auth::
    /// decider_revocation_d_appareil` qui le refuse, et son en-tête dit
    /// pourquoi — un téléphone volé et déverrouillé confisquerait le compte.
    RevoquerAppareil {
        /// L'appareil visé.
        appareil: Identifiant,
    },
    /// Retirer la clé d'une machine.
    ///
    /// **EFFET IMMÉDIAT** : la clé s'efface, les connexions que cette machine
    /// tient sont fermées, et ses baux tombent avec elles. C'est l'étage 3 qui
    /// ferme, parce que c'est lui qui tient les connexions.
    RevoquerCleMachine {
        /// La machine visée.
        machine: Identifiant,
    },
    /// Retirer une autorisation qu'on a accordée.
    RevoquerAutorisation {
        /// L'autorisation visée.
        autorisation: Identifiant,
    },
    /// Enregistrer ou changer l'alias public du compte.
    PoserAlias {
        /// L'alias demandé, déjà validé.
        alias: &'a str,
    },
    /// Retirer l'alias public du compte.
    RetirerAlias,
}

/// Ce qu'il faut savoir pour décider d'une résolution.
///
/// # POURQUOI UN TYPE, ET NON QUATRE CHAMPS DANS `Trouvaille`
///
/// Ces quatre lectures ne valent que réunies : décider avec trois sur quatre
/// n'aurait pas de sens, et laisser l'étage 2 les recevoir séparément
/// l'obligerait à vérifier qu'elles vont ensemble. Le type dit qu'elles y vont.
#[derive(Debug, Clone)]
pub struct Resolution {
    /// La machine qui demande, telle qu'`asl-auth` la veut.
    pub demandeur: asl_auth::Machine,
    /// Ce qui est visé.
    pub cible: asl_auth::Cible,
    /// Les autorisations reçues par le propriétaire du demandeur.
    ///
    /// **RÉVOQUÉES COMPRISES** : c'est `asl_auth::Autorisation::couvre` qui les
    /// écarte, et les filtrer ici mettrait cette règle à deux endroits.
    pub autorisations: alloc::vec::Vec<asl_auth::Autorisation>,
    /// Ce qui est annoncé pour ce service, en ce moment, déjà encodé.
    ///
    /// # ELLE EST LUE AVANT LA DÉCISION, ET RÉVÉLÉE APRÈS
    ///
    /// L'étage 3 la rassemble en même temps que le reste — c'est sa propre
    /// mémoire, la lire ne coûte rien et ne dit rien à personne. **Ce qui reste
    /// une décision, c'est de la RENDRE**, et cette décision-là est prise ici,
    /// après `asl_auth::decider_resolution`.
    ///
    /// `None` quand rien n'est annoncé : le service est déclaré, mais aucun
    /// daemon ne tient de connexion pour lui en ce moment.
    pub annonce: Option<alloc::vec::Vec<u8>>,
}

/// Ce que l'étage 3 a trouvé.
/// **ELLE N'EST PLUS `Copy`**, et c'est la résolution qui l'en a privée : ses
/// autorisations sont une liste, dont la longueur ne se connaît qu'à
/// l'exécution. Le reste du produit ne copie jamais une trouvaille — il la passe
/// par référence —, donc cela ne coûte rien.
#[derive(Debug, Clone, Default)]
pub enum Trouvaille {
    /// Rien ne correspond.
    #[default]
    Rien,
    /// Ce compte.
    ///
    /// **Il ne porte que son identifiant et son alias**, et c'est tout ce qu'un
    /// compte EST (C13) : ni courriel, ni numéro, ni nom.
    Compte {
        /// Son identifiant public.
        qui: Identifiant,
        /// Son alias, s'il en a choisi un.
        alias: Option<AliasRange>,
    },
    /// La clé publique de la machine demandée.
    Cle(ClePublique),
    /// D'où l'annuaire voit la connexion qui demande.
    ///
    /// **C'EST LE SEUL FAIT QUE L'ANNUAIRE CONSTATE PLUTÔT QU'IL N'ENTENDE**, et
    /// il ne peut venir que de l'étage 3 : c'est lui qui tient la socket.
    VuDepuis(asl_proto::VuDepuis),
    /// De quoi décider d'une résolution.
    Resolution(Resolution),
    /// De quoi décider d'une LISTE de résolutions.
    ///
    /// # POURQUOI UNE LISTE DE `Resolution`, ET NON UNE LISTE DE RÉPONSES
    ///
    /// Parce que la décision n'est pas prise. L'étage 3 rassemble tout ce qui
    /// PORTE le nom cherché — ou tout ce que porte la machine visée —, et c'est
    /// ici, une par une, qu'`asl_auth::decider_resolution` dit lesquelles se
    /// rendent.
    ///
    /// **Ce qui est écarté ne laisse aucune trace.** Contrairement à la forme
    /// par machine, qui rend `404` aussi bien pour « absent » que pour
    /// « interdit », une liste OMET — et l'omission ne dit rien de ce qu'elle
    /// omet. C'est C10 servie par la forme même de la réponse.
    Resolutions(alloc::vec::Vec<Resolution>),
    /// Les services d'une machine, et de quoi décider s'ils se rendent.
    ///
    /// # POURQUOI CE N'EST PAS UNE [`Trouvaille::Resolutions`]
    ///
    /// Le demandeur n'est pas une machine : c'est un APPAREIL, et
    /// `asl_auth::Machine` ne sait pas le représenter. La décision n'est donc pas
    /// la même — [`asl_auth::decider_services_de_machine`], qui ne regarde
    /// aucune autorisation.
    ServicesDeMachine {
        /// Le compte de l'appareil qui demande.
        demandeur: Identifiant,
        /// Le compte qui possède la machine visée.
        proprietaire: Identifiant,
        /// Ce que chaque service annonce, déjà encodé.
        annonces: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    },
    /// Les autorisations d'un compte, dans les deux sens.
    ///
    /// **RÉVOQUÉES COMPRISES, ET MARQUÉES.** Même raison qu'un appareil révoqué
    /// (`protocole.md` §2.2) : l'écran qu'on regarde après avoir retiré un accès
    /// doit montrer ce qu'on a retiré.
    Autorisations(alloc::vec::Vec<AutorisationRendue>),
    /// L'annonce a été prise, et voici ce qu'il faut répondre.
    ///
    /// Le corps est déjà encodé par `asl_proto::Reponse` — l'étage 3 l'a
    /// composé en même temps qu'il ouvrait la session vivante, parce que la
    /// réponse DÉCRIT cette session.
    Annoncee(alloc::vec::Vec<u8>),
    /// **Une décision a dit non.**
    ///
    /// # ELLE NE SE CONFOND PAS AVEC [`Trouvaille::Rien`]
    ///
    /// `Rien` veut dire « je n'ai pas trouvé », et sur un chemin de CRÉATION
    /// cela ne peut être qu'une panne de notre côté — l'entrepôt a refusé, le
    /// noyau n'a pas donné d'aléa. Cela rend `500`.
    ///
    /// Celle-ci veut dire « j'ai trouvé, et la règle refuse » : l'attestation
    /// manque, la machine appartient à quelqu'un d'autre, le code a expiré. Cela
    /// rend `403`, et un client qui reçoit `500` là où il devait lire `403`
    /// réessaierait sans fin une requête qui ne passera jamais.
    Refus,
    /// Un compte a été créé, et son premier appareil avec lui.
    CompteCree {
        /// Le compte.
        compte: Identifiant,
        /// L'appareil qui vient de le créer.
        appareil: Identifiant,
    },
    /// Un appareil de plus a été enrôlé.
    AppareilCree(Identifiant),
    /// Une machine a été déclarée, et voici son code.
    MachineCreee {
        /// La machine.
        machine: Identifiant,
        /// Le code, **rendu une seule fois**.
        code: TexteCode,
        /// Quand il cesse de valoir, en millisecondes d'époque.
        expire_a: u64,
    },
    /// Un code a été émis pour une machine qui existait déjà.
    CodeEmis {
        /// Le code, **rendu une seule fois**.
        code: TexteCode,
        /// Quand il cesse de valoir, en millisecondes d'époque.
        expire_a: u64,
    },
    /// La clé a été liée à cette machine.
    Enrolee(Identifiant),
    /// Une autorisation a été accordée.
    AutorisationCreee(Identifiant),
    /// C'est fait, et il n'y a rien à rendre.
    ///
    /// Les révocations et l'alias : **la réponse est le fait qu'elle réussisse**.
    /// Rendre l'objet modifié n'apprendrait rien à qui vient de le modifier.
    Fait,
    /// Cet alias appartient déjà à quelqu'un d'autre.
    ///
    /// # CE N'EST NI UN REFUS NI UNE PANNE, ET LE STATUT DOIT LE DIRE
    ///
    /// `403` dirait « vous n'avez pas le droit », ce qui est faux — n'importe
    /// qui a le droit de demander un alias. `500` dirait que la faute est de
    /// notre côté. C'est un CONFLIT : la demande est légitime, et l'état du
    /// monde s'y oppose. Le client doit en proposer un autre, et lui seul peut.
    Conflit,
}

/// Ce qu'une session sait d'une connexion.
///
/// # ELLE PORTE CE QUI NE VAUT QUE POUR CETTE CONNEXION
///
/// La liaison de canal, le défi en cours, et la machine authentifiée. Les trois
/// disparaissent avec la connexion — ce qui est exactement leur durée de
/// validité.
///
/// **Une session partagée entre connexions ferait hériter une requête des droits
/// d'une autre.** C'est la faille qu'on ne peut pas se permettre, et c'est
/// pourquoi ce type n'est ni `Clone` ni `Default`.
#[derive(Debug)]
pub struct Session {
    /// Ce à quoi une signature de cette connexion est liée.
    liaison: LiaisonDeCanal,
    /// Le défi tiré et pas encore consommé.
    defi: Option<Defi>,
    /// Le pair qui a prouvé sa clé sur cette connexion, s'il y en a un.
    ///
    /// # UN SEUL, ET SON GENRE DIT LEQUEL
    ///
    /// Une machine ou un appareil, jamais les deux : une connexion prouve UNE
    /// clé. Deux champs auraient rendu représentable « une machine et un
    /// appareil authentifiés à la fois », état qui ne correspond à rien et qu'il
    /// aurait fallu se rappeler d'interdire à chaque lecture.
    pair: Option<Identifiant>,
}

impl Session {
    /// Une session neuve, liée à ce canal.
    #[must_use]
    pub const fn new(liaison: LiaisonDeCanal) -> Self {
        Self {
            liaison,
            defi: None,
            pair: None,
        }
    }

    /// La machine authentifiée sur cette connexion.
    ///
    /// `None` si c'est un APPAREIL qui a prouvé sa clé : un téléphone n'annonce
    /// pas de service et n'interroge pas l'annuaire.
    #[must_use]
    pub fn machine(&self) -> Option<Identifiant> {
        self.pair.filter(|qui| qui.genre() == Genre::Machine)
    }

    /// Le pair — machine ou appareil — authentifié sur cette connexion.
    ///
    /// **C'est ce qui permet de FERMER ce qu'une révocation ferme.** L'étage 3
    /// cherche les connexions dont le pair vient d'être révoqué ; sans cet
    /// accesseur, il devrait demander deux fois et recoller lui-même.
    #[must_use]
    pub const fn pair(&self) -> Option<Identifiant> {
        self.pair
    }

    /// L'appareil authentifié sur cette connexion.
    ///
    /// `None` si c'est une MACHINE qui a prouvé sa clé : une machine
    /// n'administre pas un compte. C'est la séparation qui fait qu'un daemon
    /// compromis ne peut pas s'accorder des autorisations — il n'a que la clé de
    /// sa machine, et cette clé n'ouvre aucun verbe d'administration.
    #[must_use]
    pub fn appareil(&self) -> Option<Identifiant> {
        self.pair.filter(|qui| qui.genre() == Genre::Appareil)
    }

    /// Range le défi qu'on vient de tirer, et rend ses octets.
    ///
    /// **UN SEUL DÉFI À LA FOIS.** En tirer un second remplace le premier :
    /// deux défis vivants doubleraient les essais qu'un attaquant obtient pour
    /// une même connexion.
    pub fn poser_le_defi(&mut self, defi: Defi) -> [u8; asl_cle::DEFI_OCTETS] {
        self.defi = Some(defi);
        *defi.octets()
    }

    /// Vérifie cette preuve contre le défi en cours, et retient la machine.
    ///
    /// # LE DÉFI EST CONSOMMÉ DANS TOUS LES CAS
    ///
    /// Qu'il vérifie ou non. Le garder après un échec laisserait un attaquant
    /// essayer autant de signatures qu'il veut contre un même défi.
    fn verifier(&mut self, pair: Identifiant, signature: &Signature, cle: &ClePublique) -> bool {
        let Some(defi) = self.defi.take() else {
            return false;
        };
        if !cle.verifie(pair, &defi, &self.liaison, signature) {
            return false;
        }
        self.pair = Some(pair);
        true
    }

    /// Cette signature prouve-t-elle la possession de cette clé ?
    ///
    /// # ELLE NE CONSOMME PAS LE DÉFI, ET C'EST [`repondre`] QUI LE FAIT
    ///
    /// Cette fonction est appelée depuis [`besoin`], qui ne tient la session
    /// qu'en lecture — et c'est ce qui permet à la vérification d'avoir lieu
    /// AVANT que l'étage 3 n'écrive quoi que ce soit. Une preuve fausse ne doit
    /// pas créer de compte, puis se faire refuser.
    ///
    /// Le défi est donc dépensé plus tard, par [`repondre`], et **dans les deux
    /// cas** : voir [`Besoin::PreuveRefusee`].
    #[must_use]
    fn possession(&self, cle: &ClePublique, signature: &Signature) -> bool {
        match self.defi {
            Some(defi) => cle.prouve_sa_possession(&defi, &self.liaison, signature),
            None => false,
        }
    }

    /// Dépense le défi en cours, s'il y en a un.
    fn consommer_le_defi(&mut self) {
        self.defi = None;
    }
}

/// **PREMIER TEMPS** : que faut-il pour répondre à cette requête ?
///
/// Rend [`Besoin::Deja`] quand la réponse ne dépend d'aucun état — un verbe
/// qu'on ne sert pas, une cible qui ne se route pas, un corps trop gros.
#[must_use]
pub fn besoin<'a>(session: &Session, tete: &RequestHead<'a>, corps: &'a [u8]) -> Besoin<'a> {
    let Some((methode, _)) = traduire(tete.method()) else {
        return Besoin::Deja(StatusCode::METHOD_NOT_ALLOWED);
    };

    if corps.len() > CORPS_OCTETS_MAX {
        return Besoin::Deja(StatusCode::CONTENT_TOO_LARGE);
    }

    let resolu = match asl_api::resoudre(methode, tete.path()) {
        Ok(resolu) => resolu,
        Err(faute) => return Besoin::Deja(statut_de(faute)),
    };

    if !resolu.sert {
        return Besoin::Deja(StatusCode::METHOD_NOT_ALLOWED);
    }

    // ── LA PREUVE, AVANT TOUT CONTRÔLE D'EXIGENCE ───────────────────────────
    //
    // `/v1/defi` n'exige rien, et pour cause : c'est elle qui produit la preuve.
    if resolu.ressource == Ressource::Defi {
        return match methode {
            asl_api::Methode::Get => Besoin::DefiATirer,
            _ => lire_une_preuve(corps),
        };
    }

    // ── CE QUI EXIGE UNE PREUVE ─────────────────────────────────────────────
    match resolu.exigence {
        Exigence::Aucune => {}
        // **`MachineLecture` EST TENUE DÈS MAINTENANT** : la connexion sait si
        // une machine a prouvé sa clé. Sans preuve, c'est `401` — et cette
        // fois le mot est juste, puisque `/v1/defi` attend bel et bien derrière.
        Exigence::MachineLecture | Exigence::MachineAnnonce => {
            if session.machine().is_none() {
                return Besoin::Deja(StatusCode::UNAUTHORIZED);
            }
        }
        // **UN APPAREIL, ET PAS N'IMPORTE QUEL PAIR.** Une machine qui a prouvé
        // sa clé sur cette connexion ne passe pas ici : la clé d'une machine
        // vit en clair sur un disque que tout daemon peut lire, et lui ouvrir
        // l'administration d'un compte donnerait à un daemon compromis le droit
        // de s'accorder des autorisations.
        Exigence::Appareil => {
            if session.appareil().is_none() {
                return Besoin::Deja(StatusCode::UNAUTHORIZED);
            }
        }
    }

    match resolu.ressource {
        Ressource::AliasResolu { alias } => Besoin::CompteParAlias(alias.as_str()),
        Ressource::Utilisateur { compte } => Besoin::Compte(compte),
        Ressource::Annonce => Besoin::Annoncer,
        Ressource::Ou { machine, service } => Besoin::Ou {
            machine,
            service: service.as_str(),
        },
        Ressource::Poussees => Besoin::EcouterLesPoussees,
        Ressource::Vu => Besoin::OuSuisJeVu,
        Ressource::OuParNom { service } => Besoin::OuParNom {
            service: service.as_str(),
        },
        Ressource::ServicesMachine { machine } => Besoin::ServicesDeMachine { machine },
        Ressource::Comptes => lire_creation_de_compte(session, corps),
        Ressource::Appareils => lire_creation_d_appareil(corps),
        Ressource::Machines => match DeclarationMachine::decoder(corps) {
            Ok(demande) => Besoin::CreerMachine {
                nom: demande.nom,
                capacites: demande.capacites,
            },
            Err(_) => Besoin::Deja(StatusCode::BAD_REQUEST),
        },
        Ressource::Machine { machine } => match ModificationMachine::decoder(corps) {
            Ok(demande) => Besoin::ModifierMachine {
                machine,
                nom: demande.nom,
                capacites: demande.capacites,
            },
            Err(_) => Besoin::Deja(StatusCode::BAD_REQUEST),
        },
        Ressource::EnrolementMachine { machine } => Besoin::NouveauCode { machine },
        Ressource::Enrolement => lire_un_enrolement(session, corps),
        // **DEUX VERBES, DEUX BESOINS.** Le routage sert `GET` et `POST` sur
        // cette ressource depuis toujours ; la répartition, elle, ne regardait
        // que la ressource. Un `GET /v1/autorisations` — la forme que
        // `protocole.md` §2.2 décrit — tombait donc dans le décodeur d'une
        // demande, sur un corps vide, et rendait `400`.
        //
        // **`400` ÉTAIT PIRE QU'UN `501`** : il disait « votre requête est mal
        // formée » à une requête parfaite, et envoyait chercher la faute chez
        // l'appelant.
        Ressource::Autorisations => match methode {
            asl_api::Methode::Get => Besoin::MesAutorisations,
            _ => match DemandeAutorisation::decoder(corps) {
                Ok(demande) => Besoin::Autoriser {
                    a: demande.a,
                    portee: demande.portee,
                },
                Err(_) => Besoin::Deja(StatusCode::BAD_REQUEST),
            },
        },
        Ressource::PousseeAppareil { appareil } => match DepotJeton::decoder(corps) {
            Ok(depot) => Besoin::PoserJetonDePoussee {
                appareil,
                plateforme: depot.plateforme,
                jeton: depot.jeton,
            },
            Err(_) => Besoin::Deja(StatusCode::BAD_REQUEST),
        },
        Ressource::Appareil { appareil } => Besoin::RevoquerAppareil { appareil },
        Ressource::CleMachine { machine } => Besoin::RevoquerCleMachine { machine },
        Ressource::Autorisation { autorisation } => Besoin::RevoquerAutorisation { autorisation },
        Ressource::Alias => match methode {
            asl_api::Methode::Delete => Besoin::RetirerAlias,
            _ => match DemandeAlias::decoder(corps) {
                Ok(demande) => Besoin::PoserAlias {
                    alias: demande.alias.as_str(),
                },
                Err(_) => Besoin::Deja(StatusCode::BAD_REQUEST),
            },
        },
        // Ce qui reste — les expositions —
        // n'est pas écrit. Le dire par `501` est exact : la ressource existe, le
        // verbe est servi, et l'annuaire ne sait pas encore le faire.
        _ => Besoin::Deja(StatusCode::NOT_IMPLEMENTED),
    }
}

/// Lit `POST /v1/comptes` : une clé publique, et la preuve qu'on la détient.
fn lire_creation_de_compte<'a>(session: &Session, corps: &[u8]) -> Besoin<'a> {
    let Some((cle, preuve)) = lire_cle_et_preuve(corps) else {
        return Besoin::Deja(StatusCode::BAD_REQUEST);
    };
    if session.possession(&cle, &preuve) {
        Besoin::CreerCompte { cle }
    } else {
        Besoin::PreuveRefusee
    }
}

/// Lit `POST /v1/appareils` : une clé publique, et rien d'autre.
fn lire_creation_d_appareil<'a>(corps: &[u8]) -> Besoin<'a> {
    if corps.len() != CLE_SEULE_OCTETS {
        return Besoin::Deja(StatusCode::BAD_REQUEST);
    }
    match lire_une_cle(corps) {
        Some(cle) => Besoin::CreerAppareil { cle },
        None => Besoin::Deja(StatusCode::BAD_REQUEST),
    }
}

/// Lit `POST /v1/enrolement` : un code, une clé publique, et la preuve.
fn lire_un_enrolement<'a>(session: &Session, corps: &[u8]) -> Besoin<'a> {
    if corps.len() != ENROLEMENT_CORPS_OCTETS {
        return Besoin::Deja(StatusCode::BAD_REQUEST);
    }
    let symboles = corps.get(..asl_cle::CODE_SYMBOLES).unwrap_or_default();
    let Ok(texte) = core::str::from_utf8(symboles) else {
        return Besoin::Deja(StatusCode::BAD_REQUEST);
    };
    let Ok(code) = CodeEnrolement::analyser(texte) else {
        return Besoin::Deja(StatusCode::BAD_REQUEST);
    };
    let Some((cle, preuve)) =
        lire_cle_et_preuve(corps.get(asl_cle::CODE_SYMBOLES..).unwrap_or(&[]))
    else {
        return Besoin::Deja(StatusCode::BAD_REQUEST);
    };
    if session.possession(&cle, &preuve) {
        Besoin::Enroler {
            empreinte: code.empreinte(),
            cle,
        }
    } else {
        Besoin::PreuveRefusee
    }
}

/// Lit une clé publique de trente-deux octets, en tête de ces octets.
///
/// **La clé est VÉRIFIÉE** : tous les tableaux de trente-deux octets ne sont pas
/// des points de la courbe, et en ranger un ferait échouer toute vérification
/// ultérieure sans qu'on sache pourquoi.
///
/// # ELLE NE VÉRIFIE PAS LA LONGUEUR, ET SES DEUX APPELANTS L'ONT DÉJÀ FAIT
///
/// Une garde ici aurait été une branche que rien ne peut atteindre — du code
/// mort sur un chemin cryptographique, c'est-à-dire du code que personne
/// n'éprouvera jamais et que tout le monde croira éprouvé. Une tranche trop
/// courte se remplirait de zéros en silence ; c'est pourquoi les deux appelants
/// exigent une longueur EXACTE avant d'arriver ici.
fn lire_une_cle(corps: &[u8]) -> Option<ClePublique> {
    let mut octets = [0_u8; asl_cle::CLE_PUBLIQUE_OCTETS];
    for (place, octet) in octets.iter_mut().zip(corps.iter()) {
        *place = *octet;
    }
    ClePublique::depuis_octets(octets).ok()
}

/// Lit une clé publique suivie d'une signature. Exige [`POSSESSION_OCTETS`].
fn lire_cle_et_preuve(corps: &[u8]) -> Option<(ClePublique, Signature)> {
    if corps.len() != POSSESSION_OCTETS {
        return None;
    }
    let cle = lire_une_cle(corps)?;
    let mut brute = [0_u8; asl_cle::SIGNATURE_OCTETS];
    for (place, octet) in brute
        .iter_mut()
        .zip(corps.iter().skip(asl_cle::CLE_PUBLIQUE_OCTETS))
    {
        *place = *octet;
    }
    Some((cle, Signature::depuis_octets(brute)))
}

/// Lit une preuve : dix-sept octets d'identifiant, puis soixante-quatre de
/// signature.
///
/// **AUCUNE LONGUEUR NE VIENT DES OCTETS.** Le corps fait exactement
/// [`PREUVE_OCTETS`] ou il est refusé — il n'y a donc rien à borner, rien à
/// réserver, et rien à tronquer.
fn lire_une_preuve<'a>(corps: &[u8]) -> Besoin<'a> {
    if corps.len() != PREUVE_OCTETS {
        return Besoin::Deja(StatusCode::BAD_REQUEST);
    }
    // **DEUX GENRES SIGNENT, ET L'OCTET EXACT LES DISTINGUE.** Une machine
    // s'authentifie pour annoncer et interroger ; un appareil s'authentifie pour
    // administrer un compte. Le genre entre dans le message signé
    // (`asl_cle::message_a_signer`), donc une preuve de l'un ne vaut jamais pour
    // l'autre — ce n'est pas cette lecture qui les sépare, c'est la signature.
    let genre = match corps.first().copied().unwrap_or(0) {
        octet if octet == Genre::Machine.prefixe() => Genre::Machine,
        octet if octet == Genre::Appareil.prefixe() => Genre::Appareil,
        _ => return Besoin::Deja(StatusCode::BAD_REQUEST),
    };
    let mut entropie = [0_u8; 16];
    for (place, octet) in entropie.iter_mut().zip(corps.iter().skip(1)) {
        *place = *octet;
    }
    let mut brute = [0_u8; asl_cle::SIGNATURE_OCTETS];
    for (place, octet) in brute.iter_mut().zip(corps.iter().skip(17)) {
        *place = *octet;
    }
    Besoin::ClePourPreuve {
        machine: Identifiant::depuis_entropie(genre, entropie),
        signature: Signature::depuis_octets(brute),
    }
}

/// **SECOND TEMPS** : voici ce qui a été trouvé, réponds.
///
/// Tout ce que la réponse désigne vit dans `sortie` — voir [`composer`].
#[must_use]
pub fn repondre<'o>(
    session: &mut Session,
    besoin: &Besoin<'_>,
    trouvaille: &Trouvaille,
    defi_tire: Option<Defi>,
    sortie: &'o mut [u8],
) -> Reponse<'o> {
    match besoin {
        Besoin::Deja(statut) => composer(*statut, PROBLEME_MEDIA, probleme(*statut), sortie),

        // **LE DÉFI VIENT DE L'ÉTAGE 3**, parce qu'il faut de l'entropie et que
        // l'entropie est une entrée-sortie. Sans lui, on ne peut pas répondre —
        // et l'on ne prétend pas le contraire.
        Besoin::DefiATirer => match defi_tire {
            Some(defi) => {
                let octets = session.poser_le_defi(defi);
                composer(StatusCode::OK, OCTETS_MEDIA, &octets, sortie)
            }
            None => composer(
                StatusCode::INTERNAL_SERVER_ERROR,
                PROBLEME_MEDIA,
                probleme(StatusCode::INTERNAL_SERVER_ERROR),
                sortie,
            ),
        },

        // **UN REFUS NE DIT PAS LEQUEL DES TROIS.** Machine inconnue, clé
        // illisible, signature fausse : le même `401`. Distinguer dirait à qui
        // essaie quels identifiants de machine existent.
        Besoin::ClePourPreuve { machine, signature } => {
            let accorde = match trouvaille {
                Trouvaille::Cle(cle) => session.verifier(*machine, signature, cle),
                _ => {
                    // La machine est introuvable : le défi est consommé quand
                    // même, pour la raison écrite sur `Session::verifier`.
                    session.defi = None;
                    false
                }
            };
            let statut = if accorde {
                StatusCode::NO_CONTENT
            } else {
                StatusCode::UNAUTHORIZED
            };
            let corps: &[u8] = if accorde { b"" } else { probleme(statut) };
            let media = if accorde {
                OCTETS_MEDIA
            } else {
                PROBLEME_MEDIA
            };
            composer(statut, media, corps, sortie)
        }
        // **L'ANNONCE EST PRISE À L'ÉTAGE 3**, qui tient le vivier. Ici, on ne
        // fait qu'habiller ce qu'il rend.
        Besoin::Annoncer => match trouvaille {
            Trouvaille::Annoncee(corps) => composer(StatusCode::OK, JSON_MEDIA, corps, sortie),
            // **`403` ICI, ET NON `404`.** C10 impose de ne rien dire de ce qui
            // existe sur une LECTURE ; une annonce ne lit rien. Le daemon est
            // authentifié, il n'a simplement pas la capacité `annonce` — ou son
            // message est mal formé. Lui rendre « introuvable » l'enverrait
            // chercher une faute d'URL.
            _ => composer(
                StatusCode::FORBIDDEN,
                PROBLEME_MEDIA,
                probleme(StatusCode::FORBIDDEN),
                sortie,
            ),
        },

        // **C'EST `asl-auth` QUI DÉCIDE, ET RIEN D'AUTRE ICI.** Cette crate
        // rassemble et compose ; la règle « un service ne se rend qu'à qui y a
        // droit » vit à un seul endroit, et c'est là-bas.
        Besoin::Ou { .. } => match trouvaille {
            Trouvaille::Resolution(quoi) => {
                match asl_auth::decider_resolution(
                    &quoi.demandeur,
                    &quoi.cible,
                    &quoi.autorisations,
                ) {
                    // **UN REFUS REND `404`, ET NON `403`.** C10 : rien ne se
                    // lit sans autorisation nominative, et un `403` dirait à qui
                    // essaie que ce service EXISTE. « Introuvable » est vrai du
                    // point de vue du demandeur — pour lui, il n'existe pas.
                    asl_auth::Decision::Refuser => composer(
                        StatusCode::NOT_FOUND,
                        PROBLEME_MEDIA,
                        probleme(StatusCode::NOT_FOUND),
                        sortie,
                    ),
                    // **SERVI** : voici où le service se trouve.
                    asl_auth::Decision::Servir => match &quoi.annonce {
                        Some(corps) => composer(StatusCode::OK, JSON_MEDIA, corps, sortie),
                        // **DÉCLARÉ MAIS PAS ANNONCÉ : `404`.** Le demandeur y a
                        // droit, et il n'y a pourtant rien à joindre — aucun
                        // daemon ne tient de connexion pour ce service en ce
                        // moment.
                        //
                        // On pourrait vouloir dire « parti » plutôt
                        // qu'« introuvable ». **On ne le peut pas, et c'est une
                        // conséquence assumée** : l'état vivant n'est jamais
                        // écrit sur disque, donc un annuaire qui vient de
                        // redémarrer ne sait pas si ce service est parti ou n'a
                        // jamais parlé. Prétendre le savoir serait affirmer ce
                        // qu'on n'a pas mesuré, ce que C6 interdit.
                        None => composer(
                            StatusCode::NOT_FOUND,
                            PROBLEME_MEDIA,
                            probleme(StatusCode::NOT_FOUND),
                            sortie,
                        ),
                    },
                }
            }
            // Le service, la machine ou le demandeur manquent : `404`, du même
            // `404` qu'un refus. Voir ci-dessus.
            _ => composer(
                StatusCode::NOT_FOUND,
                PROBLEME_MEDIA,
                probleme(StatusCode::NOT_FOUND),
                sortie,
            ),
        },

        // ── LES VERBES DE LISTE ─────────────────────────────────────────
        //
        // **UNE LISTE VIDE EST UN `200`, ET NON UN `404`.** « Je n'ai rien à te
        // montrer » et « cette ressource n'existe pas » ne se corrigent pas au
        // même endroit, et un client qui lirait `404` là où il devait lire `[]`
        // croirait son appel fautif.
        //
        // **ET L'OMISSION NE DIT RIEN DE CE QU'ELLE OMET** (C10). La forme par
        // machine rend `404` aussi bien pour « absent » que pour « interdit » ;
        // une liste, elle, se contente de ne pas porter ce qu'on n'a pas le
        // droit de voir. Personne ne peut compter ce qui manque.
        Besoin::OuParNom { .. } => match trouvaille {
            Trouvaille::Resolutions(quoi) => composer_les_resolutions(quoi, sortie),
            _ => composer_les_resolutions(&alloc::vec::Vec::new(), sortie),
        },

        Besoin::ServicesDeMachine { .. } => match trouvaille {
            Trouvaille::ServicesDeMachine {
                demandeur,
                proprietaire,
                annonces,
            } if asl_auth::decider_services_de_machine(*demandeur, *proprietaire)
                == asl_auth::Decision::Servir =>
            {
                composer_une_liste(annonces, sortie)
            }
            // Refusé, ou rien trouvé : un tableau vide, pour la raison ci-dessus.
            _ => composer_une_liste(&alloc::vec::Vec::new(), sortie),
        },

        // **UNE RÉPONSE VIDE, ET UN FLUX QUI RESTE OUVERT.**
        //
        // Pas de `content-length` : une réponse dont la longueur est déclarée et
        // dont le corps s'allonge est un message qui se contredit, et un
        // intermédiaire aurait raison de la couper.
        //
        // Pas de corps non plus — la première poussée sera le premier octet. Un
        // tableau vide d'ouverture ferait croire à une liste, alors que ce qui
        // suit est une suite d'objets sans enveloppe.
        Besoin::EcouterLesPoussees => Reponse::new(StatusCode::OK, &[])
            .avec_champ(b"content-type", JSON_MEDIA)
            .tenue(),

        Besoin::MesAutorisations => match trouvaille {
            Trouvaille::Autorisations(quoi) => composer_les_autorisations(quoi, sortie),
            _ => composer_les_autorisations(&alloc::vec::Vec::new(), sortie),
        },

        // ── CE QUI CRÉE, ET CE QUI DÉPENSE UN DÉFI ──────────────────────
        //
        // Les trois besoins qui portent une preuve de possession consomment le
        // défi ICI, qu'ils aboutissent ou non. C'est le même principe que pour
        // `/v1/defi` : une signature fausse coûte un défi, et l'on recommence.
        Besoin::PreuveRefusee => {
            session.consommer_le_defi();
            composer(
                StatusCode::UNAUTHORIZED,
                PROBLEME_MEDIA,
                probleme(StatusCode::UNAUTHORIZED),
                sortie,
            )
        }
        Besoin::CreerCompte { .. } => {
            session.consommer_le_defi();
            match trouvaille {
                Trouvaille::CompteCree { compte, appareil } => {
                    // ── LA CONNEXION EST DÉSORMAIS CELLE DE CET APPAREIL ────
                    //
                    // **C'est la même preuve, et il n'en faut pas deux.** Cet
                    // appareil vient de signer le défi de CETTE connexion, lié à
                    // CE canal, pour CETTE clé ; l'annuaire vient de lui
                    // attribuer un identifiant, qu'il n'a donc pas pu signer —
                    // il n'existait pas.
                    //
                    // Refaire le tour par `/v1/defi` coûterait deux allers-retours
                    // pour rejouer exactement la même démonstration. Ce n'est pas
                    // un raccourci sur la sécurité : c'est le constat que le
                    // justificatif est déjà là, et qu'il est plus fort que celui
                    // que le second tour produirait — la clé y est signée, alors
                    // que `/v1/defi` ne signe qu'un identifiant.
                    session.pair = Some(*appareil);
                    let mut corps = Corps::<CREATION_CORPS_MAX>::neuf();
                    corps.pousser(br#"{"compte":""#);
                    corps.pousser(compte.texte().as_str().as_bytes());
                    corps.pousser(br#"","appareil":""#);
                    corps.pousser(appareil.texte().as_str().as_bytes());
                    corps.pousser(br#""}"#);
                    composer(StatusCode::CREATED, JSON_MEDIA, corps.rendu(), sortie)
                }
                autre => rendre_l_echec(autre, sortie),
            }
        }
        Besoin::Enroler { .. } => {
            session.consommer_le_defi();
            match trouvaille {
                Trouvaille::Enrolee(machine) => {
                    let mut corps = Corps::<CREATION_CORPS_MAX>::neuf();
                    corps.pousser(br#"{"machine":""#);
                    corps.pousser(machine.texte().as_str().as_bytes());
                    corps.pousser(br#""}"#);
                    // **`200`, ET NON `201`** : rien n'a été créé. La machine
                    // existait ; ce qui a changé est qu'elle a désormais une clé.
                    composer(StatusCode::OK, JSON_MEDIA, corps.rendu(), sortie)
                }
                autre => rendre_l_echec(autre, sortie),
            }
        }
        Besoin::CreerAppareil { .. } => match trouvaille {
            Trouvaille::AppareilCree(appareil) => {
                let mut corps = Corps::<CREATION_CORPS_MAX>::neuf();
                corps.pousser(br#"{"appareil":""#);
                corps.pousser(appareil.texte().as_str().as_bytes());
                corps.pousser(br#""}"#);
                composer(StatusCode::CREATED, JSON_MEDIA, corps.rendu(), sortie)
            }
            autre => rendre_l_echec(autre, sortie),
        },
        Besoin::CreerMachine { .. } => match trouvaille {
            Trouvaille::MachineCreee {
                machine,
                code,
                expire_a,
            } => {
                let mut corps = Corps::<CREATION_CORPS_MAX>::neuf();
                corps.pousser(br#"{"machine":""#);
                corps.pousser(machine.texte().as_str().as_bytes());
                corps.pousser(br#"","code":""#);
                corps.pousser(code.as_str().as_bytes());
                corps.pousser(br#"","expire_a":"#);
                corps.pousser_un_nombre(*expire_a);
                corps.pousser(b"}");
                composer(StatusCode::CREATED, JSON_MEDIA, corps.rendu(), sortie)
            }
            autre => rendre_l_echec(autre, sortie),
        },
        Besoin::NouveauCode { .. } => match trouvaille {
            Trouvaille::CodeEmis { code, expire_a } => {
                let mut corps = Corps::<CREATION_CORPS_MAX>::neuf();
                corps.pousser(br#"{"code":""#);
                corps.pousser(code.as_str().as_bytes());
                corps.pousser(br#"","expire_a":"#);
                corps.pousser_un_nombre(*expire_a);
                corps.pousser(b"}");
                composer(StatusCode::CREATED, JSON_MEDIA, corps.rendu(), sortie)
            }
            autre => rendre_l_echec(autre, sortie),
        },
        Besoin::Autoriser { .. } => match trouvaille {
            Trouvaille::AutorisationCreee(autorisation) => {
                let mut corps = Corps::<CREATION_CORPS_MAX>::neuf();
                corps.pousser(br#"{"autorisation":""#);
                corps.pousser(autorisation.texte().as_str().as_bytes());
                corps.pousser(br#""}"#);
                composer(StatusCode::CREATED, JSON_MEDIA, corps.rendu(), sortie)
            }
            autre => rendre_l_echec(autre, sortie),
        },
        // ── CE QUI RETIRE, ET L'ALIAS ───────────────────────────────────
        //
        // **UNE SEULE FORME DE RÉPONSE POUR LES CINQ**, et c'est ce qui les rend
        // sûres : `204` quand c'est fait, `404` quand l'objet visé n'existe pas
        // **OU N'EST PAS À NOUS**. Les distinguer dirait à qui essaie des
        // identifiants au hasard lesquels existent — et un identifiant qui
        // existe est un compte qu'on vient de découvrir.
        //
        // `403` reste pour le seul refus qui ne se cache pas : un appareil qui
        // se révoque lui-même. Celui-là connaît déjà son propre identifiant, et
        // il doit savoir pourquoi on lui dit non.
        Besoin::RevoquerAppareil { .. }
        | Besoin::ModifierMachine { .. }
        | Besoin::PoserJetonDePoussee { .. }
        | Besoin::RevoquerCleMachine { .. }
        | Besoin::RevoquerAutorisation { .. }
        | Besoin::PoserAlias { .. }
        | Besoin::RetirerAlias => match trouvaille {
            Trouvaille::Fait => composer(StatusCode::NO_CONTENT, JSON_MEDIA, &[], sortie),
            Trouvaille::Conflit => composer(
                StatusCode::CONFLICT,
                PROBLEME_MEDIA,
                probleme(StatusCode::CONFLICT),
                sortie,
            ),
            Trouvaille::Refus => composer(
                StatusCode::FORBIDDEN,
                PROBLEME_MEDIA,
                probleme(StatusCode::FORBIDDEN),
                sortie,
            ),
            _ => composer(
                StatusCode::NOT_FOUND,
                PROBLEME_MEDIA,
                probleme(StatusCode::NOT_FOUND),
                sortie,
            ),
        },

        Besoin::OuSuisJeVu => match trouvaille {
            Trouvaille::VuDepuis(vu) => rendre_ou_l_on_est_vu(*vu, sortie),
            // **`Rien` REND `404`, ET NON `500`**, comme partout ailleurs dans
            // ce module. La tentation était forte de dire `500` : la connexion
            // existe forcément, puisqu'elle vient de poser la question, et ne
            // pas savoir d'où elle vient serait bien une faute de l'annuaire.
            //
            // Mais cette ressource n'exige aucune preuve. Un `500` atteignable
            // par un inconnu est un `500` qu'un inconnu peut FABRIQUER, et un
            // journal où les `500` sont fabriqués à volonté ne sert plus à
            // repérer les vraies pannes. `fuzz_asl_session_reponse` tient cette
            // règle, et c'est elle qui a arrêté la première version d'ici.
            Trouvaille::Rien => composer(
                StatusCode::NOT_FOUND,
                PROBLEME_MEDIA,
                probleme(StatusCode::NOT_FOUND),
                sortie,
            ),
            _ => composer(
                StatusCode::INTERNAL_SERVER_ERROR,
                PROBLEME_MEDIA,
                probleme(StatusCode::INTERNAL_SERVER_ERROR),
                sortie,
            ),
        },

        Besoin::Compte(_) | Besoin::CompteParAlias(_) => match trouvaille {
            // **UN COMPTE QU'ON NE TROUVE PAS EST UN `404`**, et jamais un
            // corps vide avec un `200` : le client doit pouvoir distinguer
            // « ce compte n'existe pas » de « ce compte n'a pas d'alias ».
            Trouvaille::Rien => composer(
                StatusCode::NOT_FOUND,
                PROBLEME_MEDIA,
                probleme(StatusCode::NOT_FOUND),
                sortie,
            ),
            Trouvaille::Compte { qui, alias } => rendre_un_compte(*qui, alias.as_ref(), sortie),
            _ => composer(
                StatusCode::INTERNAL_SERVER_ERROR,
                PROBLEME_MEDIA,
                probleme(StatusCode::INTERNAL_SERVER_ERROR),
                sortie,
            ),
        },
    }
}

/// Ce qu'un corps de `/v1/vu` peut faire, en octets.
///
/// Une adresse IPv6 pleine fait 45 caractères, un port cinq, et le reste est du
/// balisage : soixante-quatre suffisent avec de la marge.
const VU_CORPS_MAX: usize = 96;

/// Rend d'où l'annuaire voit cette connexion.
///
/// # LA FAMILLE EST ÉCRITE, ALORS QU'ELLE SE DÉDUIT DE L'ADRESSE
///
/// Un client qui reçoit `"2001:db8::1"` sait déjà qu'il est en IPv6. Mais le
/// déduire demande d'analyser l'adresse, et **c'est exactement ce qu'on ne veut
/// pas faire écrire cinq fois** dans cinq liaisons : chercher un `:` marche
/// jusqu'au jour où quelqu'un rencontre `::ffff:203.0.113.7`.
fn rendre_ou_l_on_est_vu(vu: asl_proto::VuDepuis, sortie: &mut [u8]) -> Reponse<'_> {
    let mut corps = Corps::<VU_CORPS_MAX>::neuf();
    corps.pousser(br#"{"adresse":""#);
    // **AUCUN ÉCHAPPEMENT N'EST NÉCESSAIRE** : une adresse s'écrit avec des
    // chiffres, des lettres, des points et des deux-points, et rien de tout cela
    // n'a de sens particulier en JSON.
    let mut texte = [0_u8; 64];
    let combien = ecrire_une_adresse(vu.adresse, &mut texte);
    corps.pousser(texte.get(..combien).unwrap_or_default());
    corps.pousser(br#"","port":"#);
    corps.pousser_un_nombre(u64::from(vu.port.valeur()));
    corps.pousser(br#","famille":"#);
    corps.pousser_un_nombre(if vu.est_ipv6() { 6 } else { 4 });
    corps.pousser(b"}");
    composer(StatusCode::OK, JSON_MEDIA, corps.rendu(), sortie)
}

/// Écrit une adresse en texte, sans allouer, et rend combien d'octets.
///
/// `core::fmt::Write` sur une tranche demanderait un adaptateur ; `IpAddr` sait
/// s'écrire, et `write!` dans un tampon borné est exactement ce que fait
/// `asl_proto::cadrage::Ecrivain`. On l'emploie plutôt que d'en écrire un second.
fn ecrire_une_adresse(adresse: core::net::IpAddr, sortie: &mut [u8]) -> usize {
    use core::fmt::Write as _;
    let mut ecrivain = asl_proto::cadrage::Ecrivain::nouveau(sortie);
    let _ = write!(ecrivain, "{adresse}");
    ecrivain.achever().unwrap_or(0)
}

/// Ce qu'un corps de compte peut faire, en octets.
///
/// L'identifiant tient sur vingt-huit caractères, l'alias sur trente-deux, et le
/// reste est de la ponctuation. Cent vingt octets couvrent largement, et la
/// borne est ici pour que le tampon soit une CONSTANTE plutôt qu'un calcul.
pub const COMPTE_CORPS_MAX: usize = 120;

/// Ce qu'un corps de création occupe, en octets.
///
/// # LA BORNE PORTE SON CALCUL, PARCE QUE RIEN NE RATTRAPE UN DÉPASSEMENT
///
/// [`Corps`] BORNE au lieu d'échouer : un corps trop long serait tronqué en
/// silence, et le client recevrait du JSON coupé avec un `201`. Il faut donc
/// démontrer que cela ne peut pas arriver, plutôt que de s'en remettre à une
/// branche d'erreur que rien n'atteindrait.
///
/// Le plus long des six corps est celui d'une machine créée :
///
/// ```text
/// {"machine":"m-…26…","code":"XXXXX-XXXXX","expire_a":9999999999999}
///  ^^^^^^^^^^^          ^^^^^^^^          ^^^^^^^^^^^^
/// ```
///
/// 28 caractères d'identifiant, 11 de code, 20 au plus pour l'horodatage
/// (`usize::MAX` en fait vingt), et 34 de ponctuation et de noms de champs :
/// quatre-vingt-treize. Cent vingt-huit laisse de la marge sans en laisser à un
/// abus — **et aucune de ces longueurs ne vient du réseau.**
pub const CREATION_CORPS_MAX: usize = 128;

/// Le plus long corps de création, démontré plutôt qu'estimé.
const _: () = assert!(
    CREATION_CORPS_MAX >= 28 + 11 + NOMBRE_OCTETS_MAX + 34,
    "un corps de création pourrait être tronqué en silence"
);

/// Compose un tableau de résolutions, en n'y mettant que ce qui se rend.
///
/// # LA DÉCISION EST PRISE ICI, UNE PAR UNE
///
/// `asl_auth::decider_resolution` est appelée pour chaque candidat, exactement
/// comme pour la forme par machine. **La règle « un service ne se rend qu'à qui
/// y a droit » vit à un seul endroit**, et une liste qui l'aurait réécrite pour
/// aller plus vite serait celle qui finit par diverger.
///
/// Un service DÉCLARÉ mais non annoncé n'entre pas : il n'y a rien à joindre, et
/// une entrée sans candidat ferait essayer une adresse qui n'existe pas.
fn composer_les_resolutions<'o>(quoi: &[Resolution], sortie: &'o mut [u8]) -> Reponse<'o> {
    let mut place = [0_u8; asl_proto::cadrage::MESSAGE_MAX];
    let combien = {
        let mut liste = asl_proto::cadrage::Liste::nouvelle(&mut place);
        for resolution in quoi {
            if asl_auth::decider_resolution(
                &resolution.demandeur,
                &resolution.cible,
                &resolution.autorisations,
            ) != asl_auth::Decision::Servir
            {
                continue;
            }
            if let Some(annonce) = resolution.annonce.as_deref() {
                liste.ajouter(annonce);
            }
        }
        match liste.achever() {
            Ok(combien) => combien,
            // **AU-DELÀ DE LA BORNE, C'EST `500` ET NON UNE LISTE TRONQUÉE.**
            //
            // Une liste tronquée mentirait par omission, et le demandeur
            // croirait avoir tout vu. `asl_proto::LISTE_MAX` porte la raison, et
            // la pagination qui la remplacera un jour.
            //
            // **`500` EST LE MOT JUSTE** : le demandeur n'a rien fait de mal,
            // c'est nous qui avons plus à dire que notre protocole ne sait
            // exprimer. Il réessaiera et obtiendra la même chose — ce qui est
            // exactement ce qu'un `500` veut dire, et ce qui doit remonter
            // jusqu'à nous.
            Err(_) => {
                return composer(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    PROBLEME_MEDIA,
                    probleme(StatusCode::INTERNAL_SERVER_ERROR),
                    sortie,
                );
            }
        }
    };
    composer(
        StatusCode::OK,
        JSON_MEDIA,
        place.get(..combien).unwrap_or_default(),
        sortie,
    )
}

/// Compose un tableau d'éléments déjà encodés.
fn composer_une_liste<'o>(quoi: &[alloc::vec::Vec<u8>], sortie: &'o mut [u8]) -> Reponse<'o> {
    let mut place = [0_u8; asl_proto::cadrage::MESSAGE_MAX];
    let combien = {
        let mut liste = asl_proto::cadrage::Liste::nouvelle(&mut place);
        for element in quoi {
            liste.ajouter(element);
        }
        match liste.achever() {
            Ok(combien) => combien,
            // Même raison que dans `composer_les_resolutions`.
            Err(_) => {
                return composer(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    PROBLEME_MEDIA,
                    probleme(StatusCode::INTERNAL_SERVER_ERROR),
                    sortie,
                );
            }
        }
    };
    composer(
        StatusCode::OK,
        JSON_MEDIA,
        place.get(..combien).unwrap_or_default(),
        sortie,
    )
}

/// Compose un tableau d'autorisations, dans les deux sens.
fn composer_les_autorisations<'o>(
    quoi: &[AutorisationRendue],
    sortie: &'o mut [u8],
) -> Reponse<'o> {
    let mut place = [0_u8; asl_proto::cadrage::MESSAGE_MAX];
    let combien = {
        let mut liste = asl_proto::cadrage::Liste::nouvelle(&mut place);
        for autorisation in quoi {
            // **UN CORPS QUI BORNE, ET NON UN `Result` QU'ON JETTE.**
            //
            // `AutorisationRendue::encoder` peut rendre `TamponTropPetit` — et
            // ici il ne le peut PAS : les cinq champs sont de taille connue, et
            // `AUTORISATION_RENDUE_MAX` porte le calcul qui le démontre.
            //
            // Écrire quand même une branche pour ce cas poserait du code que
            // rien ne peut atteindre, donc que personne n'éprouvera jamais et
            // que tout le monde croira éprouvé. C'est l'idiome de [`Corps`],
            // employé ici pour la septième fois.
            let mut une = Corps::<AUTORISATION_RENDUE_MAX>::neuf();
            une.pousser_encode(autorisation);
            liste.ajouter(une.rendu());
        }
        match liste.achever() {
            Ok(combien) => combien,
            // Même raison que ci-dessus.
            Err(_) => {
                return composer(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    PROBLEME_MEDIA,
                    probleme(StatusCode::INTERNAL_SERVER_ERROR),
                    sortie,
                );
            }
        }
    };
    composer(
        StatusCode::OK,
        JSON_MEDIA,
        place.get(..combien).unwrap_or_default(),
        sortie,
    )
}

/// Ce qu'occupe une autorisation encodée, au plus.
///
/// Quatre identifiants de vingt-huit caractères, les noms de champs, la
/// ponctuation, et `false`. **Démontré plutôt qu'estimé**, comme
/// [`CREATION_CORPS_MAX`].
const AUTORISATION_RENDUE_MAX: usize = 256;

const _: () = assert!(
    AUTORISATION_RENDUE_MAX >= 4 * 28 + 64,
    "une autorisation rendue pourrait être tronquée en silence"
);

/// Un corps de création, qui BORNE au lieu d'échouer.
///
/// # POURQUOI PAS `asl_proto::cadrage::Ecrivain`
///
/// Celui-là retient le débordement et le rend en faute — ce qui est juste pour
/// un message dont la taille dépend de ce qu'on encode. **Ici, elle n'en dépend
/// pas** : les corps de création sont faits d'identifiants de vingt-huit
/// caractères, d'un code de onze et d'un horodatage de treize chiffres, tous de
/// taille connue. Le débordement serait donc une branche que rien ne peut
/// atteindre, et [`CREATION_CORPS_MAX`] porte le calcul qui le démontre.
///
/// C'est l'idiome de [`rendre_un_compte`], sorti dans un type parce qu'il sert
/// désormais six fois.
struct Corps<const N: usize> {
    octets: [u8; N],
    ecrits: usize,
}

impl<const N: usize> Corps<N> {
    /// Un corps vide.
    const fn neuf() -> Self {
        Self {
            octets: [0; N],
            ecrits: 0,
        }
    }

    /// Ajoute ces octets, autant qu'il en tient.
    fn pousser(&mut self, quoi: &[u8]) {
        let debut = self.ecrits.min(N);
        let fin = debut.saturating_add(quoi.len()).min(N);
        for (place, octet) in self
            .octets
            .get_mut(debut..fin)
            .unwrap_or_default()
            .iter_mut()
            .zip(quoi.iter())
        {
            *place = *octet;
        }
        self.ecrits = fin;
    }

    /// Ajoute un entier décimal.
    fn pousser_un_nombre(&mut self, valeur: u64) {
        let mut chiffres = [0_u8; NOMBRE_OCTETS_MAX];
        // `u64` ne tient pas toujours dans un `usize` sur une cible 32 bits ; un
        // horodatage en millisecondes, si. La saturation est ici pour que le
        // refus soit visible plutôt que silencieux.
        let combien =
            ecrire_un_nombre(usize::try_from(valeur).unwrap_or(usize::MAX), &mut chiffres);
        self.pousser(chiffres.get(..combien).unwrap_or_default());
    }

    /// Encode une autorisation dedans, en bornant.
    ///
    /// L'encodeur rend un `Result` parce qu'il ne connaît pas son tampon ; ici
    /// on le connaît, et `AUTORISATION_RENDUE_MAX` porte la preuve qu'il suffit.
    fn pousser_encode(&mut self, quoi: &AutorisationRendue) {
        let mut place = [0_u8; N];
        let combien = quoi.encoder(&mut place).unwrap_or(0);
        self.pousser(place.get(..combien).unwrap_or_default());
    }

    /// Ce qui a été écrit.
    fn rendu(&self) -> &[u8] {
        self.octets.get(..self.ecrits.min(N)).unwrap_or_default()
    }
}

/// Traduit l'échec d'une création : `403` si une règle a refusé, `500` sinon.
///
/// Voir [`Trouvaille::Refus`] pour pourquoi les deux ne se confondent pas.
fn rendre_l_echec<'o>(trouvaille: &Trouvaille, sortie: &'o mut [u8]) -> Reponse<'o> {
    let statut = match trouvaille {
        Trouvaille::Refus => StatusCode::FORBIDDEN,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    composer(statut, PROBLEME_MEDIA, probleme(statut), sortie)
}

/// Écrit le corps JSON d'un compte, et rend la réponse.
///
/// # POURQUOI CE CORPS-LÀ, ET RIEN DE PLUS
///
/// Un compte n'est qu'un identifiant public et, facultativement, un alias.
/// **C13 n'est pas une intention ici, c'est ce que le type permet d'écrire** :
/// il n'y a pas d'autre champ à rendre, parce qu'il n'y en a pas d'autre à
/// stocker.
fn rendre_un_compte<'o>(
    qui: Identifiant,
    alias: Option<&AliasRange>,
    sortie: &'o mut [u8],
) -> Reponse<'o> {
    let mut corps = [0_u8; COMPTE_CORPS_MAX];
    let mut ecrits = 0_usize;
    let mut ajouter = |quoi: &[u8]| {
        let debut = ecrits.min(COMPTE_CORPS_MAX);
        let fin = debut.saturating_add(quoi.len()).min(COMPTE_CORPS_MAX);
        for (place, octet) in corps
            .get_mut(debut..fin)
            .unwrap_or_default()
            .iter_mut()
            .zip(quoi.iter())
        {
            *place = *octet;
        }
        ecrits = fin;
    };

    // **AUCUN ÉCHAPPEMENT N'EST NÉCESSAIRE, ET C'EST VÉRIFIÉ PAR CONSTRUCTION.**
    // L'alphabet d'un identifiant est celui de Crockford, celui d'un alias est
    // minuscules, chiffres, `-`, `_` et `.` : aucun `"` ni `\` ne peut y entrer.
    // Un échappeur serait donc du code que rien n'appellerait jamais — et qui
    // deviendrait faux le jour où l'alphabet changerait sans qu'on y pense.
    ajouter(br#"{"identifiant":""#);
    ajouter(qui.texte().as_str().as_bytes());
    if let Some(alias) = alias {
        ajouter(br#"","alias":""#);
        ajouter(alias.octets());
    }
    ajouter(br#""}"#);

    let ecrit = ecrits.min(COMPTE_CORPS_MAX);
    let rendu = corps.get(..ecrit).unwrap_or_default();
    composer(StatusCode::OK, JSON_MEDIA, rendu, sortie)
}

/// Traduit un verbe HTTP en verbe de l'API, et dit s'il faut taire le corps.
///
/// # `HEAD` EST UN `GET`, ET CE N'EST PAS UNE COMMODITÉ
///
/// §9.3.2 de RFC 9110 exige qu'un serveur qui sert `GET` serve `HEAD`, **avec
/// les mêmes en-têtes**. Le router ailleurs ferait diverger les deux le jour où
/// l'un gagnerait une règle que l'autre n'aurait pas.
///
/// `OPTIONS` n'est pas servi : cette API n'est pas appelée depuis un navigateur,
/// donc rien ne l'interroge par requête préalable.
const fn traduire(methode: Method) -> Option<(asl_api::Methode, bool)> {
    match methode {
        Method::Get => Some((asl_api::Methode::Get, false)),
        Method::Head => Some((asl_api::Methode::Get, true)),
        Method::Post => Some((asl_api::Methode::Post, false)),
        Method::Put => Some((asl_api::Methode::Put, false)),
        Method::Patch => Some((asl_api::Methode::Patch, false)),
        Method::Delete => Some((asl_api::Methode::Delete, false)),
        Method::Options => None,
    }
}

/// Le code de statut d'un refus de routage.
///
/// **UNE SEULE RÈGLE, ET ELLE SE DIT EN UNE PHRASE** : `404` quand la cible est
/// bien formée mais ne désigne rien ; `400` quand elle n'est pas bien formée.
///
/// Les confondre coûterait cher dans les deux sens. Un `400` sur une ressource
/// inconnue ferait chercher une faute de syntaxe là où il n'y en a pas ; un
/// `404` sur une cible mal écrite ferait croire qu'une autre URL existerait.
const fn statut_de(faute: asl_api::Erreur) -> StatusCode {
    match faute {
        asl_api::Erreur::RessourceInconnue => StatusCode::NOT_FOUND,
        _ => StatusCode::BAD_REQUEST,
    }
}

/// Le corps d'un refus, en `application/problem+json` (RFC 9457).
///
/// # POURQUOI DES CHAÎNES FIGÉES PLUTÔT QU'UN FORMATAGE
///
/// Un corps composé à l'exécution demanderait un tampon, un formateur, et des
/// bornes sur chacun. Ces réponses-là ne portent aucune donnée variable : le
/// détail utile est le code de statut, et il est déjà dans la réponse.
///
/// **Elles ne nomment jamais ce qui a échoué en détail**, et c'est délibéré : un
/// refus de routage bavard décrit la surface de l'API à qui la sonde.
const fn probleme(statut: StatusCode) -> &'static [u8] {
    match statut {
        StatusCode::BAD_REQUEST => br#"{"type":"about:blank","title":"Bad Request","status":400}"#,
        StatusCode::NOT_FOUND => br#"{"type":"about:blank","title":"Not Found","status":404}"#,
        StatusCode::METHOD_NOT_ALLOWED => {
            br#"{"type":"about:blank","title":"Method Not Allowed","status":405}"#
        }
        StatusCode::CONTENT_TOO_LARGE => {
            br#"{"type":"about:blank","title":"Content Too Large","status":413}"#
        }
        StatusCode::UNAUTHORIZED => {
            br#"{"type":"about:blank","title":"Unauthorized","status":401}"#
        }
        StatusCode::FORBIDDEN => br#"{"type":"about:blank","title":"Forbidden","status":403}"#,
        StatusCode::CONFLICT => br#"{"type":"about:blank","title":"Conflict","status":409}"#,
        StatusCode::INTERNAL_SERVER_ERROR => {
            br#"{"type":"about:blank","title":"Internal Server Error","status":500}"#
        }
        _ => br#"{"type":"about:blank","title":"Not Implemented","status":501}"#,
    }
}

/// Écrit la réponse dans `sortie`, et la décrit.
///
/// # TOUT CE QUE LA RÉPONSE DÉSIGNE DOIT VIVRE DANS `sortie`
///
/// `Reponse<'o>` emprunte : son corps ET la valeur de chacun de ses champs. Une
/// longueur formatée dans une variable locale mourrait à la fin de cette
/// fonction, et le compilateur le refuserait — d'où les chiffres écrits DERRIÈRE
/// le corps, dans le même tampon, puis un découpage en tranches disjointes.
///
/// C'est le seul endroit du produit qui a cette forme, et elle vient de
/// l'absence d'allocation, pas d'un goût pour l'astuce.
#[must_use]
pub fn composer<'o>(
    statut: StatusCode,
    media: &'static [u8],
    corps: &[u8],
    sortie: &'o mut [u8],
) -> Reponse<'o> {
    // **`HEAD` N'EST PLUS TRAITÉ ICI**, et il faut dire où il est passé : il
    // l'était par un drapeau `sans_corps` que tout appelant devait penser à
    // passer. Un paramètre qu'on peut oublier est un paramètre qu'on oubliera —
    // et `ams-h3` sait déjà taire le corps d'une réponse à `HEAD`, puisque c'est
    // lui qui écrit les trames.
    //
    // Le `content-length` reste celui du corps ENTIER (§8.6 de RFC 9110), ce
    // qui est exactement ce que §9.3.2 demande.

    // §8.6 de RFC 9110 : `content-length` annonce ce que le corps AURAIT, même
    // quand la réponse à un `HEAD` n'en porte pas.
    let annonce = corps.len();
    let mut chiffres = [0_u8; NOMBRE_OCTETS_MAX];
    let combien = ecrire_un_nombre(annonce, &mut chiffres);

    // **LA LONGUEUR SE RÉSERVE AVANT LE CORPS, ET C'EST LE FUZZ QUI L'A EXIGÉ.**
    //
    // L'ordre inverse laissait le corps manger la place des chiffres. Sur un
    // tampon de deux octets, un `GET` rendait deux octets de corps et AUCUN
    // `content-length`, quand le `HEAD` de la même ressource — qui n'écrit pas
    // de corps — le rendait. **Deux réponses différentes pour la même
    // ressource**, ce que §9.3.2 de RFC 9110 interdit précisément.
    //
    // Le champ passe donc devant, et c'est le bon arbitrage : un corps tronqué
    // est inutilisable de toute façon, et sans longueur annoncée le client ne
    // peut même pas savoir qu'il l'est.
    //
    // **UNE LONGUEUR TRONQUÉE N'EST PAS UNE LONGUEUR** : si les chiffres ne
    // tiennent pas ENTIERS, on n'en réserve aucun. Un `content-length` de « 5 »
    // pour un corps de cinquante-sept octets ferait couper la lecture au mauvais
    // endroit, là où un champ absent ne trompe personne.
    let reserve = if combien <= sortie.len() { combien } else { 0 };
    let pour_le_corps = sortie.len().saturating_sub(reserve);
    let ecrit = corps.len().min(pour_le_corps);

    // ON DÉCOUPE D'ABORD, ON RECOPIE ENSUITE. L'ordre inverse demandait un
    // `get_mut` dont l'échec était impossible, et la mesure de couverture
    // signalait la branche morte.
    let (corps_rendu, reste) = sortie.split_at_mut(ecrit);
    let (longueur, _) = reste.split_at_mut(reserve.min(reste.len()));

    // `zip` s'arrête sur le plus court des deux, donc il ne peut ni déborder ni
    // échouer — et il n'ouvre aucune branche qu'un essai ne pourrait prendre.
    for (place, octet) in corps_rendu.iter_mut().zip(corps.iter()) {
        *place = *octet;
    }
    for (place, octet) in longueur.iter_mut().zip(chiffres.iter()) {
        *place = *octet;
    }

    Reponse::new(statut, corps_rendu)
        .avec_champ(b"content-type", media)
        .avec_champ(b"content-length", longueur)
        // §5.2.2.5 de RFC 9111 : rien de cette API ne se met en cache. Une
        // réponse d'annuaire est vraie à l'instant où elle est rendue.
        .avec_champ(b"cache-control", b"no-store")
        // Aucun de ces corps n'est à interpréter autrement que comme du JSON.
        .avec_champ(b"x-content-type-options", b"nosniff")
}

/// Ce qu'un nombre décimal peut faire : `usize::MAX` s'écrit sur vingt chiffres.
const NOMBRE_OCTETS_MAX: usize = 20;

/// Écrit ce nombre en chiffres décimaux, et rend combien il en a fallu.
///
/// # AUCUNE SORTIE ANTICIPÉE, ET C'EST LA COUVERTURE QUI L'A EXIGÉ
///
/// Une première écriture s'arrêtait dès que la valeur tombait à zéro, et
/// indexait le tampon derrière un `if let Some`. Ce `Some` ne pouvait pas
/// échouer — `usize::MAX` s'écrit sur exactement vingt chiffres, et le tampon en
/// fait vingt —, mais le compilateur ne le sait pas, et la mesure signalait une
/// branche que nul essai ne pouvait atteindre.
///
/// **Une branche qu'aucun essai ne peut prendre est du code mort**, et la traiter
/// autrement reviendrait à ajouter une exception à la mesure pour éviter de
/// simplifier le code. On remplit donc les vingt places, toujours, puis on jette
/// les zéros de tête.
fn ecrire_un_nombre(mut valeur: usize, sortie: &mut [u8; NOMBRE_OCTETS_MAX]) -> usize {
    for place in sortie.iter_mut().rev() {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "un reste modulo 10 tient dans un octet"
        )]
        {
            *place = b'0'.saturating_add((valeur % 10) as u8);
        }
        valeur /= 10;
    }

    // Le dernier zéro n'est pas un zéro de tête : c'est le nombre zéro.
    let tete = sortie
        .iter()
        .position(|octet| *octet != b'0')
        .unwrap_or(NOMBRE_OCTETS_MAX.saturating_sub(1));
    let combien = NOMBRE_OCTETS_MAX.saturating_sub(tete);
    sortie.copy_within(tete.., 0);
    combien
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::string::ToString as _;
    use alloc::vec;
    use ams_proto_http::{HeadBuilder, Limits, Method, RequestHead, StatusCode};
    use asl_id::{Genre, Identifiant};
    use asl_registre::AliasRange;

    use asl_cle::LiaisonDeCanal;

    use super::{
        Besoin, CORPS_OCTETS_MAX, JSON_MEDIA, NOMBRE_OCTETS_MAX, POSSESSION_OCTETS, PROBLEME_MEDIA,
        Session, Trouvaille, besoin, composer, ecrire_un_nombre, probleme, repondre, statut_de,
        traduire,
    };

    /// La liaison de l'essai : celle d'un certificat quelconque.
    fn liaison() -> LiaisonDeCanal {
        LiaisonDeCanal::depuis_octets([0x11; asl_cle::LIAISON_OCTETS])
    }

    /// Une session neuve pour l'essai.
    fn session() -> Session {
        Session::new(liaison())
    }

    /// Fabrique une tête de requête, comme le décodeur HTTP/3 en rendrait une.
    fn tete<'a>(verbe: &'a [u8], cible: &'a [u8]) -> RequestHead<'a> {
        let limites = Limits::default();
        let mut constructeur = HeadBuilder::new(&limites);
        constructeur.field(b":method", verbe).expect("le verbe");
        constructeur.field(b":scheme", b"https").expect("le schéma");
        constructeur
            .field(b":authority", b"annuaire.example")
            .expect("l'autorité");
        constructeur.field(b":path", cible).expect("la cible");
        constructeur.finish().expect("une tête complète")
    }

    /// Rend la valeur du champ nommé.
    fn champ<'a>(reponse: &ams_h3::Reponse<'a>, nom: &[u8]) -> Option<&'a [u8]> {
        reponse
            .fields()
            .find(|(cle, _)| *cle == nom)
            .map(|(_, valeur)| valeur)
    }

    /// Un identifiant d'utilisateur, reproductible.
    fn un_compte(graine: u8) -> Identifiant {
        Identifiant::depuis_entropie(Genre::Utilisateur, [graine; 16])
    }

    // ── traduire ────────────────────────────────────────────────────────────

    #[test]
    fn head_est_un_get() {
        assert_eq!(traduire(Method::Head), Some((asl_api::Methode::Get, true)));
        assert_eq!(traduire(Method::Get), Some((asl_api::Methode::Get, false)));
    }

    #[test]
    fn les_verbes_qui_modifient_se_traduisent_un_pour_un() {
        assert_eq!(
            traduire(Method::Post),
            Some((asl_api::Methode::Post, false))
        );
        assert_eq!(traduire(Method::Put), Some((asl_api::Methode::Put, false)));
        assert_eq!(
            traduire(Method::Patch),
            Some((asl_api::Methode::Patch, false))
        );
        assert_eq!(
            traduire(Method::Delete),
            Some((asl_api::Methode::Delete, false))
        );
    }

    #[test]
    fn options_n_est_pas_servi() {
        assert_eq!(traduire(Method::Options), None);
    }

    // ── statut_de ───────────────────────────────────────────────────────────

    #[test]
    fn une_cible_bien_formee_qui_ne_designe_rien_donne_404() {
        assert_eq!(
            statut_de(asl_api::Erreur::RessourceInconnue),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn une_cible_mal_formee_donne_400() {
        assert_eq!(
            statut_de(asl_api::Erreur::CibleSansRacine),
            StatusCode::BAD_REQUEST
        );
    }

    // ── probleme ────────────────────────────────────────────────────────────

    #[test]
    fn chaque_statut_a_son_corps_et_le_corps_porte_le_meme_nombre() {
        for (statut, attendu) in [
            (StatusCode::BAD_REQUEST, &b"400"[..]),
            (StatusCode::NOT_FOUND, b"404"),
            (StatusCode::METHOD_NOT_ALLOWED, b"405"),
            (StatusCode::CONTENT_TOO_LARGE, b"413"),
            (StatusCode::NOT_IMPLEMENTED, b"501"),
        ] {
            let corps = probleme(statut);
            assert!(corps.windows(3).any(|fenetre| fenetre == attendu));
        }
    }

    #[test]
    fn un_statut_hors_table_retombe_sur_501() {
        assert_eq!(
            probleme(StatusCode::OK),
            probleme(StatusCode::NOT_IMPLEMENTED)
        );
    }

    // ── ecrire_un_nombre ────────────────────────────────────────────────────

    #[test]
    fn zero_s_ecrit_sur_un_chiffre() {
        let mut sortie = [0_u8; NOMBRE_OCTETS_MAX];
        assert_eq!(ecrire_un_nombre(0, &mut sortie), 1);
        assert_eq!(sortie.first(), Some(&b'0'));
    }

    #[test]
    fn un_nombre_s_ecrit_dans_le_bon_ordre() {
        let mut sortie = [0_u8; NOMBRE_OCTETS_MAX];
        let combien = ecrire_un_nombre(1_024, &mut sortie);
        assert_eq!(sortie.get(..combien), Some(&b"1024"[..]));
    }

    #[test]
    fn le_plus_grand_nombre_tient_dans_le_tampon() {
        let mut sortie = [0_u8; NOMBRE_OCTETS_MAX];
        let combien = ecrire_un_nombre(usize::MAX, &mut sortie);
        assert!(combien <= NOMBRE_OCTETS_MAX);
        assert_eq!(
            sortie.get(..combien),
            Some(usize::MAX.to_string().as_bytes())
        );
    }

    // ── composer ────────────────────────────────────────────────────────────

    #[test]
    fn une_reponse_porte_son_corps_sa_longueur_et_ses_gardes() {
        let mut sortie = [0_u8; 256];
        let attendu = probleme(StatusCode::NOT_FOUND);
        let reponse = composer(StatusCode::NOT_FOUND, PROBLEME_MEDIA, attendu, &mut sortie);

        assert_eq!(reponse.status(), StatusCode::NOT_FOUND);
        assert_eq!(reponse.body(), attendu);
        assert_eq!(champ(&reponse, b"content-type"), Some(PROBLEME_MEDIA));
        assert_eq!(champ(&reponse, b"cache-control"), Some(&b"no-store"[..]));
        assert_eq!(
            champ(&reponse, b"x-content-type-options"),
            Some(&b"nosniff"[..])
        );
        assert_eq!(
            champ(&reponse, b"content-length"),
            Some(attendu.len().to_string().as_bytes())
        );
    }

    #[test]
    fn le_type_de_media_est_celui_qu_on_passe() {
        let mut sortie = [0_u8; 256];
        let reponse = composer(StatusCode::OK, JSON_MEDIA, b"{}", &mut sortie);
        assert_eq!(champ(&reponse, b"content-type"), Some(JSON_MEDIA));
        assert_eq!(reponse.body(), b"{}");
    }

    #[test]
    fn un_tampon_trop_court_sacrifie_le_corps_et_garde_la_longueur() {
        let corps = probleme(StatusCode::NOT_FOUND);
        let attendu = corps.len().to_string();
        let mut sortie = [0_u8; 4];
        let reponse = composer(StatusCode::NOT_FOUND, PROBLEME_MEDIA, corps, &mut sortie);
        assert_eq!(
            champ(&reponse, b"content-length"),
            Some(attendu.as_bytes()),
            "la longueur est ce qu'on garde en dernier"
        );
        assert_eq!(reponse.body().len(), 4 - attendu.len());
    }

    #[test]
    fn une_longueur_qui_ne_tient_pas_entiere_n_est_pas_ecrite() {
        let mut sortie = [0_u8; 1];
        let reponse = composer(
            StatusCode::NOT_FOUND,
            PROBLEME_MEDIA,
            probleme(StatusCode::NOT_FOUND),
            &mut sortie,
        );
        assert_eq!(champ(&reponse, b"content-length"), Some(&b""[..]));
        assert_eq!(reponse.body().len(), 1, "l'octet libre revient au corps");
    }

    #[test]
    fn un_tampon_vide_ne_panique_pas() {
        let mut sortie = [0_u8; 0];
        let reponse = composer(StatusCode::NOT_FOUND, PROBLEME_MEDIA, b"quoi", &mut sortie);
        assert!(reponse.body().is_empty());
    }

    #[test]
    fn un_corps_vide_annonce_une_longueur_nulle() {
        let mut sortie = [0_u8; 64];
        let reponse = composer(StatusCode::NO_CONTENT, JSON_MEDIA, b"", &mut sortie);
        assert_eq!(champ(&reponse, b"content-length"), Some(&b"0"[..]));
        assert!(reponse.body().is_empty());
    }

    // ── besoin ──────────────────────────────────────────────────────────────

    #[test]
    fn une_session_neuve_n_a_authentifie_personne() {
        assert_eq!(session().machine(), None);
    }

    #[test]
    fn options_est_refuse_par_le_verbe() {
        assert_eq!(
            besoin(&session(), &tete(b"OPTIONS", b"/v1/machines"), b""),
            Besoin::Deja(StatusCode::METHOD_NOT_ALLOWED)
        );
    }

    #[test]
    fn un_corps_trop_gros_est_refuse_avant_toute_analyse() {
        let enorme = vec![b'x'; CORPS_OCTETS_MAX + 1];
        assert_eq!(
            besoin(
                &session(),
                &tete(b"POST", b"/v1/ceci-n-existe-pas"),
                &enorme
            ),
            Besoin::Deja(StatusCode::CONTENT_TOO_LARGE),
            "le refus doit tomber AVANT que le routage ne regarde la cible"
        );
    }

    #[test]
    fn un_corps_juste_a_la_borne_passe() {
        let pile = vec![b'x'; CORPS_OCTETS_MAX];
        assert_ne!(
            besoin(&session(), &tete(b"POST", b"/v1/ceci-n-existe-pas"), &pile),
            Besoin::Deja(StatusCode::CONTENT_TOO_LARGE)
        );
    }

    #[test]
    fn une_cible_mal_formee_est_un_400() {
        assert_eq!(
            besoin(
                &session(),
                &tete(b"PATCH", b"/v1/machines/pas-un-identifiant"),
                b""
            ),
            Besoin::Deja(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn une_ressource_qui_ne_sert_pas_ce_verbe_est_un_405() {
        assert_eq!(
            besoin(&session(), &tete(b"GET", b"/v1/machines"), b""),
            Besoin::Deja(StatusCode::METHOD_NOT_ALLOWED)
        );
    }

    #[test]
    fn une_cible_inconnue_est_un_404() {
        assert_eq!(
            besoin(&session(), &tete(b"GET", b"/v1/rien-de-tel"), b""),
            Besoin::Deja(StatusCode::NOT_FOUND)
        );
    }

    #[test]
    fn ce_qui_exige_un_appareil_rend_401_avant_de_rendre_501() {
        // **L'EXIGENCE PASSE AVANT L'IMPLÉMENTATION, ET C'EST L'ORDRE JUSTE.**
        // `/v1/expositions` n'est pas écrite ; un inconnu n'a pas à l'apprendre.
        // Un `501` lui dirait quels verbes cet annuaire ne sait pas encore
        // servir, donc lesquels il servira demain — un renseignement gratuit
        // pour qui n'a prouvé aucune clé.
        assert_eq!(
            besoin(&session(), &tete(b"GET", b"/v1/expositions"), b""),
            Besoin::Deja(StatusCode::UNAUTHORIZED)
        );
    }

    #[test]
    fn un_alias_demande_le_compte_qui_le_porte() {
        assert_eq!(
            besoin(&session(), &tete(b"GET", b"/v1/alias/thierry"), b""),
            Besoin::CompteParAlias("thierry")
        );
    }

    #[test]
    fn un_utilisateur_demande_son_compte() {
        let qui = un_compte(1);
        let texte = alloc::format!("/v1/utilisateurs/{}", qui.texte());
        assert_eq!(
            besoin(&session(), &tete(b"GET", texte.as_bytes()), b""),
            Besoin::Compte(qui)
        );
    }

    #[test]
    fn un_corps_de_creation_de_compte_mal_dimensionne_est_refuse() {
        // Quatre-vingt-seize octets, ou rien : une clé et une signature, toutes
        // deux de longueur fixe. Il n'y a aucune longueur à lire, donc aucune à
        // se faire mentir.
        for corps in [&b""[..], &[0_u8; 95][..], &[0_u8; 97][..]] {
            let combien = corps.len();
            assert_eq!(
                besoin(&session(), &tete(b"POST", b"/v1/comptes"), corps),
                Besoin::Deja(StatusCode::BAD_REQUEST),
                "{combien} octets"
            );
        }

        // **LA BONNE LONGUEUR NE SUFFIT PAS** : il reste à prouver la
        // possession, et cette session-ci n'a tiré aucun défi.
        assert_eq!(
            besoin(
                &session(),
                &tete(b"POST", b"/v1/comptes"),
                &[0_u8; POSSESSION_OCTETS]
            ),
            Besoin::PreuveRefusee
        );
    }

    #[test]
    fn ce_qui_n_est_pas_encore_ecrit_rend_501_une_fois_l_appareil_prouve() {
        // **`501` EXISTE ENCORE**, et c'est ce qu'il doit dire : la ressource se
        // route, le verbe est servi, et l'annuaire ne sait pas le faire. Il ne
        // se dit qu'à quelqu'un qui a prouvé sa clé.
        let mut session = session();
        session.pair = Some(Identifiant::depuis_entropie(Genre::Appareil, [7; 16]));
        assert_eq!(
            besoin(&session, &tete(b"GET", b"/v1/expositions"), b""),
            Besoin::Deja(StatusCode::NOT_IMPLEMENTED)
        );
    }

    // ── repondre ────────────────────────────────────────────────────────────

    #[test]
    fn un_besoin_deja_decide_rend_son_statut() {
        let mut sortie = [0_u8; 256];
        let reponse = repondre(
            &mut session(),
            &Besoin::Deja(StatusCode::NOT_FOUND),
            &Trouvaille::Rien,
            None,
            &mut sortie,
        );
        assert_eq!(reponse.status(), StatusCode::NOT_FOUND);
        assert_eq!(champ(&reponse, b"content-type"), Some(PROBLEME_MEDIA));
    }

    #[test]
    fn un_besoin_deja_decide_ignore_ce_qu_on_a_trouve() {
        // Le besoin dit déjà tout ; une trouvaille ne doit pas pouvoir le
        // contredire.
        let mut sortie = [0_u8; 256];
        let reponse = repondre(
            &mut session(),
            &Besoin::Deja(StatusCode::METHOD_NOT_ALLOWED),
            &Trouvaille::Compte {
                qui: un_compte(1),
                alias: None,
            },
            None,
            &mut sortie,
        );
        assert_eq!(reponse.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn un_compte_introuvable_est_un_404() {
        let mut sortie = [0_u8; 256];
        for besoin in [
            Besoin::Compte(un_compte(1)),
            Besoin::CompteParAlias("personne"),
        ] {
            let reponse = repondre(
                &mut session(),
                &besoin,
                &Trouvaille::Rien,
                None,
                &mut sortie,
            );
            assert_eq!(reponse.status(), StatusCode::NOT_FOUND, "{besoin:?}");
        }
    }

    #[test]
    fn une_trouvaille_qui_ne_correspond_pas_au_besoin_est_une_panne_de_serveur() {
        // **`repondre` EST PUBLIQUE**, donc cette combinaison est atteignable :
        // un appelant peut lui donner une clé là où elle attendait un compte.
        // C'est une faute de NOTRE côté, pas du client — d'où le `500`, et non
        // un `404` qui ferait croire que le compte n'existe pas.
        let mut sortie = [0_u8; 256];
        let reponse = repondre(
            &mut session(),
            &Besoin::Compte(un_compte(1)),
            &Trouvaille::Cle(asl_cle::CleSecrete::depuis_entropie([1; 32]).publique()),
            None,
            &mut sortie,
        );
        assert_eq!(reponse.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn un_compte_trouve_rend_son_identifiant() {
        let qui = un_compte(7);
        let mut sortie = [0_u8; 512];
        let reponse = repondre(
            &mut session(),
            &Besoin::Compte(qui),
            &Trouvaille::Compte { qui, alias: None },
            None,
            &mut sortie,
        );
        assert_eq!(reponse.status(), StatusCode::OK);
        assert_eq!(champ(&reponse, b"content-type"), Some(JSON_MEDIA));

        let attendu = alloc::format!(r#"{{"identifiant":"{}"}}"#, qui.texte());
        assert_eq!(reponse.body(), attendu.as_bytes());
        assert!(
            !attendu.contains("alias"),
            "un compte sans alias n'annonce pas de champ vide"
        );
    }

    #[test]
    fn un_compte_avec_alias_le_rend_aussi() {
        let qui = un_compte(3);
        let mut sortie = [0_u8; 512];
        let reponse = repondre(
            &mut session(),
            &Besoin::CompteParAlias("thierry"),
            &Trouvaille::Compte {
                qui,
                alias: Some(AliasRange::nouveau("thierry").expect("il tient")),
            },
            None,
            &mut sortie,
        );
        let attendu = alloc::format!(r#"{{"identifiant":"{}","alias":"thierry"}}"#, qui.texte());
        assert_eq!(reponse.body(), attendu.as_bytes());
    }

    #[test]
    fn le_corps_d_un_compte_ne_deborde_jamais_sa_borne() {
        // L'alias le plus long possible, avec l'identifiant le plus long : le
        // corps doit rester dans `COMPTE_CORPS_MAX`, et rester du JSON clos.
        let qui = un_compte(0xFF);
        let long = "z".repeat(32);
        let mut sortie = [0_u8; 512];
        let reponse = repondre(
            &mut session(),
            &Besoin::Compte(qui),
            &Trouvaille::Compte {
                qui,
                alias: Some(AliasRange::nouveau(&long).expect("il tient")),
            },
            None,
            &mut sortie,
        );
        let rendu = core::str::from_utf8(reponse.body()).expect("du JSON en ASCII");
        assert!(rendu.len() <= super::COMPTE_CORPS_MAX, "{rendu}");
        assert!(rendu.ends_with('}'), "le JSON a été tronqué : {rendu}");
    }
}

#[cfg(test)]
mod authentification {
    use ams_proto_http::{HeadBuilder, Limits, RequestHead, StatusCode};
    use asl_cle::{CleSecrete, Defi, LiaisonDeCanal, SIGNATURE_OCTETS};
    use asl_id::{Genre, Identifiant};

    extern crate alloc;
    use alloc::vec::Vec;

    use super::{Besoin, OCTETS_MEDIA, PREUVE_OCTETS, Session, Trouvaille, besoin, repondre};

    fn liaison() -> LiaisonDeCanal {
        LiaisonDeCanal::depuis_octets([0x11; asl_cle::LIAISON_OCTETS])
    }

    fn tete<'a>(verbe: &'a [u8], cible: &'a [u8]) -> RequestHead<'a> {
        let limites = Limits::default();
        let mut constructeur = HeadBuilder::new(&limites);
        constructeur.field(b":method", verbe).expect("le verbe");
        constructeur.field(b":scheme", b"https").expect("le schéma");
        constructeur
            .field(b":authority", b"annuaire.example")
            .expect("l'autorité");
        constructeur.field(b":path", cible).expect("la cible");
        constructeur.finish().expect("une tête complète")
    }

    fn champ<'a>(reponse: &ams_h3::Reponse<'a>, nom: &[u8]) -> Option<&'a [u8]> {
        reponse
            .fields()
            .find(|(cle, _)| *cle == nom)
            .map(|(_, valeur)| valeur)
    }

    /// La machine du banc, et sa clé.
    fn une_machine() -> (Identifiant, CleSecrete) {
        (
            Identifiant::depuis_entropie(Genre::Machine, [3; 16]),
            CleSecrete::depuis_entropie([7; 32]),
        )
    }

    /// Compose le corps d'une preuve.
    fn corps_de_preuve(machine: Identifiant, signature: &asl_cle::Signature) -> Vec<u8> {
        let mut corps = Vec::with_capacity(PREUVE_OCTETS);
        corps.push(Genre::Machine.prefixe());
        corps.extend_from_slice(machine.octets());
        corps.extend_from_slice(signature.octets());
        corps
    }

    /// Tire un défi sur cette session, et rend ce que le client verrait.
    fn tirer(session: &mut Session, defi: Defi) -> Defi {
        let mut sortie = [0_u8; 256];
        let quoi = besoin(session, &tete(b"GET", b"/v1/defi"), b"");
        assert_eq!(quoi, Besoin::DefiATirer);
        let reponse = repondre(session, &quoi, &Trouvaille::Rien, Some(defi), &mut sortie);
        assert_eq!(reponse.status(), StatusCode::OK);
        assert_eq!(champ(&reponse, b"content-type"), Some(OCTETS_MEDIA));
        let mut octets = [0_u8; asl_cle::DEFI_OCTETS];
        octets.copy_from_slice(reponse.body());
        Defi::depuis_octets(octets)
    }

    /// Mène l'authentification complète, et rend la session.
    fn authentifier() -> (Session, Identifiant) {
        let (machine, secrete) = une_machine();
        let mut session = Session::new(liaison());
        let defi = tirer(&mut session, Defi::depuis_octets([42; 32]));
        let signature = secrete
            .signer(machine, &defi, &liaison())
            .expect("elle signe");
        let corps = corps_de_preuve(machine, &signature);

        let quoi = besoin(&session, &tete(b"POST", b"/v1/defi"), &corps);
        let mut sortie = [0_u8; 256];
        let reponse = repondre(
            &mut session,
            &quoi,
            &Trouvaille::Cle(secrete.publique()),
            None,
            &mut sortie,
        );
        assert_eq!(reponse.status(), StatusCode::NO_CONTENT, "{reponse:?}");
        (session, machine)
    }

    #[test]
    fn le_defi_rendu_est_celui_qu_on_a_tire() {
        let mut session = Session::new(liaison());
        let voulu = Defi::depuis_octets([0xAB; 32]);
        assert_eq!(tirer(&mut session, voulu), voulu);
    }

    #[test]
    fn sans_defi_tire_l_etage_3_a_failli_et_on_le_dit() {
        // **ON NE PRÉTEND PAS RÉPONDRE.** Le défi vient de l'étage 3, parce
        // qu'il faut de l'entropie ; s'il manque, c'est une panne de serveur, et
        // non une faute du client.
        let mut session = Session::new(liaison());
        let mut sortie = [0_u8; 256];
        let reponse = repondre(
            &mut session,
            &Besoin::DefiATirer,
            &Trouvaille::Rien,
            None,
            &mut sortie,
        );
        assert_eq!(reponse.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn une_preuve_juste_authentifie_la_connexion() {
        let (session, machine) = authentifier();
        assert_eq!(session.machine(), Some(machine));
    }

    #[test]
    fn une_signature_faite_pour_un_autre_defi_est_refusee() {
        // **C'EST LE REJEU**, et c'est ce que le défi existe pour arrêter.
        let (machine, secrete) = une_machine();
        let mut session = Session::new(liaison());
        tirer(&mut session, Defi::depuis_octets([1; 32]));

        let autre = Defi::depuis_octets([2; 32]);
        let signature = secrete
            .signer(machine, &autre, &liaison())
            .expect("elle signe");
        let corps = corps_de_preuve(machine, &signature);
        let quoi = besoin(&session, &tete(b"POST", b"/v1/defi"), &corps);
        let mut sortie = [0_u8; 256];
        let reponse = repondre(
            &mut session,
            &quoi,
            &Trouvaille::Cle(secrete.publique()),
            None,
            &mut sortie,
        );
        assert_eq!(reponse.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(session.machine(), None);
    }

    #[test]
    fn une_signature_faite_pour_un_autre_canal_est_refusee() {
        // **C'EST LE RELAIS.** Une machine qui a signé pour la liaison d'une
        // AUTRE connexion — celle qu'un intermédiaire a montée avec elle — ne
        // s'authentifie pas ici.
        let (machine, secrete) = une_machine();
        let mut session = Session::new(liaison());
        let defi = tirer(&mut session, Defi::depuis_octets([1; 32]));

        let ailleurs = LiaisonDeCanal::depuis_octets([0x22; asl_cle::LIAISON_OCTETS]);
        let signature = secrete
            .signer(machine, &defi, &ailleurs)
            .expect("elle signe");
        let corps = corps_de_preuve(machine, &signature);
        let quoi = besoin(&session, &tete(b"POST", b"/v1/defi"), &corps);
        let mut sortie = [0_u8; 256];
        let reponse = repondre(
            &mut session,
            &quoi,
            &Trouvaille::Cle(secrete.publique()),
            None,
            &mut sortie,
        );
        assert_eq!(reponse.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(session.machine(), None);
    }

    #[test]
    fn le_defi_est_consomme_meme_par_une_preuve_fausse() {
        // Le garder laisserait un attaquant essayer autant de signatures qu'il
        // veut contre un même défi.
        let (machine, secrete) = une_machine();
        let mut session = Session::new(liaison());
        let defi = tirer(&mut session, Defi::depuis_octets([1; 32]));

        let fausse = asl_cle::Signature::depuis_octets([0; SIGNATURE_OCTETS]);
        let mut sortie = [0_u8; 256];
        let corps = corps_de_preuve(machine, &fausse);
        let quoi = besoin(&session, &tete(b"POST", b"/v1/defi"), &corps);
        let _ = repondre(
            &mut session,
            &quoi,
            &Trouvaille::Cle(secrete.publique()),
            None,
            &mut sortie,
        );

        // Et maintenant la VRAIE signature, pour ce même défi : elle doit être
        // refusée, puisque le défi n'existe plus.
        let juste = secrete
            .signer(machine, &defi, &liaison())
            .expect("elle signe");
        let corps = corps_de_preuve(machine, &juste);
        let quoi = besoin(&session, &tete(b"POST", b"/v1/defi"), &corps);
        let reponse = repondre(
            &mut session,
            &quoi,
            &Trouvaille::Cle(secrete.publique()),
            None,
            &mut sortie,
        );
        assert_eq!(
            reponse.status(),
            StatusCode::UNAUTHORIZED,
            "le défi a survécu à un échec"
        );
    }

    #[test]
    fn une_preuve_sans_defi_tire_est_refusee() {
        let (machine, secrete) = une_machine();
        let mut session = Session::new(liaison());
        let signature = secrete
            .signer(machine, &Defi::depuis_octets([1; 32]), &liaison())
            .expect("elle signe");
        let corps = corps_de_preuve(machine, &signature);
        let quoi = besoin(&session, &tete(b"POST", b"/v1/defi"), &corps);
        let mut sortie = [0_u8; 256];
        let reponse = repondre(
            &mut session,
            &quoi,
            &Trouvaille::Cle(secrete.publique()),
            None,
            &mut sortie,
        );
        assert_eq!(reponse.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn une_machine_introuvable_est_refusee_comme_les_autres() {
        // **LE MÊME `401` QUE POUR UNE SIGNATURE FAUSSE.** Distinguer dirait à
        // qui essaie quels identifiants de machine existent.
        let (machine, secrete) = une_machine();
        let mut session = Session::new(liaison());
        let defi = tirer(&mut session, Defi::depuis_octets([1; 32]));
        let signature = secrete.signer(machine, &defi, &liaison()).expect("signe");
        let corps = corps_de_preuve(machine, &signature);
        let quoi = besoin(&session, &tete(b"POST", b"/v1/defi"), &corps);
        let mut sortie = [0_u8; 256];
        let reponse = repondre(&mut session, &quoi, &Trouvaille::Rien, None, &mut sortie);
        assert_eq!(reponse.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(session.machine(), None);
    }

    #[test]
    fn un_corps_de_preuve_de_la_mauvaise_taille_est_un_400() {
        let session = Session::new(liaison());
        for taille in [0_usize, 1, PREUVE_OCTETS - 1, PREUVE_OCTETS + 1] {
            let corps = alloc::vec![0_u8; taille];
            assert_eq!(
                besoin(&session, &tete(b"POST", b"/v1/defi"), &corps),
                Besoin::Deja(StatusCode::BAD_REQUEST),
                "{taille} octets"
            );
        }
    }

    #[test]
    fn une_preuve_dont_le_genre_n_est_pas_une_machine_est_un_400() {
        let session = Session::new(liaison());
        let mut corps = alloc::vec![0_u8; PREUVE_OCTETS];
        corps[0] = Genre::Utilisateur.prefixe();
        assert_eq!(
            besoin(&session, &tete(b"POST", b"/v1/defi"), &corps),
            Besoin::Deja(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn sans_preuve_une_lecture_de_machine_est_un_401() {
        // **ET CETTE FOIS LE MOT EST JUSTE** : `/v1/defi` attend bel et bien
        // derrière, ce qui n'était pas le cas quand tout rendait `501`.
        let session = Session::new(liaison());
        assert_eq!(
            besoin(&session, &tete(b"GET", b"/v1/ou?service=imap"), b""),
            Besoin::Deja(StatusCode::UNAUTHORIZED)
        );
    }

    #[test]
    fn avec_une_preuve_la_lecture_n_est_plus_refusee_pour_defaut_d_authentification() {
        let (session, _) = authentifier();
        let quoi = besoin(&session, &tete(b"GET", b"/v1/ou?service=imap"), b"");
        assert_ne!(
            quoi,
            Besoin::Deja(StatusCode::UNAUTHORIZED),
            "la connexion est authentifiée, le refus ne peut plus être celui-là"
        );
    }

    #[test]
    fn un_second_defi_remplace_le_premier() {
        // Deux défis vivants doubleraient les essais qu'un attaquant obtient
        // pour une même connexion.
        let (machine, secrete) = une_machine();
        let mut session = Session::new(liaison());
        let premier = tirer(&mut session, Defi::depuis_octets([1; 32]));
        let _ = tirer(&mut session, Defi::depuis_octets([2; 32]));

        let signature = secrete
            .signer(machine, &premier, &liaison())
            .expect("elle signe");
        let corps = corps_de_preuve(machine, &signature);
        let quoi = besoin(&session, &tete(b"POST", b"/v1/defi"), &corps);
        let mut sortie = [0_u8; 256];
        let reponse = repondre(
            &mut session,
            &quoi,
            &Trouvaille::Cle(secrete.publique()),
            None,
            &mut sortie,
        );
        assert_eq!(reponse.status(), StatusCode::UNAUTHORIZED);
    }
}

#[cfg(test)]
mod resolution {
    extern crate alloc;

    use alloc::vec;
    use ams_proto_http::{HeadBuilder, Limits, RequestHead, StatusCode};
    use asl_cle::LiaisonDeCanal;
    use asl_id::{Genre, Identifiant};

    use super::{Besoin, Resolution, Session, Trouvaille, besoin, repondre};

    fn liaison() -> LiaisonDeCanal {
        LiaisonDeCanal::depuis_octets([0x11; asl_cle::LIAISON_OCTETS])
    }

    fn tete<'a>(cible: &'a [u8]) -> RequestHead<'a> {
        tete_de(b"GET", cible)
    }

    fn tete_de<'a>(verbe: &'a [u8], cible: &'a [u8]) -> RequestHead<'a> {
        let limites = Limits::default();
        let mut constructeur = HeadBuilder::new(&limites);
        constructeur.field(b":method", verbe).expect("le verbe");
        constructeur.field(b":scheme", b"https").expect("le schéma");
        constructeur
            .field(b":authority", b"annuaire.example")
            .expect("l'autorité");
        constructeur.field(b":path", cible).expect("la cible");
        constructeur.finish().expect("une tête complète")
    }

    fn un(genre: Genre, graine: u8) -> Identifiant {
        Identifiant::depuis_entropie(genre, [graine; 16])
    }

    /// De quoi décider, avec ces deux propriétaires et ces autorisations.
    fn de_quoi_decider(
        proprietaire_du_demandeur: Identifiant,
        proprietaire_de_la_cible: Identifiant,
        autorisations: alloc::vec::Vec<asl_auth::Autorisation>,
    ) -> Resolution {
        Resolution {
            demandeur: asl_auth::Machine::nouvelle(
                un(Genre::Machine, 1),
                proprietaire_du_demandeur,
                asl_auth::Capacites::LECTURE,
            )
            .expect("une machine"),
            cible: asl_auth::Cible::nouvelle(
                un(Genre::Service, 1),
                un(Genre::Machine, 2),
                proprietaire_de_la_cible,
            )
            .expect("une cible"),
            autorisations,
            annonce: None,
        }
    }

    /// Le même, mais avec un service effectivement annoncé.
    fn de_quoi_decider_avec_annonce(
        proprietaire_du_demandeur: Identifiant,
        proprietaire_de_la_cible: Identifiant,
        autorisations: alloc::vec::Vec<asl_auth::Autorisation>,
    ) -> Resolution {
        let mut quoi = de_quoi_decider(
            proprietaire_du_demandeur,
            proprietaire_de_la_cible,
            autorisations,
        );
        quoi.annonce = Some(br#"{"service":"s-abc","joignabilite":[]}"#.to_vec());
        quoi
    }

    /// Le statut que rend une résolution.
    fn statut(quoi: Resolution) -> StatusCode {
        let mut session = Session::new(liaison());
        let mut sortie = [0_u8; 256];
        repondre(
            &mut session,
            &Besoin::Ou {
                machine: un(Genre::Machine, 2),
                service: "imap",
            },
            &Trouvaille::Resolution(quoi),
            None,
            &mut sortie,
        )
        .status()
    }

    /// Une session sur laquelle une machine a prouvé sa clé.
    fn session_authentifiee() -> Session {
        let secrete = asl_cle::CleSecrete::depuis_entropie([7; 32]);
        let machine = un(Genre::Machine, 1);
        let mut session = Session::new(liaison());
        let mut sortie = [0_u8; 256];

        let quoi = besoin(&session, &tete_de(b"GET", b"/v1/defi"), b"");
        let voulu = asl_cle::Defi::depuis_octets([9; 32]);
        let _ = repondre(
            &mut session,
            &quoi,
            &Trouvaille::Rien,
            Some(voulu),
            &mut sortie,
        );

        let signature = secrete
            .signer(machine, &voulu, &liaison())
            .expect("elle signe");
        let mut corps = alloc::vec::Vec::new();
        corps.push(Genre::Machine.prefixe());
        corps.extend_from_slice(machine.octets());
        corps.extend_from_slice(signature.octets());

        let quoi = besoin(&session, &tete_de(b"POST", b"/v1/defi"), &corps);
        let reponse = repondre(
            &mut session,
            &quoi,
            &Trouvaille::Cle(secrete.publique()),
            None,
            &mut sortie,
        );
        assert_eq!(reponse.status(), StatusCode::NO_CONTENT);
        session
    }

    #[test]
    fn sans_preuve_la_cible_ou_est_refusee_avant_meme_d_etre_routee() {
        let machine = un(Genre::Machine, 2);
        let chemin = alloc::format!("/v1/ou/{}/imap", machine.texte());
        assert_eq!(
            besoin(&Session::new(liaison()), &tete(chemin.as_bytes()), b""),
            Besoin::Deja(StatusCode::UNAUTHORIZED)
        );
    }

    #[test]
    fn avec_une_preuve_la_cible_ou_se_route_avec_sa_machine_et_son_nom() {
        let machine = un(Genre::Machine, 2);
        let chemin = alloc::format!("/v1/ou/{}/imap", machine.texte());
        assert_eq!(
            besoin(&session_authentifiee(), &tete(chemin.as_bytes()), b""),
            Besoin::Ou {
                machine,
                service: "imap",
            }
        );
    }

    #[test]
    fn son_propre_service_se_sert_sans_autorisation() {
        // Le propriétaire n'a besoin de l'autorisation de personne pour ses
        // propres machines.
        let moi = un(Genre::Utilisateur, 1);
        assert_eq!(
            statut(de_quoi_decider_avec_annonce(moi, moi, vec![])),
            StatusCode::OK,
            "servi"
        );
    }

    #[test]
    fn un_service_declare_mais_pas_annonce_est_introuvable() {
        // **LE DEMANDEUR Y A DROIT, ET IL N'Y A RIEN À JOINDRE.** On pourrait
        // vouloir dire « parti » plutôt qu'« introuvable » ; on ne le peut pas,
        // et c'est une conséquence assumée de ne jamais écrire l'état vivant :
        // un annuaire qui vient de redémarrer ne sait pas si ce service est
        // parti ou n'a jamais parlé.
        let moi = un(Genre::Utilisateur, 1);
        assert_eq!(
            statut(de_quoi_decider(moi, moi, vec![])),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn la_reponse_servie_est_celle_de_l_annonce() {
        let moi = un(Genre::Utilisateur, 1);
        let mut session = Session::new(liaison());
        let mut sortie = [0_u8; 512];
        let reponse = repondre(
            &mut session,
            &Besoin::Ou {
                machine: un(Genre::Machine, 2),
                service: "imap",
            },
            &Trouvaille::Resolution(de_quoi_decider_avec_annonce(moi, moi, vec![])),
            None,
            &mut sortie,
        );
        assert_eq!(reponse.status(), StatusCode::OK);
        assert_eq!(
            reponse.body(),
            br#"{"service":"s-abc","joignabilite":[]}"#,
            "la réponse servie doit être celle que l'annonce a composée"
        );
    }

    #[test]
    fn un_refus_ne_rend_jamais_l_annonce_meme_quand_elle_existe() {
        // **C'EST LA PROPRIÉTÉ QUI COMPTE.** L'étage 3 a lu ce qui est annoncé
        // AVANT de savoir si le demandeur y a droit — c'est sa propre mémoire.
        // Ce qui reste une décision est de la RENDRE, et elle se prend ici.
        let refuse = statut(de_quoi_decider_avec_annonce(
            un(Genre::Utilisateur, 1),
            un(Genre::Utilisateur, 2),
            vec![],
        ));
        assert_eq!(refuse, StatusCode::NOT_FOUND);
    }

    #[test]
    fn le_service_d_un_autre_sans_autorisation_est_introuvable() {
        // **C10 : UN REFUS REND `404`, ET NON `403`.** Un `403` dirait à qui
        // essaie que ce service EXISTE — et l'annuaire aurait alors un oracle
        // d'existence que rien n'autorise.
        assert_eq!(
            statut(de_quoi_decider(
                un(Genre::Utilisateur, 1),
                un(Genre::Utilisateur, 2),
                vec![]
            )),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn une_autorisation_de_tout_le_compte_ouvre_le_service() {
        let moi = un(Genre::Utilisateur, 1);
        let lui = un(Genre::Utilisateur, 2);
        let accord =
            asl_auth::Autorisation::nouvelle(lui, moi, asl_auth::Portee::ToutLeCompte, false)
                .expect("une autorisation");
        assert_eq!(
            statut(de_quoi_decider_avec_annonce(moi, lui, vec![accord])),
            StatusCode::OK,
            "servi"
        );
    }

    #[test]
    fn une_autorisation_revoquee_n_ouvre_plus_rien() {
        let moi = un(Genre::Utilisateur, 1);
        let lui = un(Genre::Utilisateur, 2);
        let retiree =
            asl_auth::Autorisation::nouvelle(lui, moi, asl_auth::Portee::ToutLeCompte, true)
                .expect("une autorisation");
        assert_eq!(
            statut(de_quoi_decider(moi, lui, vec![retiree])),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn une_autorisation_donnee_a_quelqu_un_d_autre_n_ouvre_rien() {
        // Elle est bien dans la liste — c'est l'entrepôt qui l'a rendue —, et
        // c'est `couvre` qui doit l'écarter.
        let moi = un(Genre::Utilisateur, 1);
        let lui = un(Genre::Utilisateur, 2);
        let tiers = un(Genre::Utilisateur, 3);
        let pour_un_autre =
            asl_auth::Autorisation::nouvelle(lui, tiers, asl_auth::Portee::ToutLeCompte, false)
                .expect("une autorisation");
        assert_eq!(
            statut(de_quoi_decider(moi, lui, vec![pour_un_autre])),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn une_machine_sans_capacite_de_lecture_ne_lit_rien() {
        // Même chez son propre propriétaire : la capacité est une décision de
        // l'utilisateur sur SA machine, et elle prime.
        let moi = un(Genre::Utilisateur, 1);
        let mut quoi = de_quoi_decider(moi, moi, vec![]);
        quoi.demandeur =
            asl_auth::Machine::nouvelle(un(Genre::Machine, 1), moi, asl_auth::Capacites::ANNONCE)
                .expect("une machine qui annonce seulement");
        assert_eq!(statut(quoi), StatusCode::NOT_FOUND);
    }

    #[test]
    fn sans_de_quoi_decider_c_est_le_meme_404() {
        // Un service absent, une machine absente, un demandeur introuvable : le
        // même refus, pour que rien ne dise à qui essaie ce qui existe.
        let mut session = Session::new(liaison());
        let mut sortie = [0_u8; 256];
        let reponse = repondre(
            &mut session,
            &Besoin::Ou {
                machine: un(Genre::Machine, 2),
                service: "imap",
            },
            &Trouvaille::Rien,
            None,
            &mut sortie,
        );
        assert_eq!(reponse.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn une_resolution_rendue_a_un_besoin_de_compte_est_une_panne_de_serveur() {
        let mut session = Session::new(liaison());
        let mut sortie = [0_u8; 256];
        let moi = un(Genre::Utilisateur, 1);
        let reponse = repondre(
            &mut session,
            &Besoin::Compte(moi),
            &Trouvaille::Resolution(de_quoi_decider(moi, moi, vec![])),
            None,
            &mut sortie,
        );
        assert_eq!(reponse.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ── Les verbes de liste ─────────────────────────────────────────────────

    use alloc::vec::Vec;
    use asl_api::corps::{AutorisationRendue, Portee};

    /// Ce que rend une réponse : son statut et son corps.
    fn rendu(besoin_: &Besoin<'_>, trouvaille: &Trouvaille) -> (StatusCode, alloc::string::String) {
        let mut session = Session::new(liaison());
        let mut sortie = [0_u8; 8192];
        let reponse = repondre(&mut session, besoin_, trouvaille, None, &mut sortie);
        let statut = reponse.status();
        let corps = alloc::string::String::from_utf8_lossy(reponse.body()).into_owned();
        (statut, corps)
    }

    fn une_autorisation_rendue(marque: u8) -> AutorisationRendue {
        AutorisationRendue {
            autorisation: un(Genre::Autorisation, marque),
            par: un(Genre::Utilisateur, 1),
            a: un(Genre::Utilisateur, 2),
            portee: Portee::ToutLeCompte,
            revoquee: false,
        }
    }

    #[test]
    fn une_liste_vide_est_un_tableau_vide_et_non_un_404() {
        // **« JE N'AI RIEN À TE MONTRER » ET « CETTE RESSOURCE N'EXISTE PAS » NE
        // SE CORRIGENT PAS AU MÊME ENDROIT.** Un client qui lirait `404` là où il
        // devait lire `[]` croirait son appel fautif.
        for (besoin_, trouvaille) in [
            (Besoin::OuParNom { service: "depot" }, Trouvaille::Rien),
            (
                Besoin::ServicesDeMachine {
                    machine: un(Genre::Machine, 2),
                },
                Trouvaille::Rien,
            ),
            (Besoin::MesAutorisations, Trouvaille::Rien),
        ] {
            let (statut, corps) = rendu(&besoin_, &trouvaille);
            assert_eq!(statut, StatusCode::OK, "{besoin_:?}");
            assert_eq!(corps, "[]", "{besoin_:?}");
        }
    }

    #[test]
    fn une_liste_de_resolutions_n_emporte_que_ce_qui_se_rend() {
        // **L'OMISSION NE DIT RIEN DE CE QU'ELLE OMET** (C10) : la forme par
        // machine rend `404` aussi bien pour « absent » que pour « interdit » ;
        // une liste, elle, se contente de ne pas porter ce qu'on ne peut voir.
        let moi = un(Genre::Utilisateur, 1);
        let autre = un(Genre::Utilisateur, 2);

        let quoi = vec![
            // À moi, et annoncé : elle sort.
            de_quoi_decider_avec_annonce(moi, moi, vec![]),
            // À quelqu'un d'autre, sans autorisation : écartée.
            de_quoi_decider_avec_annonce(moi, autre, vec![]),
            // À moi, mais rien d'annoncé : rien à joindre, donc rien à rendre.
            de_quoi_decider(moi, moi, vec![]),
        ];

        let (statut, corps) = rendu(
            &Besoin::OuParNom { service: "depot" },
            &Trouvaille::Resolutions(quoi),
        );
        assert_eq!(statut, StatusCode::OK);
        assert_eq!(
            corps, r#"[{"service":"s-abc","joignabilite":[]}]"#,
            "{corps}"
        );
    }

    #[test]
    fn une_autorisation_fait_entrer_ce_qui_n_est_pas_a_nous() {
        // La règle est celle d'`asl_auth::decider_resolution`, la MÊME que pour
        // la forme par machine. Une liste qui l'aurait réécrite pour aller plus
        // vite serait celle qui finit par diverger.
        let moi = un(Genre::Utilisateur, 1);
        let autre = un(Genre::Utilisateur, 2);
        let accordee =
            asl_auth::Autorisation::nouvelle(autre, moi, asl_auth::Portee::ToutLeCompte, false)
                .expect("une autorisation");

        let (_, sans) = rendu(
            &Besoin::OuParNom { service: "depot" },
            &Trouvaille::Resolutions(vec![de_quoi_decider_avec_annonce(moi, autre, vec![])]),
        );
        assert_eq!(sans, "[]", "sans autorisation, rien ne sort");

        let (_, avec) = rendu(
            &Besoin::OuParNom { service: "depot" },
            &Trouvaille::Resolutions(vec![de_quoi_decider_avec_annonce(
                moi,
                autre,
                vec![accordee],
            )]),
        );
        assert!(avec.contains("s-abc"), "{avec}");
    }

    #[test]
    fn au_dela_de_la_borne_c_est_500_et_non_une_liste_tronquee() {
        // **UNE LISTE TRONQUÉE MENTIRAIT PAR OMISSION**, et le demandeur croirait
        // avoir tout vu. `500` est le mot juste : il n'a rien fait de mal, c'est
        // nous qui avons plus à dire que notre protocole ne sait exprimer.
        let moi = un(Genre::Utilisateur, 1);
        let trop: Vec<Resolution> = (0..=asl_proto::LISTE_MAX)
            .map(|_| de_quoi_decider_avec_annonce(moi, moi, vec![]))
            .collect();

        let (statut, _) = rendu(
            &Besoin::OuParNom { service: "depot" },
            &Trouvaille::Resolutions(trop),
        );
        assert_eq!(statut, StatusCode::INTERNAL_SERVER_ERROR);

        // La même borne, sur les deux autres verbes.
        let annonces: Vec<Vec<u8>> = (0..=asl_proto::LISTE_MAX).map(|_| b"1".to_vec()).collect();
        let (statut, _) = rendu(
            &Besoin::ServicesDeMachine {
                machine: un(Genre::Machine, 2),
            },
            &Trouvaille::ServicesDeMachine {
                demandeur: moi,
                proprietaire: moi,
                annonces,
            },
        );
        assert_eq!(statut, StatusCode::INTERNAL_SERVER_ERROR);

        let beaucoup: Vec<AutorisationRendue> = (0..=asl_proto::LISTE_MAX)
            .map(|_| une_autorisation_rendue(3))
            .collect();
        let (statut, _) = rendu(
            &Besoin::MesAutorisations,
            &Trouvaille::Autorisations(beaucoup),
        );
        assert_eq!(statut, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn les_services_d_une_machine_ne_se_rendent_qu_a_leur_proprietaire() {
        // **UNE AUTORISATION DE LECTURE N'OUVRE PAS L'ÉNUMÉRATION D'UN PARC.**
        // `GET /v1/machines/{m}/services` est l'écran qui montre MES machines ;
        // le chemin inter-comptes est `GET /v1/ou`.
        let moi = un(Genre::Utilisateur, 1);
        let autre = un(Genre::Utilisateur, 2);
        let annonces = vec![br#"{"service":"s-abc"}"#.to_vec()];

        let (statut, corps) = rendu(
            &Besoin::ServicesDeMachine {
                machine: un(Genre::Machine, 2),
            },
            &Trouvaille::ServicesDeMachine {
                demandeur: moi,
                proprietaire: moi,
                annonces: annonces.clone(),
            },
        );
        assert_eq!(statut, StatusCode::OK);
        assert_eq!(corps, r#"[{"service":"s-abc"}]"#);

        let (statut, corps) = rendu(
            &Besoin::ServicesDeMachine {
                machine: un(Genre::Machine, 2),
            },
            &Trouvaille::ServicesDeMachine {
                demandeur: moi,
                proprietaire: autre,
                annonces,
            },
        );
        assert_eq!(
            statut,
            StatusCode::OK,
            "un refus ne se distingue pas d'un vide"
        );
        assert_eq!(corps, "[]", "et il ne dit pas si la machine existe");
    }

    #[test]
    fn les_autorisations_sortent_dans_les_deux_sens_et_marquees() {
        // `protocole.md` §2.2 : « ce que j'ai accordé, ce qu'on m'a accordé ».
        // Un seul tableau : `par` et `a` disent déjà de quel côté chacune est.
        let mut accordee = une_autorisation_rendue(3);
        accordee.revoquee = true;
        let recue = AutorisationRendue {
            autorisation: un(Genre::Autorisation, 4),
            par: un(Genre::Utilisateur, 2),
            a: un(Genre::Utilisateur, 1),
            portee: Portee::UneMachine(un(Genre::Machine, 9)),
            revoquee: false,
        };

        let (statut, corps) = rendu(
            &Besoin::MesAutorisations,
            &Trouvaille::Autorisations(vec![accordee, recue]),
        );
        assert_eq!(statut, StatusCode::OK);
        assert!(corps.starts_with('['), "{corps}");
        assert!(
            corps.contains(r#""revoquee":true"#),
            "les révoquées se voient : {corps}"
        );
        assert!(corps.contains(r#""revoquee":false"#), "{corps}");
        assert_eq!(corps.matches("autorisation").count(), 2, "{corps}");
    }

    #[test]
    fn une_trouvaille_qui_ne_correspond_pas_rend_un_tableau_vide() {
        // Ce cas ne devrait pas arriver, et l'étage 2 ne le suppose pas.
        for besoin_ in [
            Besoin::OuParNom { service: "depot" },
            Besoin::ServicesDeMachine {
                machine: un(Genre::Machine, 2),
            },
            Besoin::MesAutorisations,
        ] {
            let (statut, corps) = rendu(&besoin_, &Trouvaille::Refus);
            assert_eq!(statut, StatusCode::OK, "{besoin_:?}");
            assert_eq!(corps, "[]", "{besoin_:?}");
        }
    }

    #[test]
    fn les_trois_verbes_de_liste_se_routent() {
        let session = session_authentifiee();

        // `GET /v1/ou?service=` — la forme que le produit emploie.
        assert!(matches!(
            besoin(&session, &tete(b"/v1/ou?service=depot"), b""),
            Besoin::OuParNom { service: "depot" }
        ));

        // Les deux autres exigent un appareil, et la session n'en a pas :
        // `401` est la bonne réponse, et elle prouve quand même le routage.
        let sans = Session::new(liaison());
        for cible in [
            b"/v1/machines/m-0H248H248H248H248H248H248H/services".as_slice(),
            b"/v1/autorisations",
        ] {
            assert_eq!(
                besoin(&sans, &tete(cible), b""),
                Besoin::Deja(StatusCode::UNAUTHORIZED),
                "cette cible devrait exiger un appareil"
            );
        }
    }
    // ── Le flux des poussées ────────────────────────────────────────────────

    #[test]
    fn le_flux_des_poussees_s_ouvre_et_ne_se_ferme_pas() {
        // **C'EST TOUTE LA MÉCANIQUE, VUE DE L'ÉTAGE 2.** L'annuaire répond
        // `en_cours` parce qu'il ne fait pas attendre le démarrage d'un daemon le
        // temps d'une sonde ; le verdict arrive ensuite, sur ce flux-là. Une
        // réponse qui conclurait son flux le rendrait impossible.
        let mut session = session_authentifiee();
        let quoi = besoin(&session, &tete(b"/v1/poussees"), b"");
        assert_eq!(quoi, Besoin::EcouterLesPoussees);

        let mut sortie = [0_u8; 512];
        let reponse = repondre(&mut session, &quoi, &Trouvaille::Rien, None, &mut sortie);
        assert_eq!(reponse.status(), StatusCode::OK);
        assert!(reponse.est_tenue(), "le flux doit rester ouvert");

        // **NI CORPS, NI `content-length`.** Le premier octet sera la première
        // poussée ; une longueur déclarée sur un corps qui s'allonge est un
        // message qui se contredit.
        assert!(reponse.body().is_empty());
        let noms: alloc::vec::Vec<&[u8]> = reponse.fields().map(|(nom, _)| nom).collect();
        assert!(!noms.contains(&b"content-length".as_slice()), "{noms:?}");
    }

    #[test]
    fn le_flux_des_poussees_exige_une_machine() {
        // Sans clé prouvée sur cette connexion, `401` — et le mot est juste,
        // puisque `/v1/defi` attend bel et bien derrière.
        let sans = Session::new(liaison());
        assert_eq!(
            besoin(&sans, &tete(b"/v1/poussees"), b""),
            Besoin::Deja(StatusCode::UNAUTHORIZED)
        );
    }
}

#[cfg(test)]
mod enveloppe_de_l_annonce {
    extern crate alloc;

    use alloc::vec;
    use ams_proto_http::{HeadBuilder, Limits, RequestHead, StatusCode};
    use asl_cle::{CleSecrete, Defi, LiaisonDeCanal};
    use asl_id::{Genre, Identifiant};

    use super::{Besoin, JSON_MEDIA, PROBLEME_MEDIA, Session, Trouvaille, besoin, repondre};

    fn liaison() -> LiaisonDeCanal {
        LiaisonDeCanal::depuis_octets([0x11; asl_cle::LIAISON_OCTETS])
    }

    fn tete<'a>(verbe: &'a [u8], cible: &'a [u8]) -> RequestHead<'a> {
        let limites = Limits::default();
        let mut constructeur = HeadBuilder::new(&limites);
        constructeur.field(b":method", verbe).expect("le verbe");
        constructeur.field(b":scheme", b"https").expect("le schéma");
        constructeur
            .field(b":authority", b"annuaire.example")
            .expect("l'autorité");
        constructeur.field(b":path", cible).expect("la cible");
        constructeur.finish().expect("une tête complète")
    }

    fn champ<'a>(reponse: &ams_h3::Reponse<'a>, nom: &[u8]) -> Option<&'a [u8]> {
        reponse
            .fields()
            .find(|(cle, _)| *cle == nom)
            .map(|(_, valeur)| valeur)
    }

    /// Une session sur laquelle une machine a prouvé sa clé.
    fn authentifiee() -> Session {
        let secrete = CleSecrete::depuis_entropie([7; 32]);
        let machine = Identifiant::depuis_entropie(Genre::Machine, [3; 16]);
        let mut session = Session::new(liaison());
        let mut sortie = [0_u8; 256];

        let quoi = besoin(&session, &tete(b"GET", b"/v1/defi"), b"");
        let voulu = Defi::depuis_octets([9; 32]);
        let _ = repondre(
            &mut session,
            &quoi,
            &Trouvaille::Rien,
            Some(voulu),
            &mut sortie,
        );

        let signature = secrete
            .signer(machine, &voulu, &liaison())
            .expect("elle signe");
        let mut corps = vec![Genre::Machine.prefixe()];
        corps.extend_from_slice(machine.octets());
        corps.extend_from_slice(signature.octets());

        let quoi = besoin(&session, &tete(b"POST", b"/v1/defi"), &corps);
        let _ = repondre(
            &mut session,
            &quoi,
            &Trouvaille::Cle(secrete.publique()),
            None,
            &mut sortie,
        );
        session
    }

    #[test]
    fn sans_preuve_une_annonce_est_refusee_avant_d_etre_lue() {
        assert_eq!(
            besoin(
                &Session::new(liaison()),
                &tete(b"POST", b"/v1/annonce"),
                b"{}"
            ),
            Besoin::Deja(StatusCode::UNAUTHORIZED)
        );
    }

    #[test]
    fn avec_une_preuve_l_annonce_est_confiee_a_l_etage_3() {
        // **CETTE CRATE NE DÉCODE PAS LE MESSAGE**, et c'est le sujet de cet
        // essai : elle dit « c'est une annonce », et rien de plus. Le corps est
        // du charabia, et cela ne change rien ici.
        assert_eq!(
            besoin(
                &authentifiee(),
                &tete(b"POST", b"/v1/annonce"),
                b"n'importe quoi"
            ),
            Besoin::Annoncer
        );
    }

    #[test]
    fn une_annonce_prise_rend_ce_que_l_etage_3_a_compose() {
        let mut session = authentifiee();
        let mut sortie = [0_u8; 512];
        let compose = br#"{"service":"s-abc"}"#.to_vec();
        let reponse = repondre(
            &mut session,
            &Besoin::Annoncer,
            &Trouvaille::Annoncee(compose.clone()),
            None,
            &mut sortie,
        );
        assert_eq!(reponse.status(), StatusCode::OK);
        assert_eq!(champ(&reponse, b"content-type"), Some(JSON_MEDIA));
        assert_eq!(reponse.body(), compose.as_slice());
    }

    #[test]
    fn une_annonce_refusee_rend_403_et_non_404() {
        // **C10 NE S'APPLIQUE PAS ICI**, et il faut le dire : il impose de ne
        // rien laisser deviner sur une LECTURE. Une annonce ne lit rien — le
        // daemon est authentifié, il n'a simplement pas la capacité. Lui rendre
        // « introuvable » l'enverrait chercher une faute d'URL.
        let mut session = authentifiee();
        let mut sortie = [0_u8; 512];
        let reponse = repondre(
            &mut session,
            &Besoin::Annoncer,
            &Trouvaille::Rien,
            None,
            &mut sortie,
        );
        assert_eq!(reponse.status(), StatusCode::FORBIDDEN);
        assert_eq!(champ(&reponse, b"content-type"), Some(PROBLEME_MEDIA));
        assert!(
            reponse.body().windows(3).any(|f| f == b"403"),
            "le corps porte son propre code"
        );
    }

    #[test]
    fn une_trouvaille_qui_ne_correspond_pas_a_une_annonce_est_aussi_un_403() {
        // Toute trouvaille qui n'est pas une annonce composée est un refus : il
        // n'y a rien d'autre à rendre, et inventer un `500` distinguerait pour
        // le client deux fautes qui ne le regardent pas.
        let mut session = authentifiee();
        let mut sortie = [0_u8; 512];
        let reponse = repondre(
            &mut session,
            &Besoin::Annoncer,
            &Trouvaille::Cle(CleSecrete::depuis_entropie([1; 32]).publique()),
            None,
            &mut sortie,
        );
        assert_eq!(reponse.status(), StatusCode::FORBIDDEN);
    }
}

#[cfg(test)]
mod creations {
    //! Ce qui CRÉE : les besoins qu'une requête produit, et les réponses.
    //!
    //! # CE MODULE ÉPROUVE LES DEUX MOITIÉS D'UNE RÈGLE
    //!
    //! Celui qui PRÉSENTE une clé signe qu'il la détient — création de compte,
    //! enrôlement d'une machine. Celui pour qui un tiers déjà authentifié
    //! l'apporte ne signe pas — enrôlement d'un appareil de plus. Les deux
    //! chemins sont ici, et le second dirait `PreuveRefusee` s'il exigeait la
    //! signature qu'il ne reçoit pas.

    extern crate alloc;

    use alloc::vec::Vec;
    use ams_proto_http::{HeadBuilder, Limits, RequestHead, StatusCode};
    use asl_cle::{CleSecrete, Defi, LiaisonDeCanal, Signature};
    use asl_id::{Genre, Identifiant};

    use super::{
        Besoin, CLE_SEULE_OCTETS, ENROLEMENT_CORPS_OCTETS, POSSESSION_OCTETS, Session, Trouvaille,
        besoin, repondre,
    };

    fn liaison() -> LiaisonDeCanal {
        LiaisonDeCanal::depuis_octets([0x11; asl_cle::LIAISON_OCTETS])
    }

    fn defi() -> Defi {
        Defi::depuis_octets([0x5A; asl_cle::DEFI_OCTETS])
    }

    /// Une session dont le défi est déjà tiré.
    fn session_avec_defi() -> Session {
        let mut session = Session::new(liaison());
        let _ = session.poser_le_defi(defi());
        session
    }

    /// Une session dont un appareil a prouvé la clé.
    fn session_d_appareil() -> Session {
        let mut session = Session::new(liaison());
        session.pair = Some(un(Genre::Appareil, 9));
        session
    }

    fn un(genre: Genre, graine: u8) -> Identifiant {
        Identifiant::depuis_entropie(genre, [graine; 16])
    }

    fn tete<'a>(verbe: &'a [u8], cible: &'a [u8]) -> RequestHead<'a> {
        let limites = Limits::default();
        let mut constructeur = HeadBuilder::new(&limites);
        constructeur.field(b":method", verbe).expect("le verbe");
        constructeur.field(b":scheme", b"https").expect("le schéma");
        constructeur
            .field(b":authority", b"annuaire.example")
            .expect("l'autorité");
        constructeur.field(b":path", cible).expect("la cible");
        constructeur.finish().expect("une tête close")
    }

    /// Une clé et sa preuve de possession, pour cette connexion.
    fn possession(graine: u8) -> (CleSecrete, Vec<u8>) {
        let secrete = CleSecrete::depuis_entropie([graine; 32]);
        let preuve = secrete.prouver_la_possession(&defi(), &liaison());
        let mut corps = Vec::with_capacity(POSSESSION_OCTETS);
        corps.extend_from_slice(&secrete.publique().octets());
        corps.extend_from_slice(preuve.octets());
        (secrete, corps)
    }

    /// Le corps et le statut d'une réponse.
    fn rendre(
        session: &mut Session,
        quoi: &Besoin<'_>,
        trouvaille: &Trouvaille,
    ) -> (StatusCode, Vec<u8>) {
        let mut sortie = [0_u8; 512];
        let reponse = repondre(session, quoi, trouvaille, None, &mut sortie);
        (reponse.status(), reponse.body().to_vec())
    }

    // ── La preuve de possession ─────────────────────────────────────────────

    #[test]
    fn une_preuve_juste_ouvre_la_creation_d_un_compte() {
        let (secrete, corps) = possession(0x11);
        let quoi = besoin(&session_avec_defi(), &tete(b"POST", b"/v1/comptes"), &corps);
        assert_eq!(
            quoi,
            Besoin::CreerCompte {
                cle: secrete.publique()
            }
        );
    }

    #[test]
    fn une_preuve_signee_pour_une_autre_cle_ne_vaut_pas() {
        // Les octets sont bien formés, la signature est valide — pour une AUTRE
        // clé. C'est le cas que le message de possession existe pour fermer.
        let (_, juste) = possession(0x11);
        let (autre, _) = possession(0x22);
        let mut corps = autre.publique().octets().to_vec();
        corps.extend_from_slice(&juste[asl_cle::CLE_PUBLIQUE_OCTETS..]);
        assert_eq!(
            besoin(&session_avec_defi(), &tete(b"POST", b"/v1/comptes"), &corps),
            Besoin::PreuveRefusee
        );
    }

    #[test]
    fn sans_defi_tire_aucune_possession_ne_se_prouve() {
        // **LE DÉFI EST CE QUI SÉPARE DEUX CONNEXIONS**, puisque la liaison de
        // canal, elle, est la même pour toutes. Sans lui, la preuve se rejouerait.
        let (_, corps) = possession(0x11);
        assert_eq!(
            besoin(
                &Session::new(liaison()),
                &tete(b"POST", b"/v1/comptes"),
                &corps
            ),
            Besoin::PreuveRefusee
        );
    }

    /// Trente-deux octets qui ne forment PAS un point de la courbe.
    ///
    /// **Tous les tableaux de trente-deux octets n'en sont pas**, et c'est
    /// exactement pourquoi la clé est vérifiée à la lecture : en ranger un
    /// ferait échouer toute vérification ultérieure sans qu'on sache pourquoi.
    const CLE_IMPOSSIBLE: [u8; asl_cle::CLE_PUBLIQUE_OCTETS] = [0x02; 32];

    #[test]
    fn une_cle_qui_n_est_pas_un_point_de_la_courbe_est_refusee() {
        assert!(asl_cle::ClePublique::depuis_octets(CLE_IMPOSSIBLE).is_err());
        let mut corps = [0_u8; POSSESSION_OCTETS];
        corps[..asl_cle::CLE_PUBLIQUE_OCTETS].copy_from_slice(&CLE_IMPOSSIBLE);
        assert_eq!(
            besoin(&session_avec_defi(), &tete(b"POST", b"/v1/comptes"), &corps),
            Besoin::Deja(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn une_preuve_refusee_depense_le_defi_et_rend_401() {
        // **ELLE LE DÉPENSE, ET C'EST TOUT L'INTÉRÊT DE CE BESOIN** : le garder
        // laisserait essayer autant de signatures qu'on veut contre un même défi.
        let mut session = session_avec_defi();
        let (statut, corps) = rendre(&mut session, &Besoin::PreuveRefusee, &Trouvaille::Rien);
        assert_eq!(statut, StatusCode::UNAUTHORIZED);
        assert!(corps.windows(3).any(|f| f == b"401"));

        let (_, encore) = possession(0x11);
        assert_eq!(
            besoin(&session, &tete(b"POST", b"/v1/comptes"), &encore),
            Besoin::PreuveRefusee,
            "le défi a bien été dépensé"
        );
    }

    // ── Créer un compte ─────────────────────────────────────────────────────

    #[test]
    fn un_compte_cree_rend_201_et_authentifie_la_connexion() {
        let (secrete, corps) = possession(0x11);
        let mut session = session_avec_defi();
        let quoi = besoin(&session, &tete(b"POST", b"/v1/comptes"), &corps);
        let compte = un(Genre::Utilisateur, 1);
        let appareil = un(Genre::Appareil, 2);

        let (statut, rendu) = rendre(
            &mut session,
            &quoi,
            &Trouvaille::CompteCree { compte, appareil },
        );
        assert_eq!(statut, StatusCode::CREATED);
        let texte = alloc::string::String::from_utf8_lossy(&rendu).into_owned();
        assert!(texte.contains(compte.texte().as_str()), "{texte}");
        assert!(texte.contains(appareil.texte().as_str()), "{texte}");

        // **LA MÊME PREUVE VAUT AUTHENTIFICATION.** Cet appareil vient de signer
        // le défi de cette connexion pour cette clé ; refaire le tour par
        // `/v1/defi` rejouerait la même démonstration.
        assert_eq!(session.appareil(), Some(appareil));
        assert_eq!(session.machine(), None, "un appareil n'est pas une machine");
        let _ = secrete;
    }

    #[test]
    fn une_creation_refusee_rend_403_et_une_panne_rend_500() {
        // `Refus` dit « la règle refuse » — l'attestation manque. `Rien` dit
        // « je n'ai pas pu » — l'entrepôt ou le noyau. Un client qui lirait
        // `500` là où il devait lire `403` réessaierait sans fin.
        for (trouvaille, attendu) in [
            (Trouvaille::Refus, StatusCode::FORBIDDEN),
            (Trouvaille::Rien, StatusCode::INTERNAL_SERVER_ERROR),
        ] {
            let (_, corps) = possession(0x11);
            let mut session = session_avec_defi();
            let quoi = besoin(&session, &tete(b"POST", b"/v1/comptes"), &corps);
            let (statut, _) = rendre(&mut session, &quoi, &trouvaille);
            assert_eq!(statut, attendu, "{trouvaille:?}");
            assert_eq!(session.appareil(), None, "rien n'a été authentifié");
        }
    }

    // ── Enrôler un appareil de plus ─────────────────────────────────────────

    #[test]
    fn un_appareil_de_plus_ne_porte_qu_une_cle() {
        // **AUCUNE PREUVE DE POSSESSION** : le nouveau téléphone ne parle pas
        // sur cette connexion, c'est un appareil déjà enrôlé qui apporte sa clé.
        let secrete = CleSecrete::depuis_entropie([0x33; 32]);
        let corps = secrete.publique().octets();
        assert_eq!(corps.len(), CLE_SEULE_OCTETS);
        assert_eq!(
            besoin(
                &session_d_appareil(),
                &tete(b"POST", b"/v1/appareils"),
                &corps
            ),
            Besoin::CreerAppareil {
                cle: secrete.publique()
            }
        );
    }

    #[test]
    fn un_appareil_de_plus_exige_un_appareil_deja_enrole() {
        let secrete = CleSecrete::depuis_entropie([0x33; 32]);
        let corps = secrete.publique().octets();
        assert_eq!(
            besoin(
                &Session::new(liaison()),
                &tete(b"POST", b"/v1/appareils"),
                &corps
            ),
            Besoin::Deja(StatusCode::UNAUTHORIZED)
        );

        // **ET UNE MACHINE NE SUFFIT PAS.** Sa clé vit en clair sur un disque
        // que tout daemon peut lire ; lui ouvrir l'administration d'un compte
        // donnerait à un daemon compromis le droit de s'y ajouter un appareil.
        let mut session = Session::new(liaison());
        session.pair = Some(un(Genre::Machine, 4));
        assert_eq!(
            besoin(&session, &tete(b"POST", b"/v1/appareils"), &corps),
            Besoin::Deja(StatusCode::UNAUTHORIZED)
        );
    }

    #[test]
    fn un_corps_d_appareil_mal_dimensionne_est_refuse() {
        for corps in [
            &b""[..],
            &[0_u8; 31][..],
            &[0_u8; 33][..],
            &CLE_IMPOSSIBLE[..],
        ] {
            let combien = corps.len();
            assert_eq!(
                besoin(
                    &session_d_appareil(),
                    &tete(b"POST", b"/v1/appareils"),
                    corps
                ),
                Besoin::Deja(StatusCode::BAD_REQUEST),
                "{combien} octets"
            );
        }
    }

    #[test]
    fn un_appareil_cree_rend_201_puis_403_et_500() {
        let appareil = un(Genre::Appareil, 5);
        let quoi = Besoin::CreerAppareil {
            cle: CleSecrete::depuis_entropie([0x33; 32]).publique(),
        };
        let mut session = session_d_appareil();
        let (statut, rendu) = rendre(&mut session, &quoi, &Trouvaille::AppareilCree(appareil));
        assert_eq!(statut, StatusCode::CREATED);
        assert!(alloc::string::String::from_utf8_lossy(&rendu).contains(appareil.texte().as_str()));

        assert_eq!(
            rendre(&mut session, &quoi, &Trouvaille::Refus).0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            rendre(&mut session, &quoi, &Trouvaille::Rien).0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    // ── Déclarer une machine, et émettre un code ────────────────────────────

    #[test]
    fn une_declaration_de_machine_se_lit_et_rend_son_code() {
        let quoi = besoin(
            &session_d_appareil(),
            &tete(b"POST", b"/v1/machines"),
            br#"{"nom":"grenier","capacites":["annonce"]}"#,
        );
        assert!(matches!(
            quoi,
            Besoin::CreerMachine {
                nom: "grenier",
                capacites: asl_api::corps::Capacites {
                    annonce: true,
                    lecture: false
                }
            }
        ));

        let machine = un(Genre::Machine, 6);
        let code = asl_cle::CodeEnrolement::analyser("4K9M2P7R1T").expect("un code");
        let mut session = session_d_appareil();
        let (statut, rendu) = rendre(
            &mut session,
            &quoi,
            &Trouvaille::MachineCreee {
                machine,
                code: code.texte_groupe(),
                expire_a: 1_757_000_000_000,
            },
        );
        assert_eq!(statut, StatusCode::CREATED);
        let texte = alloc::string::String::from_utf8_lossy(&rendu).into_owned();
        assert!(texte.contains(machine.texte().as_str()), "{texte}");
        assert!(texte.contains("4K9M2-P7R1T"), "{texte}");
        assert!(texte.contains("1757000000000"), "{texte}");

        assert_eq!(
            rendre(&mut session, &quoi, &Trouvaille::Refus).0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            rendre(&mut session, &quoi, &Trouvaille::Rien).0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn une_declaration_mal_formee_est_refusee() {
        assert_eq!(
            besoin(&session_d_appareil(), &tete(b"POST", b"/v1/machines"), b"{"),
            Besoin::Deja(StatusCode::BAD_REQUEST)
        );
    }

    // ── D'où l'on est vu ────────────────────────────────────────────────────

    #[test]
    fn ou_l_on_est_vu_ne_demande_aucune_preuve() {
        // **UNE SESSION NUE SUFFIT** : la question ne porte que sur la connexion
        // qui la pose, et exiger une clé aurait exclu la machine qu'on installe.
        assert_eq!(
            besoin(&Session::new(liaison()), &tete(b"GET", b"/v1/vu"), b""),
            Besoin::OuSuisJeVu
        );
    }

    #[test]
    fn une_adresse_v6_et_son_port_se_rendent_avec_leur_famille() {
        let vu = asl_proto::VuDepuis {
            adresse: core::net::IpAddr::V6(core::net::Ipv6Addr::new(
                0x2001, 0x0db8, 0, 0, 0, 0, 0, 1,
            )),
            port: asl_proto::Port::depuis_u16(49152).expect("un port"),
        };
        let mut session = Session::new(liaison());
        let (statut, rendu) = rendre(&mut session, &Besoin::OuSuisJeVu, &Trouvaille::VuDepuis(vu));
        assert_eq!(statut, StatusCode::OK);
        let texte = alloc::string::String::from_utf8_lossy(&rendu).into_owned();
        assert!(texte.contains(r#""adresse":"2001:db8::1""#), "{texte}");
        assert!(texte.contains(r#""port":49152"#), "{texte}");
        // **LA FAMILLE EST ÉCRITE**, pour qu'aucune des cinq liaisons n'ait à la
        // déduire en cherchant un `:` — ce qui marche jusqu'à `::ffff:203.0.113.7`.
        assert!(texte.contains(r#""famille":6"#), "{texte}");
    }

    #[test]
    fn une_adresse_v4_se_rend_aussi() {
        let vu = asl_proto::VuDepuis {
            adresse: core::net::IpAddr::V4(core::net::Ipv4Addr::new(203, 0, 113, 7)),
            port: asl_proto::Port::depuis_u16(1).expect("un port"),
        };
        let mut session = Session::new(liaison());
        let (statut, rendu) = rendre(&mut session, &Besoin::OuSuisJeVu, &Trouvaille::VuDepuis(vu));
        assert_eq!(statut, StatusCode::OK);
        let texte = alloc::string::String::from_utf8_lossy(&rendu).into_owned();
        assert!(texte.contains(r#""adresse":"203.0.113.7""#), "{texte}");
        assert!(texte.contains(r#""famille":4"#), "{texte}");
    }

    #[test]
    fn ne_pas_savoir_d_ou_l_on_voit_rend_404_et_non_500() {
        // **UN `500` ATTEIGNABLE PAR UN INCONNU EST UN `500` QU'UN INCONNU PEUT
        // FABRIQUER**, et cette ressource n'exige aucune preuve. Un journal où
        // les `500` se fabriquent à volonté ne sert plus à repérer les pannes.
        let mut session = Session::new(liaison());
        assert_eq!(
            rendre(&mut session, &Besoin::OuSuisJeVu, &Trouvaille::Rien).0,
            StatusCode::NOT_FOUND
        );
        // Une trouvaille d'un AUTRE genre, elle, reste un `500` : celle-là ne
        // peut venir que de l'étage 3, jamais du réseau.
        assert_eq!(
            rendre(&mut session, &Besoin::OuSuisJeVu, &Trouvaille::Fait).0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    // ── Le jeton de poussée ─────────────────────────────────────────────────

    #[test]
    fn les_deux_bornes_du_jeton_sont_le_meme_nombre() {
        // **`asl-api` RECOPIE LA BORNE DU MAGASIN**, parce qu'une grammaire ne
        // dépend pas d'un rangement. Cet essai est la seule chose qui relie les
        // deux copies : sans lui, un jeton accepté par le décodeur serait refusé
        // à l'écriture, et le téléphone cesserait silencieusement d'être joint.
        assert_eq!(asl_api::corps::JETON_MAX, asl_registre::JETON_OCTETS_MAX);
    }

    #[test]
    fn un_depot_de_jeton_se_lit_et_rend_204() {
        let appareil = un(Genre::Appareil, 5);
        let cible = alloc::format!("/v1/appareils/{}/poussee", appareil.texte());
        let quoi = besoin(
            &session_d_appareil(),
            &tete(b"PUT", cible.as_bytes()),
            br#"{"plateforme":"apns","jeton":"c0ffee"}"#,
        );
        assert_eq!(
            quoi,
            Besoin::PoserJetonDePoussee {
                appareil,
                plateforme: asl_api::corps::Plateforme::Apns,
                jeton: "c0ffee",
            }
        );

        let mut session = session_d_appareil();
        assert_eq!(
            rendre(&mut session, &quoi, &Trouvaille::Fait).0,
            StatusCode::NO_CONTENT
        );
        // **VISER L'APPAREIL D'UN AUTRE REND LE MÊME `404`** qu'un appareil qui
        // n'existe pas : dire « ce n'est pas vous » confirmerait son existence.
        assert_eq!(
            rendre(&mut session, &quoi, &Trouvaille::Rien).0,
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn un_depot_mal_forme_est_refuse() {
        let appareil = un(Genre::Appareil, 5);
        let cible = alloc::format!("/v1/appareils/{}/poussee", appareil.texte());
        for corps in [
            &b"{}"[..],
            &br#"{"plateforme":"apns"}"#[..],
            &br#"{"plateforme":"windows","jeton":"x"}"#[..],
            &br#"{"plateforme":"apns","jeton":""}"#[..],
        ] {
            assert_eq!(
                besoin(
                    &session_d_appareil(),
                    &tete(b"PUT", cible.as_bytes()),
                    corps
                ),
                Besoin::Deja(StatusCode::BAD_REQUEST),
                "{corps:?}"
            );
        }
    }

    // ── Modifier une machine ────────────────────────────────────────────────

    #[test]
    fn une_modification_se_lit_et_rend_204() {
        let machine = un(Genre::Machine, 6);
        let cible = alloc::format!("/v1/machines/{}", machine.texte());
        let quoi = besoin(
            &session_d_appareil(),
            &tete(b"PATCH", cible.as_bytes()),
            br#"{"nom":"grenier"}"#,
        );
        assert_eq!(
            quoi,
            Besoin::ModifierMachine {
                machine,
                nom: Some("grenier"),
                capacites: None,
            }
        );

        let mut session = session_d_appareil();
        assert_eq!(
            rendre(&mut session, &quoi, &Trouvaille::Fait).0,
            StatusCode::NO_CONTENT
        );
        // **UNE MACHINE QUI N'EST PAS À NOUS REND LE MÊME `404`** que celle qui
        // n'existe pas : les distinguer dirait à qui essaie des identifiants au
        // hasard lesquels existent.
        assert_eq!(
            rendre(&mut session, &quoi, &Trouvaille::Rien).0,
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn une_modification_ne_porte_que_ce_qu_elle_nomme() {
        let machine = un(Genre::Machine, 6);
        let cible = alloc::format!("/v1/machines/{}", machine.texte());
        // **LE TABLEAU VIDE RETIRE**, là où l'absence du champ laisse : c'est ce
        // qui permet à une machine de tout perdre par ce verbe.
        assert_eq!(
            besoin(
                &session_d_appareil(),
                &tete(b"PATCH", cible.as_bytes()),
                br#"{"capacites":[]}"#,
            ),
            Besoin::ModifierMachine {
                machine,
                nom: None,
                capacites: Some(asl_api::corps::Capacites {
                    annonce: false,
                    lecture: false,
                }),
            }
        );
    }

    #[test]
    fn une_modification_vide_ou_mal_formee_est_refusee() {
        let machine = un(Genre::Machine, 6);
        let cible = alloc::format!("/v1/machines/{}", machine.texte());
        for corps in [&b"{}"[..], &b"{"[..], &br#"{"couleur":"bleu"}"#[..]] {
            assert_eq!(
                besoin(
                    &session_d_appareil(),
                    &tete(b"PATCH", cible.as_bytes()),
                    corps,
                ),
                Besoin::Deja(StatusCode::BAD_REQUEST),
                "{corps:?}"
            );
        }
    }

    #[test]
    fn un_nouveau_code_nomme_la_machine_et_se_rend() {
        let machine = un(Genre::Machine, 6);
        let cible = alloc::format!("/v1/machines/{}/enrolement", machine.texte());
        let quoi = besoin(&session_d_appareil(), &tete(b"POST", cible.as_bytes()), b"");
        assert_eq!(quoi, Besoin::NouveauCode { machine });

        let code = asl_cle::CodeEnrolement::analyser("0123456789").expect("un code");
        let mut session = session_d_appareil();
        let (statut, rendu) = rendre(
            &mut session,
            &quoi,
            &Trouvaille::CodeEmis {
                code: code.texte_groupe(),
                expire_a: 0,
            },
        );
        assert_eq!(statut, StatusCode::CREATED);
        let texte = alloc::string::String::from_utf8_lossy(&rendu).into_owned();
        assert!(texte.contains("01234-56789"), "{texte}");
        // Zéro s'écrit sur un chiffre, et non sur vingt.
        assert!(texte.contains(r#""expire_a":0}"#), "{texte}");

        assert_eq!(
            rendre(&mut session, &quoi, &Trouvaille::Refus).0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            rendre(&mut session, &quoi, &Trouvaille::Rien).0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    // ── Enrôler une machine ─────────────────────────────────────────────────

    /// Le corps de `POST /v1/enrolement` : le code, la clé, la preuve.
    fn corps_d_enrolement(code: &str, graine: u8) -> Vec<u8> {
        let (_, possession) = possession(graine);
        let mut corps = Vec::with_capacity(ENROLEMENT_CORPS_OCTETS);
        corps.extend_from_slice(code.as_bytes());
        corps.extend_from_slice(&possession);
        corps
    }

    #[test]
    fn un_enrolement_rend_l_empreinte_du_code_et_jamais_le_code() {
        let corps = corps_d_enrolement("0123456789", 0x44);
        assert_eq!(corps.len(), ENROLEMENT_CORPS_OCTETS);
        let quoi = besoin(
            &session_avec_defi(),
            &tete(b"POST", b"/v1/enrolement"),
            &corps,
        );
        let attendue = asl_cle::CodeEnrolement::analyser("0123456789")
            .expect("un code")
            .empreinte();
        assert!(matches!(quoi, Besoin::Enroler { empreinte, .. } if empreinte == attendue));
    }

    #[test]
    fn le_rattrapage_de_crockford_vaut_jusque_dans_le_corps() {
        // Un `O` tapé pour un `0` doit désigner le même code : l'empreinte est
        // calculée sur la forme canonique, pas sur ce qui a été reçu.
        let juste = corps_d_enrolement("0123456789", 0x44);
        let rattrape = corps_d_enrolement("O123456789", 0x44);
        let a = besoin(
            &session_avec_defi(),
            &tete(b"POST", b"/v1/enrolement"),
            &juste,
        );
        let b = besoin(
            &session_avec_defi(),
            &tete(b"POST", b"/v1/enrolement"),
            &rattrape,
        );
        assert_eq!(a, b);
    }

    #[test]
    fn un_enrolement_mal_forme_est_refuse() {
        // Longueur, symbole hors alphabet, octets qui ne sont pas du texte.
        let mut trop_court = corps_d_enrolement("0123456789", 0x44);
        trop_court.pop();
        let mauvais_symbole = corps_d_enrolement("01234U6789", 0x44);
        let mut pas_du_texte = corps_d_enrolement("0123456789", 0x44);
        pas_du_texte[0] = 0xFF;

        for corps in [trop_court, mauvais_symbole, pas_du_texte] {
            let combien = corps.len();
            assert_eq!(
                besoin(
                    &session_avec_defi(),
                    &tete(b"POST", b"/v1/enrolement"),
                    &corps
                ),
                Besoin::Deja(StatusCode::BAD_REQUEST),
                "{combien} octets"
            );
        }
    }

    #[test]
    fn un_enrolement_dont_la_cle_n_est_pas_un_point_est_refuse() {
        // Le code est juste, la longueur aussi : c'est la CLÉ qui n'en est pas
        // une. La faute se voit à la lecture, et non trois requêtes plus tard.
        let mut corps = corps_d_enrolement("0123456789", 0x44);
        corps[asl_cle::CODE_SYMBOLES..asl_cle::CODE_SYMBOLES + asl_cle::CLE_PUBLIQUE_OCTETS]
            .copy_from_slice(&CLE_IMPOSSIBLE);
        assert_eq!(
            besoin(
                &session_avec_defi(),
                &tete(b"POST", b"/v1/enrolement"),
                &corps
            ),
            Besoin::Deja(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn un_enrolement_sans_preuve_de_possession_est_refuse() {
        // Le code seul ne suffit pas : la machine doit montrer qu'elle détient
        // la clé qu'elle présente.
        let mut corps = corps_d_enrolement("0123456789", 0x44);
        let dernier = corps.len().saturating_sub(1);
        corps[dernier] ^= 0xFF;
        assert_eq!(
            besoin(
                &session_avec_defi(),
                &tete(b"POST", b"/v1/enrolement"),
                &corps
            ),
            Besoin::PreuveRefusee
        );
    }

    #[test]
    fn une_machine_enrolee_rend_200_et_non_201() {
        // **RIEN N'A ÉTÉ CRÉÉ** : la machine existait ; ce qui a changé est
        // qu'elle a désormais une clé.
        let corps = corps_d_enrolement("0123456789", 0x44);
        let mut session = session_avec_defi();
        let quoi = besoin(&session, &tete(b"POST", b"/v1/enrolement"), &corps);
        let machine = un(Genre::Machine, 7);

        let (statut, rendu) = rendre(&mut session, &quoi, &Trouvaille::Enrolee(machine));
        assert_eq!(statut, StatusCode::OK);
        assert!(alloc::string::String::from_utf8_lossy(&rendu).contains(machine.texte().as_str()));

        // Et le défi est dépensé, comme pour toute preuve.
        assert_eq!(
            besoin(&session, &tete(b"POST", b"/v1/enrolement"), &corps),
            Besoin::PreuveRefusee
        );
    }

    #[test]
    fn un_code_inconnu_ou_perime_rend_403() {
        let corps = corps_d_enrolement("0123456789", 0x44);
        for (trouvaille, attendu) in [
            (Trouvaille::Refus, StatusCode::FORBIDDEN),
            (Trouvaille::Rien, StatusCode::INTERNAL_SERVER_ERROR),
        ] {
            let mut session = session_avec_defi();
            let quoi = besoin(&session, &tete(b"POST", b"/v1/enrolement"), &corps);
            assert_eq!(rendre(&mut session, &quoi, &trouvaille).0, attendu);
        }
    }

    // ── Les deux verbes de liste qui exigent un appareil ────────────────────

    #[test]
    fn les_services_d_une_machine_se_routent() {
        let machine = un(Genre::Machine, 5);
        let cible = alloc::format!("/v1/machines/{}/services", machine.texte());
        assert_eq!(
            besoin(&session_d_appareil(), &tete(b"GET", cible.as_bytes()), b""),
            Besoin::ServicesDeMachine { machine }
        );
    }

    #[test]
    fn get_et_post_sur_les_autorisations_ne_veulent_pas_dire_la_meme_chose() {
        // **`GET` TOMBAIT DANS LE DÉCODEUR D'UNE DEMANDE**, sur un corps vide, et
        // rendait `400`. Or le routage servait ce verbe depuis toujours : c'était
        // la répartition qui ne regardait que la ressource.
        //
        // **`400` ÉTAIT PIRE QU'UN `501`** : il disait « votre requête est mal
        // formée » à une requête parfaite, et envoyait chercher la faute chez
        // l'appelant.
        assert_eq!(
            besoin(
                &session_d_appareil(),
                &tete(b"GET", b"/v1/autorisations"),
                b""
            ),
            Besoin::MesAutorisations
        );

        let beneficiaire = un(Genre::Utilisateur, 3);
        let corps = alloc::format!(r#"{{"a":"{}","portee":"tout"}}"#, beneficiaire.texte());
        assert_eq!(
            besoin(
                &session_d_appareil(),
                &tete(b"POST", b"/v1/autorisations"),
                corps.as_bytes()
            ),
            Besoin::Autoriser {
                a: beneficiaire,
                portee: asl_api::corps::Portee::ToutLeCompte
            }
        );
    }

    // ── Accorder une autorisation ───────────────────────────────────────────

    #[test]
    fn une_autorisation_se_demande_et_se_rend() {
        let beneficiaire = un(Genre::Utilisateur, 3);
        let corps = alloc::format!(r#"{{"a":"{}","portee":"tout"}}"#, beneficiaire.texte());
        let quoi = besoin(
            &session_d_appareil(),
            &tete(b"POST", b"/v1/autorisations"),
            corps.as_bytes(),
        );
        assert_eq!(
            quoi,
            Besoin::Autoriser {
                a: beneficiaire,
                portee: asl_api::corps::Portee::ToutLeCompte
            }
        );

        let accordee = un(Genre::Autorisation, 8);
        let mut session = session_d_appareil();
        let (statut, rendu) = rendre(
            &mut session,
            &quoi,
            &Trouvaille::AutorisationCreee(accordee),
        );
        assert_eq!(statut, StatusCode::CREATED);
        assert!(alloc::string::String::from_utf8_lossy(&rendu).contains(accordee.texte().as_str()));

        assert_eq!(
            rendre(&mut session, &quoi, &Trouvaille::Refus).0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            rendre(&mut session, &quoi, &Trouvaille::Rien).0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn une_demande_d_autorisation_mal_formee_est_refusee() {
        assert_eq!(
            besoin(
                &session_d_appareil(),
                &tete(b"POST", b"/v1/autorisations"),
                b"{}"
            ),
            Besoin::Deja(StatusCode::BAD_REQUEST)
        );
    }

    // ── La preuve du défi, pour les deux genres qui signent ─────────────────

    #[test]
    fn un_appareil_prouve_sa_cle_comme_une_machine() {
        let appareil = un(Genre::Appareil, 9);
        let secrete = CleSecrete::depuis_entropie([0x55; 32]);
        let signature = secrete
            .signer(appareil, &defi(), &liaison())
            .expect("un appareil signe");
        let mut corps = alloc::vec![Genre::Appareil.prefixe()];
        corps.extend_from_slice(appareil.octets());
        corps.extend_from_slice(signature.octets());

        let quoi = besoin(&session_avec_defi(), &tete(b"POST", b"/v1/defi"), &corps);
        assert_eq!(
            quoi,
            Besoin::ClePourPreuve {
                machine: appareil,
                signature
            }
        );

        let mut session = session_avec_defi();
        let (statut, _) = rendre(&mut session, &quoi, &Trouvaille::Cle(secrete.publique()));
        assert_eq!(statut, StatusCode::NO_CONTENT);
        assert_eq!(session.appareil(), Some(appareil));
    }

    #[test]
    fn un_genre_qui_ne_signe_pas_est_refuse_des_la_lecture() {
        for genre in [
            Genre::Utilisateur,
            Genre::Service,
            Genre::Autorisation,
            Genre::Annuaire,
        ] {
            let mut corps = alloc::vec![genre.prefixe()];
            corps.extend_from_slice(un(genre, 1).octets());
            corps.extend_from_slice(&[0_u8; asl_cle::SIGNATURE_OCTETS]);
            assert_eq!(
                besoin(&session_avec_defi(), &tete(b"POST", b"/v1/defi"), &corps),
                Besoin::Deja(StatusCode::BAD_REQUEST),
                "{genre:?}"
            );
        }
    }

    #[test]
    fn une_signature_de_machine_ne_vaut_pas_pour_un_appareil() {
        // **LE GENRE ENTRE DANS LE MESSAGE SIGNÉ.** Ce n'est pas la lecture du
        // corps qui sépare les deux, c'est la signature elle-même.
        let secrete = CleSecrete::depuis_entropie([0x55; 32]);
        let machine = un(Genre::Machine, 9);
        let signature = secrete
            .signer(machine, &defi(), &liaison())
            .expect("elle signe");

        // Le même identifiant, relu comme un appareil.
        let appareil = Identifiant::depuis_entropie(Genre::Appareil, *machine.octets());
        let mut corps = alloc::vec![Genre::Appareil.prefixe()];
        corps.extend_from_slice(appareil.octets());
        corps.extend_from_slice(signature.octets());

        let mut session = session_avec_defi();
        let quoi = besoin(&session, &tete(b"POST", b"/v1/defi"), &corps);
        let (statut, _) = rendre(&mut session, &quoi, &Trouvaille::Cle(secrete.publique()));
        assert_eq!(statut, StatusCode::UNAUTHORIZED);
        assert_eq!(session.appareil(), None);
    }

    #[test]
    fn un_verbe_de_creation_signale_le_defi_manquant() {
        // `Signature` est `Copy` : on s'assure que le type public sert bien.
        let brute = Signature::depuis_octets([0; asl_cle::SIGNATURE_OCTETS]);
        assert_eq!(brute.octets().len(), asl_cle::SIGNATURE_OCTETS);
    }
}

#[cfg(test)]
mod retraits {
    //! Ce qui RETIRE, et l'alias.
    //!
    //! # UNE SEULE FORME DE RÉPONSE, ET C'EST CE QUI LES REND SÛRES
    //!
    //! `204` quand c'est fait, `404` quand l'objet visé n'existe pas **ou n'est
    //! pas à nous**. Les distinguer dirait à qui essaie des identifiants au
    //! hasard lesquels existent — et un identifiant qui existe est un compte
    //! qu'on vient de découvrir.

    extern crate alloc;

    use alloc::vec::Vec;
    use ams_proto_http::{HeadBuilder, Limits, RequestHead, StatusCode};
    use asl_cle::LiaisonDeCanal;
    use asl_id::{Genre, Identifiant};

    use super::{Besoin, Session, Trouvaille, besoin, repondre};

    fn liaison() -> LiaisonDeCanal {
        LiaisonDeCanal::depuis_octets([0x11; asl_cle::LIAISON_OCTETS])
    }

    fn un(genre: Genre, graine: u8) -> Identifiant {
        Identifiant::depuis_entropie(genre, [graine; 16])
    }

    /// Une session dont un appareil a prouvé la clé.
    fn session_d_appareil() -> Session {
        let mut session = Session::new(liaison());
        session.pair = Some(un(Genre::Appareil, 9));
        session
    }

    fn tete<'a>(verbe: &'a [u8], cible: &'a [u8]) -> RequestHead<'a> {
        let limites = Limits::default();
        let mut constructeur = HeadBuilder::new(&limites);
        constructeur.field(b":method", verbe).expect("le verbe");
        constructeur.field(b":scheme", b"https").expect("le schéma");
        constructeur
            .field(b":authority", b"annuaire.example")
            .expect("l'autorité");
        constructeur.field(b":path", cible).expect("la cible");
        constructeur.finish().expect("une tête close")
    }

    fn rendre(quoi: &Besoin<'_>, trouvaille: &Trouvaille) -> (StatusCode, Vec<u8>) {
        let mut session = session_d_appareil();
        let mut sortie = [0_u8; 512];
        let reponse = repondre(&mut session, quoi, trouvaille, None, &mut sortie);
        (reponse.status(), reponse.body().to_vec())
    }

    // ── Les trois révocations ───────────────────────────────────────────────

    #[test]
    fn les_trois_revocations_se_routent_vers_leur_besoin() {
        let appareil = un(Genre::Appareil, 1);
        let machine = un(Genre::Machine, 2);
        let autorisation = un(Genre::Autorisation, 3);

        let cible = alloc::format!("/v1/appareils/{}", appareil.texte());
        assert_eq!(
            besoin(
                &session_d_appareil(),
                &tete(b"DELETE", cible.as_bytes()),
                b""
            ),
            Besoin::RevoquerAppareil { appareil }
        );

        let cible = alloc::format!("/v1/machines/{}/cle", machine.texte());
        assert_eq!(
            besoin(
                &session_d_appareil(),
                &tete(b"DELETE", cible.as_bytes()),
                b""
            ),
            Besoin::RevoquerCleMachine { machine }
        );

        let cible = alloc::format!("/v1/autorisations/{}", autorisation.texte());
        assert_eq!(
            besoin(
                &session_d_appareil(),
                &tete(b"DELETE", cible.as_bytes()),
                b""
            ),
            Besoin::RevoquerAutorisation { autorisation }
        );
    }

    #[test]
    fn une_revocation_exige_un_appareil_et_pas_une_machine() {
        let cible = alloc::format!("/v1/appareils/{}", un(Genre::Appareil, 1).texte());

        assert_eq!(
            besoin(
                &Session::new(liaison()),
                &tete(b"DELETE", cible.as_bytes()),
                b""
            ),
            Besoin::Deja(StatusCode::UNAUTHORIZED)
        );

        // **LA CLÉ D'UNE MACHINE VIT EN CLAIR SUR UN DISQUE** que tout daemon
        // peut lire. Lui ouvrir la révocation permettrait à un daemon compromis
        // d'écarter les appareils de son propriétaire.
        let mut session = Session::new(liaison());
        session.pair = Some(un(Genre::Machine, 4));
        assert_eq!(
            besoin(&session, &tete(b"DELETE", cible.as_bytes()), b""),
            Besoin::Deja(StatusCode::UNAUTHORIZED)
        );
    }

    #[test]
    fn ce_qui_est_fait_rend_204_et_le_reste_rend_404() {
        let quoi = Besoin::RevoquerAppareil {
            appareil: un(Genre::Appareil, 1),
        };
        let (statut, corps) = rendre(&quoi, &Trouvaille::Fait);
        assert_eq!(statut, StatusCode::NO_CONTENT);
        assert!(corps.is_empty(), "`204` ne porte pas de corps");

        // **INCONNU ET PAS-À-NOUS SONT LE MÊME `404`.**
        let (statut, _) = rendre(&quoi, &Trouvaille::Rien);
        assert_eq!(statut, StatusCode::NOT_FOUND);
    }

    #[test]
    fn se_revoquer_soi_meme_rend_403_et_non_404() {
        // **CE REFUS-LÀ NE SE CACHE PAS** : celui qui demande connaît déjà son
        // propre identifiant, et il doit savoir pourquoi on lui dit non.
        let quoi = Besoin::RevoquerAppareil {
            appareil: un(Genre::Appareil, 9),
        };
        let (statut, corps) = rendre(&quoi, &Trouvaille::Refus);
        assert_eq!(statut, StatusCode::FORBIDDEN);
        assert!(corps.windows(3).any(|f| f == b"403"));
    }

    // ── L'alias ─────────────────────────────────────────────────────────────

    #[test]
    fn poser_et_retirer_un_alias_se_routent() {
        assert_eq!(
            besoin(
                &session_d_appareil(),
                &tete(b"PUT", b"/v1/alias"),
                br#"{"alias":"thierry"}"#
            ),
            Besoin::PoserAlias { alias: "thierry" }
        );
        assert_eq!(
            besoin(&session_d_appareil(), &tete(b"DELETE", b"/v1/alias"), b""),
            Besoin::RetirerAlias
        );
    }

    #[test]
    fn un_alias_mal_forme_est_refuse_avant_toute_ecriture() {
        assert_eq!(
            besoin(
                &session_d_appareil(),
                &tete(b"PUT", b"/v1/alias"),
                // Un alias est une CLÉ : le non-ASCII y est refusé, là où le nom
                // d'une machine l'accepte.
                "{\"alias\":\"Th\u{e9}r\u{e8}se\"}".as_bytes()
            ),
            Besoin::Deja(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn un_alias_deja_pris_rend_409_et_non_403() {
        // `403` dirait « vous n'avez pas le droit », ce qui est faux — n'importe
        // qui a le droit de demander un alias. C'est un CONFLIT : la demande est
        // légitime, et l'état du monde s'y oppose.
        let quoi = Besoin::PoserAlias { alias: "thierry" };
        let (statut, corps) = rendre(&quoi, &Trouvaille::Conflit);
        assert_eq!(statut, StatusCode::CONFLICT);
        assert!(corps.windows(3).any(|f| f == b"409"), "il porte son code");

        assert_eq!(rendre(&quoi, &Trouvaille::Fait).0, StatusCode::NO_CONTENT);
        assert_eq!(
            rendre(&Besoin::RetirerAlias, &Trouvaille::Fait).0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            rendre(&Besoin::RetirerAlias, &Trouvaille::Rien).0,
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn le_pair_de_la_session_se_lit_quel_que_soit_son_genre() {
        // C'est ce qui permet à l'étage 3 de savoir quelles connexions fermer.
        let session = session_d_appareil();
        assert_eq!(session.pair(), session.appareil());

        let mut session = Session::new(liaison());
        let machine = un(Genre::Machine, 4);
        session.pair = Some(machine);
        assert_eq!(session.pair(), Some(machine));
        assert_eq!(session.appareil(), None);

        assert_eq!(Session::new(liaison()).pair(), None);
    }
}
