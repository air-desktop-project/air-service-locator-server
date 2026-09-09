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
use asl_api::{Exigence, Ressource};
use asl_cle::{ClePublique, Defi, LiaisonDeCanal, Signature};
use asl_id::{Genre, Identifiant};
use asl_registre::AliasRange;

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
    /// De quoi décider d'une résolution.
    Resolution(Resolution),
    /// L'annonce a été prise, et voici ce qu'il faut répondre.
    ///
    /// Le corps est déjà encodé par `asl_proto::Reponse` — l'étage 3 l'a
    /// composé en même temps qu'il ouvrait la session vivante, parce que la
    /// réponse DÉCRIT cette session.
    Annoncee(alloc::vec::Vec<u8>),
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
    /// La machine qui a prouvé sa clé, s'il y en a une.
    machine: Option<Identifiant>,
}

impl Session {
    /// Une session neuve, liée à ce canal.
    #[must_use]
    pub const fn new(liaison: LiaisonDeCanal) -> Self {
        Self {
            liaison,
            defi: None,
            machine: None,
        }
    }

    /// La machine authentifiée sur cette connexion.
    #[must_use]
    pub const fn machine(&self) -> Option<Identifiant> {
        self.machine
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
    fn verifier(&mut self, machine: Identifiant, signature: &Signature, cle: &ClePublique) -> bool {
        let Some(defi) = self.defi.take() else {
            return false;
        };
        if !cle.verifie(machine, &defi, &self.liaison, signature) {
            return false;
        }
        self.machine = Some(machine);
        true
    }
}

/// **PREMIER TEMPS** : que faut-il pour répondre à cette requête ?
///
/// Rend [`Besoin::Deja`] quand la réponse ne dépend d'aucun état — un verbe
/// qu'on ne sert pas, une cible qui ne se route pas, un corps trop gros.
#[must_use]
pub fn besoin<'a>(session: &Session, tete: &RequestHead<'a>, corps: &[u8]) -> Besoin<'a> {
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
            if session.machine.is_none() {
                return Besoin::Deja(StatusCode::UNAUTHORIZED);
            }
        }
        // L'enrôlement d'un appareil mobile n'a pas de chemin de preuve : il
        // passe par un code d'enrôlement que rien ne sert encore.
        Exigence::Appareil => return Besoin::Deja(StatusCode::NOT_IMPLEMENTED),
    }

    match resolu.ressource {
        Ressource::AliasResolu { alias } => Besoin::CompteParAlias(alias.as_str()),
        Ressource::Utilisateur { compte } => Besoin::Compte(compte),
        Ressource::Annonce => Besoin::Annoncer,
        Ressource::Ou { machine, service } => Besoin::Ou {
            machine,
            service: service.as_str(),
        },
        // `Comptes` est un `POST` qui CRÉE : il ne se sert pas d'une lecture, et
        // il demande de l'entropie que cette crate n'a pas.
        _ => Besoin::Deja(StatusCode::NOT_IMPLEMENTED),
    }
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
    let genre = corps.first().copied().unwrap_or(0);
    if genre != Genre::Machine.prefixe() {
        return Besoin::Deja(StatusCode::BAD_REQUEST);
    }
    let mut entropie = [0_u8; 16];
    for (place, octet) in entropie.iter_mut().zip(corps.iter().skip(1)) {
        *place = *octet;
    }
    let mut brute = [0_u8; asl_cle::SIGNATURE_OCTETS];
    for (place, octet) in brute.iter_mut().zip(corps.iter().skip(17)) {
        *place = *octet;
    }
    Besoin::ClePourPreuve {
        machine: Identifiant::depuis_entropie(Genre::Machine, entropie),
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
                    // Servi — mais il n'y a rien à servir tant que les
                    // annonces ne sont pas rangées : l'état vivant d'un service
                    // n'existe pas encore.
                    asl_auth::Decision::Servir => composer(
                        StatusCode::NOT_IMPLEMENTED,
                        PROBLEME_MEDIA,
                        probleme(StatusCode::NOT_IMPLEMENTED),
                        sortie,
                    ),
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
            Trouvaille::Cle(_) | Trouvaille::Resolution(_) | Trouvaille::Annoncee(_) => composer(
                StatusCode::INTERNAL_SERVER_ERROR,
                PROBLEME_MEDIA,
                probleme(StatusCode::INTERNAL_SERVER_ERROR),
                sortie,
            ),
        },
    }
}

/// Ce qu'un corps de compte peut faire, en octets.
///
/// L'identifiant tient sur vingt-huit caractères, l'alias sur trente-deux, et le
/// reste est de la ponctuation. Cent vingt octets couvrent largement, et la
/// borne est ici pour que le tampon soit une CONSTANTE plutôt qu'un calcul.
pub const COMPTE_CORPS_MAX: usize = 120;

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
        Besoin, CORPS_OCTETS_MAX, JSON_MEDIA, NOMBRE_OCTETS_MAX, PROBLEME_MEDIA, Session,
        Trouvaille, besoin, composer, ecrire_un_nombre, probleme, repondre, statut_de, traduire,
    };

    /// La liaison de l'essai : celle d'un certificat quelconque.
    fn liaison() -> LiaisonDeCanal {
        asl_cle::liaison_depuis_certificat(b"le certificat du banc")
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
    fn ce_qui_exige_un_appareil_rend_encore_501() {
        // L'enrôlement d'un appareil mobile n'a pas de chemin de preuve : il
        // passe par un code d'enrôlement que rien ne sert encore. Dire `401`
        // inviterait à s'authentifier alors que rien ne l'attend derrière.
        assert_eq!(
            besoin(&session(), &tete(b"GET", b"/v1/expositions"), b""),
            Besoin::Deja(StatusCode::NOT_IMPLEMENTED)
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
    fn une_ressource_sans_exigence_qu_on_ne_sert_pas_encore_rend_501() {
        // `/v1/comptes` est un `POST` qui CRÉE : il ne se sert d'aucune lecture,
        // et il demande de l'entropie que cette crate n'a pas.
        assert_eq!(
            besoin(&session(), &tete(b"POST", b"/v1/comptes"), b""),
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
        asl_cle::liaison_depuis_certificat(b"le certificat du banc")
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
        // **C'EST LE RELAIS.** Une machine qui a signé pour le certificat d'un
        // intermédiaire ne s'authentifie pas ici.
        let (machine, secrete) = une_machine();
        let mut session = Session::new(liaison());
        let defi = tirer(&mut session, Defi::depuis_octets([1; 32]));

        let ailleurs = asl_cle::liaison_depuis_certificat(b"le certificat de l'intrus");
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
        let quoi = besoin(
            &session,
            &tete(b"POST", b"/v1/defi"),
            &corps_de_preuve(machine, &fausse),
        );
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
        let quoi = besoin(
            &session,
            &tete(b"POST", b"/v1/defi"),
            &corps_de_preuve(machine, &juste),
        );
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
        let quoi = besoin(
            &session,
            &tete(b"POST", b"/v1/defi"),
            &corps_de_preuve(machine, &signature),
        );
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
        let quoi = besoin(
            &session,
            &tete(b"POST", b"/v1/defi"),
            &corps_de_preuve(machine, &signature),
        );
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
        let quoi = besoin(
            &session,
            &tete(b"POST", b"/v1/defi"),
            &corps_de_preuve(machine, &signature),
        );
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
        asl_cle::liaison_depuis_certificat(b"le certificat du banc")
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
        }
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
            statut(de_quoi_decider(moi, moi, vec![])),
            StatusCode::NOT_IMPLEMENTED,
            "servi — il n'y a simplement rien à servir encore"
        );
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
            statut(de_quoi_decider(moi, lui, vec![accord])),
            StatusCode::NOT_IMPLEMENTED,
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
        asl_cle::liaison_depuis_certificat(b"le certificat du banc")
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
