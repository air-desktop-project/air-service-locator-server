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
//! # ET CE QU'ELLE NE DÉCIDE PAS ENCORE
//!
//! Tout ce qui exige une preuve rend `501` : l'authentification n'existe pas.
//! Répondre `401` serait pire — cela dirait à un client de s'authentifier et de
//! réessayer, alors que rien ne l'attend derrière.

#![no_std]

use ams_h3::Reponse;
use ams_proto_http::{Method, RequestHead, StatusCode};
use asl_api::{Exigence, Ressource};
use asl_id::Identifiant;
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

/// Ce qu'il faut aller chercher pour répondre.
///
/// **Ce n'est pas un effet, c'est un besoin.** L'étage 3 le satisfait ; cette
/// crate ne sait pas ouvrir un fichier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Besoin<'a> {
    /// Rien à chercher : la réponse est déjà décidée, et la voici.
    Deja(StatusCode),
    /// Le compte de cet identifiant.
    Compte(Identifiant),
    /// Le compte qui porte cet alias.
    CompteParAlias(&'a str),
}

/// Ce que l'étage 3 a trouvé.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
}

/// Ce qu'une session sait d'une connexion.
///
/// # ELLE EST VIDE, ET ELLE NE LE RESTERA PAS
///
/// Elle portera la machine authentifiée : **la connexion QUIC EST le bail**, et
/// ce qu'une requête a le droit de faire dépend de qui a signé le défi au début
/// de cette connexion-là. Une session par connexion est donc la bonne portée.
///
/// **Elle ne retient PAS le besoin en cours** : voir l'en-tête du module.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    /// Réservé : rien à retenir tant que rien ne s'authentifie.
    _rien: (),
}

impl Session {
    /// Une session neuve, pour une connexion neuve.
    #[must_use]
    pub const fn new() -> Self {
        Self { _rien: () }
    }
}

/// **PREMIER TEMPS** : que faut-il pour répondre à cette requête ?
///
/// Rend [`Besoin::Deja`] quand la réponse ne dépend d'aucun état — un verbe
/// qu'on ne sert pas, une cible qui ne se route pas, un corps trop gros.
#[must_use]
pub fn besoin<'a>(tete: &RequestHead<'a>, corps: &[u8]) -> Besoin<'a> {
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

    // **CE QUI EXIGE UNE PREUVE REND `501`, ET NON `401`.** L'authentification
    // n'existe pas : dire `401` inviterait un client à s'authentifier et à
    // réessayer, alors que rien ne l'attend derrière.
    if resolu.exigence != Exigence::Aucune {
        return Besoin::Deja(StatusCode::NOT_IMPLEMENTED);
    }

    match resolu.ressource {
        Ressource::AliasResolu { alias } => Besoin::CompteParAlias(alias.as_str()),
        Ressource::Utilisateur { compte } => Besoin::Compte(compte),
        // `Comptes` est un `POST` qui CRÉE : il ne se sert pas d'une lecture, et
        // il demande de l'entropie que cette crate n'a pas.
        _ => Besoin::Deja(StatusCode::NOT_IMPLEMENTED),
    }
}

/// **SECOND TEMPS** : voici ce qui a été trouvé, réponds.
///
/// Tout ce que la réponse désigne vit dans `sortie` — voir [`composer`].
#[must_use]
pub fn repondre<'o>(
    besoin: &Besoin<'_>,
    trouvaille: &Trouvaille,
    sortie: &'o mut [u8],
) -> Reponse<'o> {
    match besoin {
        Besoin::Deja(statut) => composer(*statut, PROBLEME_MEDIA, probleme(*statut), sortie),
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

    use super::{
        Besoin, CORPS_OCTETS_MAX, JSON_MEDIA, NOMBRE_OCTETS_MAX, PROBLEME_MEDIA, Session,
        Trouvaille, besoin, composer, ecrire_un_nombre, probleme, repondre, statut_de, traduire,
    };

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
    fn une_session_neuve_vaut_la_session_par_defaut() {
        assert_eq!(Session::new(), Session::default());
    }

    #[test]
    fn options_est_refuse_par_le_verbe() {
        assert_eq!(
            besoin(&tete(b"OPTIONS", b"/v1/machines"), b""),
            Besoin::Deja(StatusCode::METHOD_NOT_ALLOWED)
        );
    }

    #[test]
    fn un_corps_trop_gros_est_refuse_avant_toute_analyse() {
        let enorme = vec![b'x'; CORPS_OCTETS_MAX + 1];
        assert_eq!(
            besoin(&tete(b"POST", b"/v1/ceci-n-existe-pas"), &enorme),
            Besoin::Deja(StatusCode::CONTENT_TOO_LARGE),
            "le refus doit tomber AVANT que le routage ne regarde la cible"
        );
    }

    #[test]
    fn un_corps_juste_a_la_borne_passe() {
        let pile = vec![b'x'; CORPS_OCTETS_MAX];
        assert_ne!(
            besoin(&tete(b"POST", b"/v1/ceci-n-existe-pas"), &pile),
            Besoin::Deja(StatusCode::CONTENT_TOO_LARGE)
        );
    }

    #[test]
    fn une_cible_mal_formee_est_un_400() {
        assert_eq!(
            besoin(&tete(b"PATCH", b"/v1/machines/pas-un-identifiant"), b""),
            Besoin::Deja(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn une_ressource_qui_ne_sert_pas_ce_verbe_est_un_405() {
        assert_eq!(
            besoin(&tete(b"GET", b"/v1/machines"), b""),
            Besoin::Deja(StatusCode::METHOD_NOT_ALLOWED)
        );
    }

    #[test]
    fn une_cible_inconnue_est_un_404() {
        assert_eq!(
            besoin(&tete(b"GET", b"/v1/rien-de-tel"), b""),
            Besoin::Deja(StatusCode::NOT_FOUND)
        );
    }

    #[test]
    fn ce_qui_exige_une_preuve_rend_501_et_non_401() {
        // `401` dirait à un client de s'authentifier et de réessayer, alors que
        // rien ne l'attend derrière.
        assert_eq!(
            besoin(&tete(b"GET", b"/v1/expositions"), b""),
            Besoin::Deja(StatusCode::NOT_IMPLEMENTED)
        );
    }

    #[test]
    fn un_alias_demande_le_compte_qui_le_porte() {
        assert_eq!(
            besoin(&tete(b"GET", b"/v1/alias/thierry"), b""),
            Besoin::CompteParAlias("thierry")
        );
    }

    #[test]
    fn un_utilisateur_demande_son_compte() {
        let qui = un_compte(1);
        let texte = alloc::format!("/v1/utilisateurs/{}", qui.texte());
        assert_eq!(
            besoin(&tete(b"GET", texte.as_bytes()), b""),
            Besoin::Compte(qui)
        );
    }

    #[test]
    fn une_ressource_sans_exigence_qu_on_ne_sert_pas_encore_rend_501() {
        // `/v1/comptes` est un `POST` qui CRÉE : il ne se sert d'aucune lecture,
        // et il demande de l'entropie que cette crate n'a pas.
        assert_eq!(
            besoin(&tete(b"POST", b"/v1/comptes"), b""),
            Besoin::Deja(StatusCode::NOT_IMPLEMENTED)
        );
    }

    // ── repondre ────────────────────────────────────────────────────────────

    #[test]
    fn un_besoin_deja_decide_rend_son_statut() {
        let mut sortie = [0_u8; 256];
        let reponse = repondre(
            &Besoin::Deja(StatusCode::NOT_FOUND),
            &Trouvaille::Rien,
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
            &Besoin::Deja(StatusCode::METHOD_NOT_ALLOWED),
            &Trouvaille::Compte {
                qui: un_compte(1),
                alias: None,
            },
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
            let reponse = repondre(&besoin, &Trouvaille::Rien, &mut sortie);
            assert_eq!(reponse.status(), StatusCode::NOT_FOUND, "{besoin:?}");
        }
    }

    #[test]
    fn un_compte_trouve_rend_son_identifiant() {
        let qui = un_compte(7);
        let mut sortie = [0_u8; 512];
        let reponse = repondre(
            &Besoin::Compte(qui),
            &Trouvaille::Compte { qui, alias: None },
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
            &Besoin::CompteParAlias("thierry"),
            &Trouvaille::Compte {
                qui,
                alias: Some(AliasRange::nouveau("thierry").expect("il tient")),
            },
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
            &Besoin::Compte(qui),
            &Trouvaille::Compte {
                qui,
                alias: Some(AliasRange::nouveau(&long).expect("il tient")),
            },
            &mut sortie,
        );
        let rendu = core::str::from_utf8(reponse.body()).expect("du JSON en ASCII");
        assert!(rendu.len() <= super::COMPTE_CORPS_MAX, "{rendu}");
        assert!(rendu.ends_with('}'), "le JSON a été tronqué : {rendu}");
    }
}
