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
//! # ET CE QU'ELLE NE DÉCIDE PAS ENCORE
//!
//! Tout le reste rend `501`. Ce n'est pas un trou : **aucune ressource de cette
//! API ne se sert sans état**, et l'entrepôt n'existe pas. Répondre `401` serait
//! pire — cela dirait à un client de s'authentifier et de réessayer, alors que
//! rien ne l'attend derrière.

#![no_std]

use ams_h3::Reponse;
use ams_proto_http::{Method, RequestHead, StatusCode};

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

/// Ce qu'une session sait d'une connexion.
///
/// # ELLE EST VIDE, ET ELLE NE LE RESTERA PAS
///
/// Elle portera la machine authentifiée : **la connexion QUIC EST le bail**, et
/// ce qu'une requête a le droit de faire dépend de qui a signé le défi au début
/// de cette connexion-là. Une session par connexion est donc la bonne portée, et
/// c'est pour cela que ce type existe déjà plutôt qu'une fonction libre.
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

    /// Décide de la réponse à cette requête.
    ///
    /// Tout ce que la réponse désigne vit dans `sortie` — voir [`composer`].
    pub fn servir<'o>(
        &mut self,
        tete: &RequestHead<'_>,
        corps: &[u8],
        sortie: &'o mut [u8],
    ) -> Reponse<'o> {
        let Some((methode, sans_corps)) = traduire(tete.method()) else {
            return composer(StatusCode::METHOD_NOT_ALLOWED, false, sortie);
        };

        if corps.len() > CORPS_OCTETS_MAX {
            return composer(StatusCode::CONTENT_TOO_LARGE, sans_corps, sortie);
        }

        let resolu = match asl_api::resoudre(methode, tete.path()) {
            Ok(resolu) => resolu,
            Err(faute) => return composer(statut_de(faute), sans_corps, sortie),
        };

        if !resolu.sert {
            return composer(StatusCode::METHOD_NOT_ALLOWED, sans_corps, sortie);
        }

        // La cible se route, le verbe est servi — et rien ne peut encore être
        // rendu, faute d'entrepôt.
        composer(StatusCode::NOT_IMPLEMENTED, sans_corps, sortie)
    }
}

/// C'est par là qu'`ams-h3` entre.
///
/// # POURQUOI L'IMPLÉMENTATION EST ICI ET NON DANS LA BOUCLE
///
/// [`ams_h3::Service`] est un trait étranger, [`Session`] est notre type : la
/// règle de l'orphelin autorise le mariage ici, et l'interdit ailleurs. Ce n'est
/// pas une contrainte subie — **c'est le bon endroit**, puisque rien dans ce
/// trait ne demande une socket.
///
/// La boucle n'a donc qu'à tenir une `Session` par connexion et la lui passer.
impl ams_h3::Service for Session {
    fn serve<'o>(
        &mut self,
        tete: &RequestHead<'_>,
        corps: &[u8],
        sortie: &'o mut [u8],
    ) -> Reponse<'o> {
        self.servir(tete, corps, sortie)
    }
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
pub fn composer(statut: StatusCode, sans_corps: bool, sortie: &mut [u8]) -> Reponse<'_> {
    let corps = probleme(statut);

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
    let ecrit = if sans_corps {
        0
    } else {
        corps.len().min(pour_le_corps)
    };

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

    let media = if statut == StatusCode::OK {
        JSON_MEDIA
    } else {
        PROBLEME_MEDIA
    };

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

    use super::{
        CORPS_OCTETS_MAX, JSON_MEDIA, NOMBRE_OCTETS_MAX, PROBLEME_MEDIA, Session, composer,
        ecrire_un_nombre, probleme, statut_de, traduire,
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

    /// Rend le statut, et la valeur du champ nommé.
    fn champ<'a>(reponse: &ams_h3::Reponse<'a>, nom: &[u8]) -> Option<&'a [u8]> {
        reponse
            .fields()
            .find(|(cle, _)| *cle == nom)
            .map(|(_, valeur)| valeur)
    }

    // ── traduire ────────────────────────────────────────────────────────────

    #[test]
    fn head_est_un_get_sans_corps() {
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
            assert!(
                corps.windows(3).any(|fenetre| fenetre == attendu),
                "le corps doit porter son propre code"
            );
        }
    }

    #[test]
    fn un_statut_hors_table_retombe_sur_501() {
        // La branche `_` existe parce qu'un statut peut arriver ici sans avoir
        // de corps à lui ; elle ne doit jamais rendre un corps vide.
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
        assert_eq!(combien, 4);
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
        let reponse = composer(StatusCode::NOT_FOUND, false, &mut sortie);

        assert_eq!(reponse.status(), StatusCode::NOT_FOUND);
        assert_eq!(reponse.body(), probleme(StatusCode::NOT_FOUND));
        assert_eq!(champ(&reponse, b"content-type"), Some(PROBLEME_MEDIA));
        assert_eq!(champ(&reponse, b"cache-control"), Some(&b"no-store"[..]));
        assert_eq!(
            champ(&reponse, b"x-content-type-options"),
            Some(&b"nosniff"[..])
        );
    }

    #[test]
    fn la_longueur_annoncee_est_celle_du_corps_meme_sans_corps() {
        let attendu = probleme(StatusCode::NOT_FOUND).len().to_string();

        let mut avec = [0_u8; 256];
        let pleine = composer(StatusCode::NOT_FOUND, false, &mut avec);
        assert_eq!(champ(&pleine, b"content-length"), Some(attendu.as_bytes()));

        let mut sans = [0_u8; 256];
        let vide = composer(StatusCode::NOT_FOUND, true, &mut sans);
        assert!(vide.body().is_empty(), "un HEAD ne porte pas de corps");
        assert_eq!(
            champ(&vide, b"content-length"),
            Some(attendu.as_bytes()),
            "et il annonce quand même ce que le corps AURAIT (§8.6)"
        );
    }

    #[test]
    fn une_reponse_ordinaire_est_du_json_pas_un_probleme() {
        let mut sortie = [0_u8; 256];
        let reponse = composer(StatusCode::OK, false, &mut sortie);
        assert_eq!(champ(&reponse, b"content-type"), Some(JSON_MEDIA));
    }

    #[test]
    fn un_tampon_trop_court_sacrifie_le_corps_et_garde_la_longueur() {
        // Le corps de ce statut fait cinquante-sept octets, sa longueur deux
        // chiffres. Dans quatre octets, la longueur passe d'abord, et il reste
        // deux octets pour le corps.
        let attendu = probleme(StatusCode::NOT_FOUND).len().to_string();
        let mut sortie = [0_u8; 4];
        let reponse = composer(StatusCode::NOT_FOUND, false, &mut sortie);
        assert_eq!(reponse.status(), StatusCode::NOT_FOUND);
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
        let reponse = composer(StatusCode::NOT_FOUND, false, &mut sortie);
        assert_eq!(
            champ(&reponse, b"content-length"),
            Some(&b""[..]),
            "un seul chiffre sur deux ne s'écrit pas"
        );
        assert_eq!(reponse.body().len(), 1, "l'octet libre revient au corps");
    }

    #[test]
    fn un_head_et_un_get_annoncent_la_meme_longueur_meme_a_l_etroit() {
        // C'EST LE FUZZ QUI A TROUVÉ CE CAS. Sur deux octets, le corps du `GET`
        // mangeait la place des chiffres, et le `HEAD` — qui n'écrit pas de
        // corps — gardait un champ que le `GET` perdait.
        for taille in 0..8_usize {
            let mut avec = vec![0_u8; taille];
            let mut sans = vec![0_u8; taille];
            let par_get = composer(StatusCode::NOT_FOUND, false, &mut avec);
            let par_head = composer(StatusCode::NOT_FOUND, true, &mut sans);
            assert_eq!(
                champ(&par_get, b"content-length"),
                champ(&par_head, b"content-length"),
                "à {taille} octets, `GET` et `HEAD` divergent (§9.3.2)"
            );
        }
    }

    #[test]
    fn un_tampon_vide_ne_panique_pas_non_plus() {
        let mut sortie = [0_u8; 0];
        let reponse = composer(StatusCode::NOT_FOUND, false, &mut sortie);
        assert!(reponse.body().is_empty());
    }

    // ── servir ──────────────────────────────────────────────────────────────

    #[test]
    fn une_session_neuve_vaut_la_session_par_defaut() {
        assert_eq!(Session::new(), Session::default());
    }

    #[test]
    fn le_trait_d_ams_h3_rend_exactement_ce_que_servir_rend() {
        use ams_h3::Service as _;

        let mut par_le_trait = Session::new();
        let mut a = [0_u8; 256];
        let une = par_le_trait.serve(&tete(b"GET", b"/v1/rien-de-tel"), b"", &mut a);
        let statut_une = une.status();
        let corps_une = une.body().len();

        let mut en_direct = Session::new();
        let mut b = [0_u8; 256];
        let autre = en_direct.servir(&tete(b"GET", b"/v1/rien-de-tel"), b"", &mut b);

        assert_eq!(statut_une, autre.status());
        assert_eq!(corps_une, autre.body().len());
    }

    #[test]
    fn options_est_refuse_par_le_verbe() {
        let mut session = Session::new();
        let mut sortie = [0_u8; 256];
        let reponse = session.servir(&tete(b"OPTIONS", b"/v1/machines"), b"", &mut sortie);
        assert_eq!(reponse.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn un_corps_trop_gros_est_refuse_avant_toute_analyse() {
        let mut session = Session::new();
        let mut sortie = [0_u8; 256];
        let enorme = vec![b'x'; CORPS_OCTETS_MAX + 1];
        // La cible est ABERRANTE, et c'est exprès : le refus doit porter sur le
        // corps, donc tomber AVANT que le routage ne la regarde.
        let reponse = session.servir(
            &tete(b"POST", b"/v1/ceci-n-existe-pas"),
            &enorme,
            &mut sortie,
        );
        assert_eq!(reponse.status(), StatusCode::CONTENT_TOO_LARGE);
    }

    #[test]
    fn un_corps_juste_a_la_borne_passe() {
        let mut session = Session::new();
        let mut sortie = [0_u8; 256];
        let pile = vec![b'x'; CORPS_OCTETS_MAX];
        let reponse = session.servir(&tete(b"POST", b"/v1/ceci-n-existe-pas"), &pile, &mut sortie);
        assert_ne!(reponse.status(), StatusCode::CONTENT_TOO_LARGE);
    }

    #[test]
    fn une_cible_mal_formee_est_un_400() {
        // LA CIBLE EST BIEN FORMÉE POUR HTTP, ET MAL FORMÉE POUR NOUS, et il
        // fallait la choisir ainsi : `ams-proto-http` refuse LUI-MÊME une cible
        // sans racine, avec `MalformedPath`, et le routage ne la voit jamais.
        // La faute que `statut_de` traduit en `400` est donc SÉMANTIQUE — ici,
        // un identifiant de machine qui n'en est pas un.
        let mut session = Session::new();
        let mut sortie = [0_u8; 256];
        let reponse = session.servir(
            &tete(b"PATCH", b"/v1/machines/pas-un-identifiant"),
            b"",
            &mut sortie,
        );
        assert_eq!(reponse.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn une_ressource_qui_ne_sert_pas_ce_verbe_est_un_405() {
        // `/v1/machines` ne sert que `POST` : on y déclare une machine, on n'y
        // liste rien.
        let mut session = Session::new();
        let mut sortie = [0_u8; 256];
        let reponse = session.servir(&tete(b"GET", b"/v1/machines"), b"", &mut sortie);
        assert_eq!(reponse.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn une_cible_inconnue_est_un_404() {
        let mut session = Session::new();
        let mut sortie = [0_u8; 256];
        let reponse = session.servir(&tete(b"GET", b"/v1/rien-de-tel"), b"", &mut sortie);
        assert_eq!(reponse.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn une_ressource_qui_se_route_repond_501_faute_d_entrepot() {
        let mut session = Session::new();
        let mut sortie = [0_u8; 256];
        let reponse = session.servir(&tete(b"GET", b"/v1/expositions"), b"", &mut sortie);
        assert_eq!(
            reponse.status(),
            StatusCode::NOT_IMPLEMENTED,
            "la cible se route ; c'est l'entrepôt qui manque"
        );
    }
}
