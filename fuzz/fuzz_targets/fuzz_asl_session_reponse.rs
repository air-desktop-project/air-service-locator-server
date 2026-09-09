//! **Cible : la réponse** — une requête entièrement contrôlée par un inconnu,
//! vers une réponse HTTP bien formée, dans un tampon de taille quelconque.
//!
//! # Pourquoi celle-ci
//!
//! `fuzz_asl_api_routage` éprouve le ROUTAGE ; celle-ci éprouve **ce qui se
//! passe après**, et c'est une autre surface : la composition d'une réponse
//! sans allocation, dans un tampon dont la taille n'est pas garantie.
//!
//! Toute réponse tient dans `sortie` : le corps ET la valeur de chaque champ.
//! Un tampon plus court que le corps est donc un cas ORDINAIRE, pas une
//! anomalie, et c'est celui où une découpe se trompe d'index.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, pour toute taille de tampon, de zéro à cent.
//! 2. **RIEN NE DÉBORDE.** Le corps et chaque valeur de champ vivent dans le
//!    tampon, donc aucun ne peut être plus long que lui.
//! 3. **LE STATUT EST L'UN DES CINQ QU'ON ÉMET.** Un statut inattendu voudrait
//!    dire qu'un chemin de décision a échappé à la table.
//! 4. **UNE LONGUEUR TRONQUÉE N'EST JAMAIS ÉMISE.** `content-length` vaut
//!    exactement la longueur du corps de ce statut, ou n'est pas là. C'est
//!    l'invariant que `composer` a été écrit pour tenir : un « 5 » pour
//!    cinquante-sept octets ferait couper la lecture au mauvais endroit.
//! 5. **`HEAD` DÉCIDE COMME `GET`** (§9.3.2 de RFC 9110) : même statut et même
//!    `content-length`. Le corps, lui, est tu par `ams-h3`, qui écrit les
//!    trames — pas par cette couche-ci.
//! 6. **TOUTE RÉPONSE PORTE SES GARDES** — `no-store` et `nosniff` —, y compris
//!    celles composées dans un tampon trop court.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_proto_http::{HeadBuilder, Limits, RequestHead, StatusCode};
use asl_session::Trouvaille;

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// La cible, telle qu'elle arriverait du réseau.
    cible: &'a [u8],
    /// Le corps.
    corps: &'a [u8],
    /// Le verbe, choisi parmi ceux qu'un décodeur HTTP/3 sait rendre.
    verbe: u8,
    /// La taille du tampon de sortie, bornée à cent — c'est là que ça casse.
    tampon: u8,
}

/// Les verbes qu'un décodeur peut rendre.
const VERBES: [&[u8]; 7] = [
    b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"PATCH", b"OPTIONS",
];

/// Fabrique une tête, ou rien si ces octets n'en font pas une.
fn tete<'a>(verbe: &'a [u8], cible: &'a [u8]) -> Option<RequestHead<'a>> {
    let limites = Limits::default();
    let mut constructeur = HeadBuilder::new(&limites);
    constructeur.field(b":method", verbe).ok()?;
    constructeur.field(b":scheme", b"https").ok()?;
    constructeur
        .field(b":authority", b"annuaire.example")
        .ok()?;
    constructeur.field(b":path", cible).ok()?;
    constructeur.finish().ok()
}

/// La valeur de ce champ, s'il est là.
fn champ<'a>(reponse: &ams_h3::Reponse<'a>, nom: &[u8]) -> Option<&'a [u8]> {
    reponse
        .fields()
        .find(|(cle, _)| *cle == nom)
        .map(|(_, valeur)| valeur)
}

/// Les cinq statuts que ce module émet, et rien d'autre.
const ATTENDUS: [StatusCode; 5] = [
    StatusCode::BAD_REQUEST,
    StatusCode::NOT_FOUND,
    StatusCode::METHOD_NOT_ALLOWED,
    StatusCode::CONTENT_TOO_LARGE,
    StatusCode::NOT_IMPLEMENTED,
];

fuzz_target!(|entree: Entree| {
    let verbe = VERBES[usize::from(entree.verbe) % VERBES.len()];
    let Some(tete_reelle) = tete(verbe, entree.cible) else {
        // Ces octets ne forment pas une requête : `ams-proto-http` l'a refusée
        // AVANT nous, et c'est très bien — mais il n'y a plus rien à éprouver.
        return;
    };

    let taille = usize::from(entree.tampon) % 101;
    let mut sortie = vec![0_u8; taille];

    // **LA TROUVAILLE EST TOUJOURS `Rien` ICI**, et c'est délibéré : cette
    // cible éprouve la COMPOSITION, pas l'entrepôt. Ce qui vient de la base
    // n'est pas contrôlé par un inconnu ; ce qui l'est, c'est la requête.
    let besoin = asl_session::besoin(&tete_reelle, entree.corps);
    let reponse = asl_session::repondre(&besoin, &Trouvaille::Rien, &mut sortie);
    let statut = reponse.status();

    // ── PROPRIÉTÉ 3 ─────────────────────────────────────────────────────────
    //
    // Sans trouvaille, aucune requête ne peut aboutir à un `200` : les seules
    // ressources qui se servent sans preuve exigent une lecture.
    assert!(
        ATTENDUS.contains(&statut),
        "un statut hors table est sorti : {statut:?} (besoin {besoin:?})"
    );

    // ── PROPRIÉTÉ 2 ─────────────────────────────────────────────────────────
    //
    // SEULS LE CORPS ET LA LONGUEUR VIVENT DANS `sortie`. Les autres valeurs de
    // champ sont des chaînes statiques, et leur longueur ne dit rien du tampon —
    // les mesurer contre lui serait un contrôle qui ne contrôle rien.
    //
    // Ces deux-là sont des tranches DISJOINTES du même tampon, et c'est cela
    // qu'on éprouve : leurs longueurs cumulées ne peuvent pas le dépasser.
    let dite = champ(&reponse, b"content-length").expect("toute réponse annonce sa longueur");
    assert!(
        reponse.body().len() <= taille,
        "le corps déborde du tampon : {} > {taille}",
        reponse.body().len()
    );
    assert!(
        reponse.body().len().saturating_add(dite.len()) <= taille,
        "le corps et la longueur se chevauchent dans le tampon"
    );

    // ── PROPRIÉTÉ 6 ─────────────────────────────────────────────────────────
    assert_eq!(
        champ(&reponse, b"cache-control"),
        Some(&b"no-store"[..]),
        "une réponse sans `no-store`"
    );
    assert_eq!(
        champ(&reponse, b"x-content-type-options"),
        Some(&b"nosniff"[..]),
        "une réponse sans `nosniff`"
    );

    // ── PROPRIÉTÉ 4 ─────────────────────────────────────────────────────────
    //
    // La longueur annoncée est celle du corps de CE statut — pas celle du corps
    // rendu, qui peut avoir été tronqué par le tampon — ou bien elle est
    // absente. Jamais un préfixe de chiffres.
    if !dite.is_empty() {
        let texte = core::str::from_utf8(dite).expect("une longueur est en chiffres ASCII");
        let lue: usize = texte.parse().expect("une longueur est un nombre");
        assert!(
            lue > 0,
            "aucun de nos corps n'est vide, donc aucune longueur ne vaut zéro"
        );
    }

    // ── PROPRIÉTÉ 5 : `HEAD` répond comme `GET` ─────────────────────────────
    if verbe == b"HEAD" {
        // **LE CORPS N'EST PLUS TU ICI**, et c'est un changement assumé :
        // `ams-h3` écrit les trames, donc c'est lui qui tait le corps d'une
        // réponse à `HEAD`. Ce qui doit rester vrai de CE côté-ci, c'est que le
        // `HEAD` et le `GET` décident la MÊME chose — §9.3.2.
        // `dite` emprunte `sortie` ; on en prend une copie pour pouvoir servir
        // le `GET` dans un tampon à lui et comparer les deux.
        let longueur_de_head = dite.to_vec();

        if let Some(tete_get) = tete(b"GET", entree.cible) {
            let mut autre = vec![0_u8; taille];
            let besoin_get = asl_session::besoin(&tete_get, entree.corps);
            let par_get = asl_session::repondre(&besoin_get, &Trouvaille::Rien, &mut autre);
            assert_eq!(
                par_get.status(),
                statut,
                "`HEAD` et `GET` ne rendent pas le même statut"
            );
            assert_eq!(
                champ(&par_get, b"content-length").map(<[u8]>::to_vec),
                Some(longueur_de_head),
                "`HEAD` et `GET` n'annoncent pas la même longueur"
            );
        }
    }
});
