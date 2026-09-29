//! L'identifiant DÉRIVÉ d'un service (`docs/annuaires.md` §2 ter, piste A1 ;
//! `docs/replication.md` décisions 66, 67 et 72 ; 0.37.0).
//!
//! # LA FORME, ARRÊTÉE ICI — ET FIGÉE PAR LES VECTEURS DES ESSAIS
//!
//! ```text
//! s-… = SHA-256( "asl/service/1" ‖ m (16 octets) ‖ nom (UTF-8) )[0..16]
//! ```
//!
//! - **`"asl/service/1"`** : les treize octets ASCII de la chaîne, sans
//!   terminateur — la chaîne de séparation que la spécification écrit.
//! - **`m`** : les SEIZE OCTETS de l'identifiant de la machine
//!   ([`Identifiant::octets`]), jamais son texte. Le texte n'est pas unique
//!   (Crockford rattrape `I`, `L`, `O` : `asl-id`), les octets le sont.
//! - **`nom`** : les octets UTF-8 du nom tel qu'il est rangé
//!   ([`crate::NomRange::octets`]), sans longueur ni terminateur.
//! - **Les seize premiers octets** du condensat deviennent le corps d'un
//!   identifiant de genre `s`.
//!
//! **Pourquoi ni longueur ni séparateur entre `m` et le nom** : la chaîne de
//! séparation est de longueur fixe, `m` aussi ; le nom est tout ce qui suit.
//! Deux couples `(machine, nom)` différents donnent donc deux messages
//! différents, octet pour octet — il n'y a aucune façon de lire un même
//! message comme deux couples. Préfixer une longueur n'ajouterait rien.
//!
//! # UNE FONCTION, DEUX CHAÎNES — LA SECONDE EST CELLE D'`asl-directory`
//!
//! La décision 73 dérive de même le `s-…` du service `asl-directory` d'un
//! annuaire local (0.38.0) :
//!
//! ```text
//! s-… = SHA-256( "asl/annuaire/1" ‖ n (16 octets) ‖ "asl-directory" )[0..16]
//! ```
//!
//! — les quatorze octets ASCII de [`SEPARATION_ANNUAIRE`], les seize octets
//! du `n-…` du TITULAIRE (celui qui nomme l'annuaire logique, jamais celui du
//! second membre), puis les treize octets du nom. [`deriver`] est la forme
//! commune — une chaîne, seize octets d'identifiant, un nom. **Les deux
//! chaînes ne se rencontrent jamais** : elles diffèrent dès leur cinquième
//! octet (`s` et `a`), donc aucun message de l'une n'est un message de
//! l'autre, même si seize octets d'un `n-…` et d'un `m-…` coïncidaient.
//! Vecteur : `n-7MSV5RPCXBZH25PQM4ZPE5X87P` → `s-294B4BA9XHXFZ5DQ8Q7T35M7PY`.
//!
//! # CE QUE LA DÉRIVATION COÛTE, ET QUI L'A ACCEPTÉ
//!
//! Un `s-…` n'est plus imprévisible : qui connaît `m-…` peut essayer des noms
//! jusqu'à retomber sur un `s-…` qu'il a vu (décision 67, acceptée). Aucun
//! verbe ne s'ouvre pour autant — la résolution se fait par `(machine, nom)`,
//! et le `404` de C9 ne distingue toujours rien.

use asl_id::{Genre, Identifiant};

use crate::poser;

/// La chaîne de séparation du `s-…` d'un service de machine (décision 66).
pub const SEPARATION_SERVICE: &[u8] = b"asl/service/1";

/// La chaîne de séparation du `s-…` de l'`asl-directory` d'un annuaire
/// local (décision 73).
pub const SEPARATION_ANNUAIRE: &[u8] = b"asl/annuaire/1";

/// Le nom sous lequel ce `s-…` se dérive — `asl_proto::NOM_ASL_DIRECTORY`,
/// que cette crate ne tire pas ; `asl-session`, qui connaît les deux, tient
/// leur égalité à la compilation.
pub const NOM_ASL_DIRECTORY: &[u8] = b"asl-directory";

/// L'identifiant de service dérivé de cette chaîne, de ce titulaire et de ce
/// nom : les seize premiers octets de `SHA-256(separation ‖ titulaire (16
/// octets) ‖ nom)`.
///
/// **La forme commune** — voir l'en-tête. Un appelant ne s'en sert qu'à
/// travers une chaîne nommée ([`service_derive`], [`asl_directory_derive`]) :
/// c'est la chaîne qui dit ce qu'on dérive.
#[must_use]
pub fn deriver(separation: &[u8], titulaire: Identifiant, nom: &[u8]) -> Identifiant {
    use sha2::Digest as _;
    let mut condensat = sha2::Sha256::new();
    condensat.update(separation);
    condensat.update(titulaire.octets());
    condensat.update(nom);
    let entier = condensat.finalize();
    let mut seize = [0_u8; 16];
    poser(&mut seize, &entier);
    Identifiant::depuis_entropie(Genre::Service, seize)
}

/// Le `s-…` du service `nom` de cette machine (décision 66, A1).
///
/// **Le même partout, sans rien échanger** : aux deux racines, dans chaque
/// membre d'une paire, chez l'hébergeur d'hier et celui de demain (I1, I2,
/// I3). Chaque entrepôt le calcule à la déclaration, à l'application d'une
/// opération venue d'un pair, et à la migration de 0.37.0.
#[must_use]
pub fn service_derive(machine: Identifiant, nom: &[u8]) -> Identifiant {
    deriver(SEPARATION_SERVICE, machine, nom)
}

/// Le `s-…` de l'`asl-directory` de l'annuaire local que ce `n-…` titulaire
/// nomme (décision 73).
///
/// **Calculé, jamais rangé** : les deux racines le rendent sans se parler,
/// et le service n'existe qu'autant que l'inscription acceptée (décision 74).
#[must_use]
pub fn asl_directory_derive(titulaire: Identifiant) -> Identifiant {
    deriver(SEPARATION_ANNUAIRE, titulaire, NOM_ASL_DIRECTORY)
}

#[cfg(test)]
mod tests {
    //! **Les vecteurs FIGENT la forme** : ils ont été calculés hors de ce code
    //! (Python, `hashlib.sha256`, le Crockford relu à la main) et ne doivent
    //! jamais changer. Un vecteur qui casse est un `s-…` qui change partout
    //! où il a été vu — une migration, pas une retouche.

    use asl_id::{Genre, Identifiant};

    use super::{
        NOM_ASL_DIRECTORY, SEPARATION_ANNUAIRE, SEPARATION_SERVICE, asl_directory_derive, deriver,
        service_derive,
    };

    /// Relit un identifiant écrit, qu'on sait bien formé.
    fn lu(texte: &str) -> Identifiant {
        Identifiant::analyser(texte).expect("bien formé")
    }

    #[test]
    fn les_vecteurs_figes() {
        // Le service du constat du 2026-09-28 (`docs/annuaires.md` §2 ter).
        assert_eq!(
            service_derive(lu("m-32Q2JXER1HTVRZQ956T7V3GE0S"), b"essai-federation"),
            lu("s-7ANMGMZPJ3EGA41WA129KAJTWE")
        );
        let zero = Identifiant::depuis_entropie(Genre::Machine, [0; 16]);
        assert_eq!(
            service_derive(zero, b""),
            lu("s-76GYQ9134SJAF9FY4F30GVDM2W")
        );
        assert_eq!(
            service_derive(zero, b"ssh"),
            lu("s-0FKTEVZNF2DMF0TB3TG0CZXZSS")
        );
        let suite = Identifiant::depuis_entropie(
            Genre::Machine,
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        );
        assert_eq!(
            service_derive(suite, b"depot"),
            lu("s-5028GFCBHS78SH0QQFCB2M0XKJ")
        );
    }

    #[test]
    fn la_chaine_de_separation_est_celle_de_la_specification() {
        assert_eq!(SEPARATION_SERVICE, b"asl/service/1");
    }

    #[test]
    fn un_service_depend_de_sa_machine_et_de_son_nom_et_de_rien_d_autre() {
        let une = Identifiant::depuis_entropie(Genre::Machine, [1; 16]);
        let autre = Identifiant::depuis_entropie(Genre::Machine, [2; 16]);
        let derive = service_derive(une, b"imap");
        assert_eq!(derive.genre(), Genre::Service);
        assert_eq!(service_derive(une, b"imap"), derive);
        assert_ne!(service_derive(autre, b"imap"), derive);
        assert_ne!(service_derive(une, b"imaps"), derive);
        // Seuls les SEIZE OCTETS de la machine comptent, pas son genre : la
        // chaîne de séparation dit ce qu'on dérive.
        let memes_octets = Identifiant::depuis_entropie(Genre::Annuaire, [1; 16]);
        assert_eq!(deriver(SEPARATION_SERVICE, memes_octets, b"imap"), derive);
        // Une autre chaîne, un autre identifiant — celle de l'`asl-directory`
        // (décision 73) ne rencontre pas celle-ci.
        assert_ne!(deriver(b"asl/annuaire/1", une, b"imap"), derive);
    }

    #[test]
    fn les_vecteurs_figes_de_l_asl_directory() {
        // **La paire de production** (speedy, titulaire ; helium, second) :
        // c'est ce que `GET /v1/ou/n-7MSV…/asl-directory` rend en `service`.
        assert_eq!(
            asl_directory_derive(lu("n-7MSV5RPCXBZH25PQM4ZPE5X87P")),
            lu("s-294B4BA9XHXFZ5DQ8Q7T35M7PY")
        );
        // Le second a son propre `n-…`, qui ne nomme pas l'annuaire : son
        // dérivé n'est celui d'aucun `asl-directory` servi.
        assert_eq!(
            asl_directory_derive(lu("n-4EQRD1VWYQQB1Y9C3T49Z8F8Z9")),
            lu("s-5GQYJW6MK7JMV67KQDQYSCT1F5")
        );
        let zero = Identifiant::depuis_entropie(Genre::Annuaire, [0; 16]);
        assert_eq!(
            asl_directory_derive(zero),
            lu("s-7K8JYNPMFK8J970VEZJK6XC72W")
        );
        let suite = Identifiant::depuis_entropie(
            Genre::Annuaire,
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        );
        assert_eq!(
            asl_directory_derive(suite),
            lu("s-4HVV10FRS8PH73S5XBKJ90VTEN")
        );
    }

    #[test]
    fn la_separation_de_l_asl_directory_n_est_pas_celle_des_services() {
        assert_eq!(SEPARATION_ANNUAIRE, b"asl/annuaire/1");
        assert_eq!(NOM_ASL_DIRECTORY, b"asl-directory");
        // Elles diffèrent dès le cinquième octet.
        assert_eq!(SEPARATION_ANNUAIRE[..4], SEPARATION_SERVICE[..4]);
        assert_ne!(SEPARATION_ANNUAIRE[4], SEPARATION_SERVICE[4]);
        // Les mêmes seize octets et le même nom, sous l'autre chaîne : un
        // autre identifiant — vecteur calculé hors du code, lui aussi.
        let speedy = lu("n-7MSV5RPCXBZH25PQM4ZPE5X87P");
        assert_eq!(
            service_derive(speedy, NOM_ASL_DIRECTORY),
            lu("s-3DEC09PVS1NSG89SEF2KY3XMRK")
        );
        assert_ne!(
            service_derive(speedy, NOM_ASL_DIRECTORY),
            asl_directory_derive(speedy)
        );
        // Seuls les seize octets comptent, pas le genre : une machine qui
        // aurait les octets d'un `n-…` et annoncerait ce nom — ce que la
        // réservation refuse de toute façon — ne rencontrerait pas le service
        // de l'annuaire.
        let machine = Identifiant::depuis_entropie(Genre::Machine, *speedy.octets());
        assert_ne!(
            service_derive(machine, NOM_ASL_DIRECTORY),
            asl_directory_derive(speedy)
        );
        assert_eq!(asl_directory_derive(speedy).genre(), Genre::Service);
    }
}
