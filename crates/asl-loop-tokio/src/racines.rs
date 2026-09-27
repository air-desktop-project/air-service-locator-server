//! Les racines embarquées — l'ancre (`annuaires.md` §2, décision 56).
//!
//! # CE QUI EST ÉPINGLÉ, C'EST LA CLÉ
//!
//! Pour chaque racine : son identifiant `n-…`, **sa clé d'identité**, et des
//! locateurs — des adresses d'abord (C20 : aucun résolveur requis), des noms
//! ensuite, comme commodités. Un locateur ne fait rien croire : il dit où
//! joindre ; la clé dit qui l'on doit trouver au bout.
//!
//! # POURQUOI DANS LE BINAIRE
//!
//! C'est ce qu'un annuaire neuf a pour tout bagage (§2) : il n'a encore parlé à
//! personne. Les clés ont été relevées sur les bancs le 2026-09-27
//! (`/etc/asl-server/identite.key.pub`) ; un essai tient que chacune se déduit
//! bien en l'identifiant écrit à côté — une clé recopiée de travers ne
//! passerait pas la barrière.

use asl_cle::{CLE_PUBLIQUE_OCTETS, ClePublique};

/// Une racine, telle que le logiciel la connaît avant tout contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RacineEmbarquee {
    /// Son identifiant, qui se déduit de la clé.
    pub identifiant: &'static str,
    /// Sa clé d'identité Ed25519.
    pub cle: [u8; CLE_PUBLIQUE_OCTETS],
    /// Où la joindre : adresses d'abord, noms ensuite.
    pub locateurs: &'static [&'static str],
}

/// Les deux racines d'air-desktop-project.
pub const RACINES: [RacineEmbarquee; 2] = [
    RacineEmbarquee {
        identifiant: "n-0PWT8HZD80QMSPPDZ5CQXXYHQC",
        cle: [
            0x42, 0x9c, 0x70, 0xc6, 0x36, 0x51, 0xb4, 0xbb, 0x14, 0x3c, 0xac, 0xa6, 0x79, 0x60,
            0xff, 0x70, 0xee, 0xde, 0x5d, 0x8e, 0x41, 0x8a, 0x9d, 0x0b, 0xc2, 0xbe, 0x12, 0xe1,
            0x9a, 0xc6, 0xf5, 0xfd,
        ],
        locateurs: &[
            "[2001:41d0:20a:900::1dd4]:6630",
            "178.32.16.250:6630",
            "nitrogen.air-desktop.org:6630",
        ],
    },
    RacineEmbarquee {
        identifiant: "n-3K3P6H252W8K9370QG1YYTWBWB",
        cle: [
            0x75, 0xa0, 0x31, 0xae, 0x9f, 0xb9, 0xb6, 0x49, 0x36, 0x76, 0x29, 0x83, 0x72, 0x12,
            0x13, 0x22, 0xcc, 0x04, 0x37, 0x9e, 0x3b, 0x70, 0xd8, 0xd5, 0xf0, 0x11, 0xac, 0x61,
            0xf6, 0x8a, 0x8a, 0x8d,
        ],
        locateurs: &[
            "[2001:41d0:20a:900::1d32]:6630",
            "178.32.16.249:6630",
            "argon.air-desktop.org:6630",
        ],
    },
];

/// Le locateur commun aux deux racines — un nom, donc une commodité.
pub const ALIAS_DES_RACINES: &str = "asl-root.air-desktop.org:6630";

/// Les identités qu'on doit trouver au bout de ce locateur : celle d'une
/// racine embarquée, les deux pour l'alias commun, aucune sinon.
///
/// **La comparaison est textuelle** : un locateur est ce que l'exploitant a
/// écrit, et `--federation [2001:41d0:20a:900::1dd4]:6630` ou
/// `--federation nitrogen.air-desktop.org:6630` désignent la même racine parce
/// que la liste le dit — pas parce qu'un résolveur l'aurait dit.
#[must_use]
pub fn identites_du_locateur(locateur: &str) -> Vec<ClePublique> {
    let toutes = locateur.eq_ignore_ascii_case(ALIAS_DES_RACINES);
    RACINES
        .iter()
        .filter(|racine| {
            toutes
                || racine
                    .locateurs
                    .iter()
                    .any(|connu| connu.eq_ignore_ascii_case(locateur))
        })
        .filter_map(|racine| ClePublique::depuis_octets(racine.cle).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{ALIAS_DES_RACINES, RACINES, identites_du_locateur};

    #[test]
    fn chaque_cle_embarquee_se_deduit_en_son_identifiant() {
        // Une clé recopiée de travers ne passerait pas : l'identifiant écrit à
        // côté est celui qu'on a relevé sur le banc.
        for racine in RACINES {
            let cle = asl_cle::ClePublique::depuis_octets(racine.cle).expect("un point");
            assert_eq!(
                asl_cle::identifiant_de_racine(&cle).texte().as_str(),
                racine.identifiant
            );
            // Ses locateurs la désignent, elle seule.
            for locateur in racine.locateurs {
                assert_eq!(identites_du_locateur(locateur), vec![cle], "{locateur}");
            }
        }
    }

    #[test]
    fn l_alias_designe_les_deux_et_un_inconnu_personne() {
        assert_eq!(identites_du_locateur(ALIAS_DES_RACINES).len(), 2);
        assert_eq!(
            identites_du_locateur("ASL-ROOT.air-desktop.org:6630").len(),
            2
        );
        assert!(identites_du_locateur("127.0.0.1:6630").is_empty());
    }
}
