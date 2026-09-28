//! Le localisateur détecté (`--locator auto`, décision 64, 0.35.0) : **quelle
//! adresse IPv6 de cette machine publier aux racines**, lue dans ce que le
//! noyau Linux écrit de ses adresses et de ses routes.
//!
//! # POURQUOI ICI, À L'ÉTAGE 1
//!
//! Un annuaire local derrière une box grand public reçoit son préfixe IPv6 de
//! l'opérateur, et ce préfixe peut changer. Écrit en dur, le locateur publié
//! devient faux en silence : les racines renvoient les daemons (`421`) vers
//! une adresse où personne ne répond. La détection lit deux textes —
//! `/proc/net/if_inet6` et `/proc/net/ipv6_route` —, et **le choix est une
//! fonction pure de ces deux textes**. C'est donc une grammaire, et elle vit
//! à côté de [`crate::Adresse`] et de [`crate::Locateurs`], qu'elle nourrit :
//! lue ici, elle est couverte à 100 % (C2) et fuzzée (C3) ; la lecture des
//! fichiers, elle, est à l'étage 3 (`asl_loop_tokio::localisateur`).
//!
//! # LA RÈGLE
//!
//! Une adresse est **publiable** si elle est unicast globale (`2000::/3`, ni
//! Teredo `2001::/32` ni 6to4 `2002::/16`, qui ne joignent pas une maison de
//! façon stable), et que le noyau ne la dit ni **temporaire** (extensions de
//! confidentialité, RFC 8981 : elle change d'elle-même, et ne reçoit rien),
//! ni **dépréciée** (son préfixe s'en va), ni **en essai** (DAD en cours), ni
//! **refusée** par la DAD. Lien local, ULA, bouclage : hors de `2000::/3`,
//! donc écartés par la première condition.
//!
//! Reste une adresse **stable** — EUI-64 ou « stable privacy » (RFC 7217),
//! ou posée à la main. Parmi elles, **le choix est déterministe** :
//!
//! 1. si une interface est nommée (`--locator auto:<interface>`), seules les
//!    siennes comptent ;
//! 2. sinon, celles de l'interface qui porte **la route par défaut** IPv6 de
//!    plus petite métrique — c'est par elle que la maison sort, et que les
//!    réponses reviennent — si elle en a au moins une ;
//! 3. sinon, toutes ;
//!
//! et parmi celles qui restent, **la plus petite**, dans l'ordre numérique
//! des adresses. Aucune préférence d'horloge, aucun ordre de fichier : le même
//! état du noyau rend la même adresse.

use core::net::Ipv6Addr;

/// Le drapeau `IFA_F_TEMPORARY` : une adresse temporaire (RFC 8981).
pub const IFA_F_TEMPORAIRE: u8 = 0x01;
/// Le drapeau `IFA_F_DADFAILED` : la détection de doublon a échoué.
pub const IFA_F_DAD_ECHOUEE: u8 = 0x08;
/// Le drapeau `IFA_F_DEPRECATED` : l'adresse est dépréciée.
pub const IFA_F_DEPRECIEE: u8 = 0x20;
/// Le drapeau `IFA_F_TENTATIVE` : la détection de doublon est en cours.
pub const IFA_F_EN_ESSAI: u8 = 0x40;

/// Les drapeaux qui rendent une adresse impubliable.
const DRAPEAUX_REFUSES: u8 =
    IFA_F_TEMPORAIRE | IFA_F_DAD_ECHOUEE | IFA_F_DEPRECIEE | IFA_F_EN_ESSAI;

/// `RTF_UP` : la route est active.
const RTF_UP: u32 = 0x0001;
/// `RTF_REJECT` : la route rejette (le « pas de route » que le noyau pose sur
/// `lo`) — elle ne mène nulle part.
const RTF_REJECT: u32 = 0x0200;

/// Une ligne de `/proc/net/if_inet6` : une adresse, et d'où elle vient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdresseDInterface<'a> {
    /// L'adresse.
    pub adresse: Ipv6Addr,
    /// Les drapeaux `IFA_F_*` — l'octet de poids faible, que le noyau imprime.
    pub drapeaux: u8,
    /// Le nom de l'interface.
    pub interface: &'a str,
}

/// Lit un nombre hexadécimal d'exactement `chiffres` chiffres — et rien
/// d'autre : ni signe, ni préfixe, ni espace.
fn hexadecimal(texte: &str, chiffres: usize) -> Option<u128> {
    if texte.len() != chiffres {
        return None;
    }
    // Trente-deux chiffres au plus : le décalage ne perd rien.
    texte.bytes().try_fold(0_u128, |valeur, octet| {
        Some(valeur.wrapping_shl(4) | u128::from(char::from(octet).to_digit(16)?))
    })
}

impl<'a> AdresseDInterface<'a> {
    /// Lit une ligne : `<adresse, 32 chiffres> <index> <préfixe> <portée>
    /// <drapeaux> <interface>`, séparés d'espaces. Rend `None` pour une ligne
    /// qui n'a pas cette forme — on l'ignore, on ne la devine pas.
    #[must_use]
    pub fn lire(ligne: &'a str) -> Option<Self> {
        let mut champs = ligne.split_ascii_whitespace();
        let adresse = Ipv6Addr::from_bits(hexadecimal(champs.next()?, 32)?);
        let _index = champs.next()?;
        let _prefixe = champs.next()?;
        let _portee = champs.next()?;
        // Deux chiffres : l'octet de poids faible est tout.
        let [drapeaux, ..] = hexadecimal(champs.next()?, 2)?.to_le_bytes();
        let interface = champs.next()?;
        if champs.next().is_some() {
            return None;
        }
        Some(Self {
            adresse,
            drapeaux,
            interface,
        })
    }

    /// Peut-on la publier comme localisateur ? (La règle de l'en-tête.)
    #[must_use]
    pub fn publiable(&self) -> bool {
        let bits = self.adresse.to_bits();
        let globale = bits >> 125 == 0b001;
        let teredo = bits >> 96 == 0x2001_0000;
        let six_vers_quatre = bits >> 112 == 0x2002;
        globale && !teredo && !six_vers_quatre && self.drapeaux & DRAPEAUX_REFUSES == 0
    }
}

/// L'interface de la route par défaut IPv6 de plus petite métrique, lue dans
/// `/proc/net/ipv6_route` — ou `None` s'il n'y en a pas.
///
/// Une ligne : `<destination> <longueur> <source> <longueur> <passerelle>
/// <métrique> <références> <usage> <drapeaux> <interface>`. Une route par
/// défaut a une destination nulle de longueur nulle ; on ne retient que les
/// routes actives (`RTF_UP`) qui ne rejettent pas (`RTF_REJECT`). À métrique
/// égale, le plus petit nom d'interface : le choix ne dépend pas de l'ordre
/// du fichier.
#[must_use]
pub fn interface_par_defaut(routes: &str) -> Option<&str> {
    routes
        .lines()
        .filter_map(|ligne| {
            let champs: [&str; 10] = {
                let mut lus = ligne.split_ascii_whitespace();
                let champs = core::array::from_fn(|_| lus.next().unwrap_or(""));
                if lus.next().is_some() {
                    return None;
                }
                champs
            };
            let [
                destination,
                longueur,
                _,
                _,
                _,
                metrique,
                _,
                _,
                drapeaux,
                interface,
            ] = champs;
            let defaut = hexadecimal(destination, 32)? == 0 && hexadecimal(longueur, 2)? == 0;
            let metrique = hexadecimal(metrique, 8)?;
            let drapeaux = hexadecimal(drapeaux, 8)?;
            let active =
                drapeaux & u128::from(RTF_UP) != 0 && drapeaux & u128::from(RTF_REJECT) == 0;
            (defaut && active && !interface.is_empty()).then_some((metrique, interface))
        })
        .min()
        .map(|(_, interface)| interface)
}

/// Le localisateur à publier : l'adresse que la règle de l'en-tête choisit
/// dans `adresses` (`/proc/net/if_inet6`) et `routes` (`/proc/net/ipv6_route`),
/// sur l'interface nommée s'il y en a une — ou `None` si aucune n'est
/// publiable.
#[must_use]
pub fn choisir(adresses: &str, routes: &str, interface: Option<&str>) -> Option<Ipv6Addr> {
    let publiables = || {
        adresses
            .lines()
            .filter_map(AdresseDInterface::lire)
            .filter(AdresseDInterface::publiable)
    };
    let sur = |nom: &str| {
        publiables()
            .filter(|lue| lue.interface == nom)
            .map(|lue| lue.adresse)
            .min()
    };
    match interface {
        Some(nom) => sur(nom),
        None => interface_par_defaut(routes)
            .and_then(sur)
            .or_else(|| publiables().map(|lue| lue.adresse).min()),
    }
}

#[cfg(test)]
mod essais {
    extern crate std;

    use super::*;
    use std::format;
    use std::string::String;
    use std::vec::Vec;

    /// `/proc/net/if_inet6` de speedy, relevé le 2026-09-28 : Ethernet
    /// (EUI-64) et Wi-Fi (stable privacy, deux temporaires dont une
    /// dépréciée), une ULA sur chacune, le lien local, le bouclage.
    const SPEEDY: &str = "\
2a01cb190d272f003ac986fffe479d54 02 40 00 00 enp3s0f0
2a01cb190d272f00c54a2b2c0fe233f6 03 40 00 00   wlp2s0
fd3fcb218a9700010000000000000102 02 40 00 80 enp3s0f0
fd3fcb218a9700010000000000000122 03 40 00 80   wlp2s0
00000000000000000000000000000001 01 80 10 80       lo
2a01cb190d272f0045d7276550236114 03 40 00 01   wlp2s0
fe800000000000003ac986fffe479d54 02 40 20 80 enp3s0f0
2a01cb190d272f009784e1404858878f 03 40 00 21   wlp2s0
fe800000000000005277e8d161670757 03 40 20 80   wlp2s0
";

    /// Les routes par défaut de speedy le même jour — Ethernet à 100, Wi-Fi à
    /// 600 —, et le « pas de route » que le noyau pose sur `lo`.
    const ROUTES_SPEEDY: &str = "\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000002ef2a5fffe6e7b40 00000258 00000001 00000000 00450003   wlp2s0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000002ef2a5fffe6e7b40 00000064 00000002 00000000 00450003 enp3s0f0
2a01cb190d272f000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000064 00000001 00000000 00000001 enp3s0f0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
";

    fn ip(texte: &str) -> Ipv6Addr {
        texte.parse().expect("une adresse IPv6")
    }

    #[test]
    fn speedy_publie_son_adresse_ethernet() {
        assert_eq!(
            choisir(SPEEDY, ROUTES_SPEEDY, None),
            Some(ip("2a01:cb19:d27:2f00:3ac9:86ff:fe47:9d54"))
        );
        assert_eq!(interface_par_defaut(ROUTES_SPEEDY), Some("enp3s0f0"));
        // L'interface nommée l'emporte sur la route : la stable du Wi-Fi.
        assert_eq!(
            choisir(SPEEDY, ROUTES_SPEEDY, Some("wlp2s0")),
            Some(ip("2a01:cb19:d27:2f00:c54a:2b2c:fe2:33f6"))
        );
        assert_eq!(choisir(SPEEDY, ROUTES_SPEEDY, Some("lo")), None);
        assert_eq!(choisir(SPEEDY, ROUTES_SPEEDY, Some("eth9")), None);
    }

    #[test]
    fn chaque_adresse_de_speedy_est_jugee_pour_ce_qu_elle_est() {
        let publiables: [bool; 9] = core::array::from_fn(|rang| {
            SPEEDY
                .lines()
                .nth(rang)
                .and_then(AdresseDInterface::lire)
                .is_some_and(|lue| lue.publiable())
        });
        // EUI-64, stable privacy ; ULA ×2, bouclage, temporaire, lien local,
        // temporaire dépréciée, lien local.
        assert_eq!(
            publiables,
            [true, true, false, false, false, false, false, false, false]
        );
    }

    #[test]
    fn les_drapeaux_du_noyau_ecartent_ce_qui_ne_dure_pas() {
        let globale = |drapeaux: u8| AdresseDInterface {
            adresse: ip("2001:db8::1"),
            drapeaux,
            interface: "eth0",
        };
        assert!(globale(0x00).publiable());
        // Posée à la main (`IFA_F_PERMANENT`), ou sans DAD : publiable.
        assert!(globale(0x80).publiable());
        assert!(globale(0x02).publiable());
        for refuse in [
            IFA_F_TEMPORAIRE,
            IFA_F_DAD_ECHOUEE,
            IFA_F_DEPRECIEE,
            IFA_F_EN_ESSAI,
            IFA_F_DEPRECIEE | 0x80,
        ] {
            assert!(!globale(refuse).publiable(), "{refuse:#04x}");
        }
        // Hors de `2000::/3`, ou Teredo, ou 6to4 : jamais.
        for adresse in [
            "fe80::1",
            "fd00::1",
            "::1",
            "::ffff:192.0.2.1",
            "ff02::1",
            "4000::1",
            "2001:0:4136:e378::1",
            "2002:c000:201::1",
        ] {
            let lue = AdresseDInterface {
                adresse: ip(adresse),
                ..globale(0)
            };
            assert!(!lue.publiable(), "{adresse}");
        }
        assert!(
            AdresseDInterface {
                adresse: ip("3fff:ffff::1"),
                ..globale(0)
            }
            .publiable()
        );
    }

    #[test]
    fn une_ligne_de_travers_est_ignoree_et_non_devinee() {
        for ligne in [
            "",
            "2001:db8::1 02 40 00 00 eth0",
            "+001db8000000000000000000000001 02 40 00 00 eth0",
            "20010db8000000000000000000000001 02 40 00 0g eth0",
            "20010db8000000000000000000000001 02 40 00 100 eth0",
            "20010db8000000000000000000000001 02 40 00 00",
            "20010db8000000000000000000000001 02 40 00",
            "20010db8000000000000000000000001 02 40",
            "20010db8000000000000000000000001 02",
            "20010db8000000000000000000000001",
            "20010db8000000000000000000000001 02 40 00 00 eth0 de trop",
        ] {
            assert_eq!(AdresseDInterface::lire(ligne), None, "{ligne}");
        }
        assert_eq!(
            AdresseDInterface::lire("20010db8000000000000000000000001 02 40 00 80 eth0"),
            Some(AdresseDInterface {
                adresse: ip("2001:db8::1"),
                drapeaux: 0x80,
                interface: "eth0",
            })
        );
        assert_eq!(choisir("n'importe quoi\n\n", "", None), None);
    }

    #[test]
    fn plusieurs_globales_la_plus_petite_et_pas_la_premiere() {
        let adresses = "\
20010db8000000000000000000000009 02 40 00 00 eth0
20010db8000000000000000000000003 02 40 00 00 eth0
20010db8000000000000000000000001 02 40 00 01 eth0
20010db8000000000000000000000002 03 40 00 00 eth1
";
        // Aucune route : toutes comptent, la plus petite publiable gagne — la
        // temporaire `::1` est écartée.
        assert_eq!(choisir(adresses, "", None), Some(ip("2001:db8::2")));
        // La route par défaut sort par eth0 : ses adresses d'abord.
        let par_eth0 = "\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth1
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000064 00000001 00000000 00000003 eth0
";
        assert_eq!(choisir(adresses, par_eth0, None), Some(ip("2001:db8::3")));
        // Le même état, lignes mêlées : le même choix.
        let mut lignes: Vec<&str> = adresses.lines().collect();
        lignes.reverse();
        let melees: String = lignes.iter().map(|ligne| format!("{ligne}\n")).collect();
        let melees = melees.as_str();
        assert_eq!(choisir(melees, par_eth0, None), Some(ip("2001:db8::3")));
        // La route sort par une interface sans adresse publiable : toutes
        // comptent de nouveau.
        let par_ppp = "\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000001 00000001 00000000 00000001 ppp0
";
        assert_eq!(choisir(adresses, par_ppp, None), Some(ip("2001:db8::2")));
    }

    #[test]
    fn la_route_par_defaut_est_active_ne_rejette_pas_et_a_la_plus_petite_metrique() {
        let nulle = "00000000000000000000000000000000";
        let une = |destination: &str,
                   longueur: &str,
                   metrique: &str,
                   drapeaux: &str,
                   interface: &str| {
            let ligne = format!(
                "{destination} {longueur} {nulle} 00 {nulle} {metrique} 00000001 00000000 {drapeaux} {interface}"
            );
            interface_par_defaut(&ligne).is_some()
        };
        assert!(une(nulle, "00", "00000064", "00000003", "eth0"));
        // Inactive, qui rejette, pas une route par défaut : non.
        assert!(!une(nulle, "00", "00000064", "00000002", "eth0"));
        assert!(!une(nulle, "00", "00000064", "00000201", "eth0"));
        assert!(!une(
            "20010db8000000000000000000000000",
            "00",
            "00000064",
            "00000001",
            "eth0"
        ));
        assert!(!une(nulle, "40", "00000064", "00000001", "eth0"));
        // De travers : non.
        assert!(!une(nulle, "0", "00000064", "00000001", "eth0"));
        assert!(!une("0", "00", "00000064", "00000001", "eth0"));
        assert!(!une(nulle, "00", "64", "00000001", "eth0"));
        assert!(!une(nulle, "00", "00000064", "1", "eth0"));
        assert!(!une(nulle, "00", "00000064", "00000001", ""));
        assert!(!une(nulle, "00", "00000064", "00000001", "eth0 de-trop"));
        // À métrique égale, le plus petit nom.
        let egales = "\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000064 00000001 00000000 00000001 eth1
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000064 00000001 00000000 00000001 eth0
";
        assert_eq!(interface_par_defaut(egales), Some("eth0"));
        assert_eq!(interface_par_defaut(""), None);
    }
}
