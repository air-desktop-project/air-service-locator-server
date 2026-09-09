//! **Cible : la vie d'une session** — une suite d'événements quelconque, dans
//! un ordre quelconque, avec une horloge quelconque.
//!
//! # Ce qu'elle éprouve, et qu'aucune autre cible n'éprouve
//!
//! Les six autres cibles éprouvent des CODECS : un message entre, une valeur
//! sort. Celle-ci éprouve une MACHINE À ÉTATS — donc des invariants qui doivent
//! tenir après n'importe quelle suite d'événements, pas seulement après un.
//!
//! **C'est ce que le découpage en étages achète.** Une session ne fait aucune
//! entrée-sortie : on peut donc lui envoyer un million de suites d'événements en
//! dix secondes, ce qui serait impossible si chaque expiration coûtait
//! quarante-cinq secondes d'attente.
//!
//! # Les invariants, vérifiés APRÈS CHAQUE ÉVÉNEMENT
//!
//! 1. **Rien ne panique.**
//! 2. **La réponse et la poussée restent toujours CONSTRUCTIBLES.** Elles
//!    passent par les validations d'`asl-proto` : si l'une échouait, c'est que
//!    la session aurait fabriqué un état que le protocole refuse.
//! 3. **C6 : aucun point UDP n'est jamais dit mesuré**, quelle que soit la suite
//!    d'événements.
//! 4. **UNE SESSION CLOSE RESTE CLOSE.** Aucun événement ne la ressuscite.
//! 5. **L'EXPIRATION EST MONOTONE** : une session expirée à un instant l'est
//!    encore plus tard. Sans cela, un service clignoterait — `parti`, puis
//!    `annoncé`, puis `parti` — alors qu'on a déjà dit à ses clients qu'il était
//!    parti.
//!
//!    **CETTE PROPRIÉTÉ A ÉTÉ VIOLÉE À LA PREMIÈRE CAMPAGNE.** Un keepalive
//!    tardif ressuscitait la session. Le verrou est dans `Session::avancer`, et
//!    cet essai est ce qui l'y a mis.
//! 6. **`etat` ne dit `Joignable` que si un verdict de mesure existe** — et il
//!    porte alors sa date.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use asl_annuaire::{CANDIDATS_MAX, Etat, Faute, Instant, MotifDeDepart, Session};
use asl_id::{Genre, Identifiant};
use asl_proto::{
    Annonce, Bail, Candidat, Horodatage, NomService, Origine, POINTS_MAX, PointEcoute, Port,
    Protocole, Verdict, VuDepuis,
};

/// Un point d'écoute, tel que le fuzzer sait le fabriquer.
#[derive(Arbitrary, Debug)]
struct PointBrut {
    protocole: u8,
    port: u16,
}

/// Une adresse.
#[derive(Arbitrary, Debug)]
enum AdresseBrute {
    V4([u8; 4]),
    V6([u8; 16]),
}

/// Un événement de la vie d'une session.
#[derive(Arbitrary, Debug)]
enum Evenement {
    /// Le daemon donne signe de vie.
    Keepalive { avance: u16 },
    /// Le daemon réannonce.
    Reannonce {
        avance: u16,
        points: Vec<PointBrut>,
        adresses: Vec<AdresseBrute>,
        vu: AdresseBrute,
    },
    /// Une sonde rend son verdict.
    Sonde {
        avance: u16,
        rang: u8,
        aboutie: bool,
        candidat: AdresseBrute,
    },
    /// Le daemon ferme.
    Fermeture { volontaire: bool },
    /// Le temps passe, sans que rien n'arrive.
    Attente { avance: u16 },
}

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree {
    keepalive: u16,
    inactivite: u16,
    points: Vec<PointBrut>,
    adresses: Vec<AdresseBrute>,
    vu: AdresseBrute,
    evenements: Vec<Evenement>,
}

fn adresse(brute: &AdresseBrute) -> IpAddr {
    match brute {
        AdresseBrute::V4(octets) => IpAddr::V4(Ipv4Addr::from(*octets)),
        AdresseBrute::V6(octets) => IpAddr::V6(Ipv6Addr::from(*octets)),
    }
}

fn points_de(bruts: &[PointBrut]) -> Vec<PointEcoute> {
    bruts
        .iter()
        .filter_map(|brut| {
            let protocole = if brut.protocole % 2 == 0 {
                Protocole::Tcp
            } else {
                Protocole::Udp
            };
            Port::depuis_u16(brut.port)
                .ok()
                .map(|port| PointEcoute::nouveau(protocole, port))
        })
        .take(POINTS_MAX)
        .collect()
}

/// Retire les doublons : l'annonce les refuse, et ce n'est pas ce qu'on éprouve
/// ici.
fn sans_doublons(points: Vec<PointEcoute>) -> Vec<PointEcoute> {
    let mut gardes: Vec<PointEcoute> = Vec::new();
    for point in points {
        if !gardes.contains(&point) {
            gardes.push(point);
        }
    }
    gardes
}

/// Les invariants qui doivent tenir après CHAQUE événement.
fn verifier(session: &Session, maintenant: Instant, deja_close: bool) {
    // PROPRIÉTÉ 2 : la réponse et la poussée restent constructibles.
    let reponse = session
        .reponse()
        .expect("une session valide rend toujours une réponse valide");
    let poussee = session
        .poussee()
        .expect("une session valide rend toujours une poussée valide");
    assert_eq!(poussee.joignabilite, reponse.joignabilite);

    // PROPRIÉTÉ 3 : C6.
    for entree in reponse.joignabilite {
        let mesure = matches!(
            entree.verdict,
            Verdict::Joignable { .. } | Verdict::Injoignable { .. }
        );
        assert!(
            !mesure || entree.point.protocole == Protocole::Tcp,
            "un point UDP a été dit mesuré"
        );
    }

    let etat = session.etat(maintenant);

    // PROPRIÉTÉ 4 : une session close reste close.
    if deja_close {
        assert!(
            matches!(etat, Etat::Parti { .. }),
            "une session close est revenue à {etat:?}"
        );
    }

    // PROPRIÉTÉ 6 : `Joignable` suppose un verdict de mesure qui l'atteste.
    if let Etat::Joignable { candidat, a } = etat {
        let atteste = reponse.joignabilite.iter().any(|entree| {
            matches!(entree.verdict, Verdict::Joignable { candidat: c, a: quand }
                if c == candidat && quand == a)
        });
        assert!(atteste, "`Joignable` sans verdict qui l'atteste");
    }
}

fuzz_target!(|entree: Entree| {
    let Ok(bail) = Bail::nouveau(entree.keepalive, entree.inactivite) else {
        return;
    };
    let nom = NomService::analyser("x").expect("nom constant valide");
    let machine = Identifiant::depuis_entropie(Genre::Machine, [0x11; 16]);
    let service = Identifiant::depuis_entropie(Genre::Service, [0x22; 16]);

    let points = sans_doublons(points_de(&entree.points));
    let adresses: Vec<IpAddr> = entree.adresses.iter().map(adresse).take(8).collect();
    let Ok(annonce) = Annonce::nouvelle(machine, nom, &points, &adresses) else {
        return;
    };
    let Ok(vu_port) = Port::depuis_u16(51_840) else {
        return;
    };
    let vu_depuis = VuDepuis {
        adresse: adresse(&entree.vu),
        port: vu_port,
    };

    let mut maintenant = Instant::depuis_millisecondes(1_000_000);
    let Ok((mut session, _ordres)) =
        Session::ouvrir(service, bail, &annonce, vu_depuis, maintenant)
    else {
        return;
    };

    let mut close = false;
    let mut deja_expiree = false;
    verifier(&session, maintenant, close);

    for evenement in &entree.evenements {
        match evenement {
            Evenement::Attente { avance } => {
                maintenant =
                    Instant::depuis_millisecondes(maintenant.millisecondes() + u64::from(*avance));
            }
            Evenement::Keepalive { avance } => {
                maintenant =
                    Instant::depuis_millisecondes(maintenant.millisecondes() + u64::from(*avance));
                // Le temps n'avance jamais à reculons dans ce harnais : le
                // SEUL refus possible est l'expiration.
                if let Err(faute) = session.keepalive(maintenant) {
                    assert!(
                        matches!(faute, Faute::SessionExpiree { .. }),
                        "faute inattendue : {faute:?}"
                    );
                }
            }
            Evenement::Reannonce {
                avance,
                points,
                adresses,
                vu,
            } => {
                maintenant =
                    Instant::depuis_millisecondes(maintenant.millisecondes() + u64::from(*avance));
                let points = sans_doublons(points_de(points));
                let adresses: Vec<IpAddr> = adresses.iter().map(adresse).take(8).collect();
                let Ok(nouvelle) = Annonce::nouvelle(machine, nom, &points, &adresses) else {
                    continue;
                };
                let vu = VuDepuis {
                    adresse: adresse(vu),
                    port: vu_port,
                };
                if let Err(faute) = session.reannoncer(&nouvelle, vu, maintenant) {
                    assert!(
                        matches!(faute, Faute::SessionExpiree { .. }),
                        "faute inattendue : {faute:?}"
                    );
                }
            }
            Evenement::Sonde {
                avance,
                rang,
                aboutie,
                candidat,
            } => {
                maintenant =
                    Instant::depuis_millisecondes(maintenant.millisecondes() + u64::from(*avance));
                let reponse = session.reponse().expect("réponse valide");
                let compte = reponse.joignabilite.len();
                if compte == 0 {
                    continue;
                }
                let point = reponse.joignabilite[usize::from(*rang) % compte].point;
                let resultat = aboutie.then(|| Candidat {
                    protocole: point.protocole,
                    adresse: adresse(candidat),
                    port: point.port,
                    origine: Origine::Reflexif,
                });
                // Un point UDP est refusé, et c'est la propriété qu'on veut.
                let _ = session.verdict_de_sonde(
                    point,
                    resultat,
                    Horodatage::depuis_millisecondes(maintenant.millisecondes()),
                    maintenant,
                );
            }
            Evenement::Fermeture { volontaire } => {
                session.fermer(if *volontaire {
                    MotifDeDepart::Volontaire
                } else {
                    MotifDeDepart::Inactivite
                });
                close = true;
            }
        }

        // PROPRIÉTÉ 5 : l'expiration est monotone. AUCUN événement ne la défait.
        let expiree = session.expiree(maintenant);
        if deja_expiree && !close {
            assert!(expiree, "une session expirée a cessé de l'être");
        }
        deja_expiree = expiree;

        verifier(&session, maintenant, close);
    }

    // Les candidats se calculent quel que soit l'état, et ne débordent jamais.
    let reponse = session.reponse().expect("réponse valide");
    if let Some(premiere) = reponse.joignabilite.first() {
        let mut sortie = [Candidat {
            protocole: Protocole::Tcp,
            adresse: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: vu_port,
            origine: Origine::Annonce,
        }; CANDIDATS_MAX];
        let compte = session.candidats(premiere.point, &mut sortie);
        assert!(compte <= CANDIDATS_MAX);
        // Ils sont ordonnés : IPv6 avant IPv4.
        for paire in sortie[..compte].windows(2) {
            assert!(paire[0].rang() <= paire[1].rang(), "candidats mal ordonnés");
        }
    }
});
