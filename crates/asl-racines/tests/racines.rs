//! La liste embarquée, la règle « clé = identité », et la vérification d'une
//! liste servie — éprouvées une par une.

use asl_api::annuaire::RacineRendue;
use asl_cle::{CleSecrete, certificat_d_identite, identifiant_de_racine};
use asl_id::{Genre, Identifiant};
use asl_racines::{
    ALIAS_DES_RACINES, FauteDeListe, RACINES, RacineEmbarquee, identite_attendue,
    identite_du_certificat, racines_du_locateur, verifier_la_liste,
};

fn hexa(octets: &[u8]) -> String {
    octets.iter().map(|octet| format!("{octet:02x}")).collect()
}

/// La liste embarquée, telle que `GET /v1/racines` la rend.
fn liste_servie() -> String {
    let rendues: Vec<String> = RACINES
        .iter()
        .map(|racine| {
            let mut sortie = vec![0_u8; 1024];
            let combien = RacineRendue {
                annuaire: racine.identite().expect("un identifiant"),
                cle: racine.cle,
                locateurs: racine.locateurs,
            }
            .encoder(&mut sortie)
            .expect("assez de place");
            String::from_utf8(sortie[..combien].to_vec()).expect("de l'ASCII")
        })
        .collect();
    format!("[{}]", rendues.join(","))
}

#[test]
fn chaque_cle_embarquee_se_deduit_en_son_identifiant() {
    // **L'ANCRE EST RECOPIÉE D'UN BANC** : une clé de travers ne passerait pas.
    for racine in RACINES {
        let cle = racine.cle_publique().expect("un point");
        assert_eq!(Some(identifiant_de_racine(&cle)), racine.identite());
        // Ses locateurs la désignent, elle seule — adresses d'abord (C20).
        assert!(racine.locateurs[0].starts_with('['), "IPv6 d'abord");
        for locateur in racine.locateurs {
            let designees: Vec<_> = racines_du_locateur(locateur).collect();
            assert_eq!(designees, vec![&racine], "{locateur}");
        }
    }
}

#[test]
fn l_alias_designe_les_deux_sans_casse_et_un_inconnu_personne() {
    assert_eq!(racines_du_locateur(ALIAS_DES_RACINES).count(), 2);
    assert_eq!(
        racines_du_locateur("ASL-ROOT.air-desktop.org:6630").count(),
        2
    );
    assert_eq!(
        racines_du_locateur("NITROGEN.air-desktop.org:6630").count(),
        1
    );
    assert_eq!(racines_du_locateur("127.0.0.1:6630").count(), 0);
}

#[test]
fn une_racine_mal_recopiee_ne_rend_ni_cle_ni_identite() {
    let fausse = RacineEmbarquee {
        identifiant: "pas un identifiant",
        cle: [0x02; 32],
        locateurs: &[],
    };
    assert!(fausse.cle_publique().is_none());
    assert!(fausse.identite().is_none());
    assert!(!fausse.designee_par("127.0.0.1:6630"));
}

#[test]
fn un_certificat_d_identite_d_un_seul_maillon_dit_son_identite() {
    let cle = CleSecrete::depuis_entropie([7; 32]);
    let attendue = identifiant_de_racine(&cle.publique());
    let certificat = certificat_d_identite(&cle);
    assert_eq!(identite_du_certificat(1, &certificat), Some(attendue));
    assert_eq!(
        identite_attendue(1, &certificat, &[attendue]),
        Some(attendue)
    );
}

#[test]
fn une_chaine_de_deux_n_est_pas_un_certificat_d_identite() {
    // **QUELLE QUE SOIT LA CLÉ DE SA TÊTE** (décision 54).
    let cle = CleSecrete::depuis_entropie([7; 32]);
    let attendue = identifiant_de_racine(&cle.publique());
    let certificat = certificat_d_identite(&cle);
    assert_eq!(identite_du_certificat(2, &certificat), None);
    assert_eq!(identite_du_certificat(0, &certificat), None);
    assert_eq!(identite_attendue(2, &certificat, &[attendue]), None);
}

#[test]
fn une_autre_cle_n_est_pas_l_identite_attendue() {
    let nous = CleSecrete::depuis_entropie([7; 32]);
    let autre = CleSecrete::depuis_entropie([8; 32]);
    let attendue = identifiant_de_racine(&nous.publique());
    assert_eq!(
        identite_attendue(1, &certificat_d_identite(&autre), &[attendue]),
        None
    );
    // Rien d'attendu : rien n'est cru.
    assert_eq!(
        identite_attendue(1, &certificat_d_identite(&nous), &[]),
        None
    );
    // Des octets qui ne sont pas un certificat.
    assert_eq!(identite_du_certificat(1, b"pas un certificat"), None);
}

#[test]
fn la_liste_servie_se_verifie() {
    let servie = liste_servie();
    let liste = verifier_la_liste(servie.as_bytes()).expect("elle se vérifie");
    let lues: Vec<_> = liste.racines().collect();
    assert_eq!(lues.len(), RACINES.len());
    for (lue, embarquee) in lues.iter().zip(RACINES) {
        assert_eq!(Some(lue.annuaire), embarquee.identite());
        assert_eq!(lue.cle, embarquee.cle);
        assert_eq!(lue.locateurs(), embarquee.locateurs);
    }
}

#[test]
fn une_cle_etrangere_fait_mentir_la_liste_entiere() {
    // La clé d'argon sous l'identité de nitrogen.
    let menteuse = liste_servie().replacen(&hexa(&RACINES[0].cle), &hexa(&RACINES[1].cle), 1);
    assert_eq!(
        verifier_la_liste(menteuse.as_bytes()).map(|_| ()),
        Err(FauteDeListe::Mensonge)
    );
}

#[test]
fn une_cle_qui_n_est_pas_un_point_refuse_la_liste() {
    let pas_un_point = liste_servie().replacen(&hexa(&RACINES[0].cle), &"02".repeat(32), 1);
    assert_eq!(
        verifier_la_liste(pas_un_point.as_bytes()).map(|_| ()),
        Err(FauteDeListe::ClePasUnPoint)
    );
}

#[test]
fn une_liste_illisible_est_refusee() {
    assert_eq!(
        verifier_la_liste(b"[]").map(|_| ()),
        Err(FauteDeListe::Illisible)
    );
    assert_eq!(
        verifier_la_liste(b"{").map(|_| ()),
        Err(FauteDeListe::Illisible)
    );
    // Une identité inconnue du lecteur, mais sous la bonne forme, se lit :
    // c'est la clé qui dit si elle ment.
    let inconnue = Identifiant::depuis_entropie(Genre::Annuaire, [3; 16]);
    let cle = CleSecrete::depuis_entropie([9; 32]).publique();
    let mut sortie = vec![0_u8; 512];
    let combien = RacineRendue {
        annuaire: inconnue,
        cle: cle.octets(),
        locateurs: &["192.0.2.9:6630"],
    }
    .encoder(&mut sortie)
    .expect("assez de place");
    let corps = format!("[{}]", String::from_utf8_lossy(&sortie[..combien]));
    assert_eq!(
        verifier_la_liste(corps.as_bytes()).map(|_| ()),
        Err(FauteDeListe::Mensonge)
    );
}
