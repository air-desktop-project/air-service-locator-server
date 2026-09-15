//! L'identifiant d'une racine, déduit de sa clé d'identité.
//!
//! **Ce qui compte ici est ce que la dérivation LIE** : le genre `n`, le domaine,
//! et la clé entière. Une dérivation qui rendrait le même identifiant pour deux
//! clés, ou un genre qu'on n'attend pas, ferait deux racines qui se croient
//! une — ou une racine qu'un enregistrement prendrait pour une machine.

use asl_cle::{CleSecrete, DOMAINE_IDENTITE_RACINE, identifiant_de_racine};
use asl_id::Genre;
use sha2::Digest as _;

fn cle(graine: u8) -> asl_cle::ClePublique {
    CleSecrete::depuis_entropie([graine; 32]).publique()
}

#[test]
fn l_identifiant_est_un_annuaire_et_se_deduit_toujours_pareil() {
    let une = identifiant_de_racine(&cle(0x42));
    assert_eq!(une.genre(), Genre::Annuaire);
    assert_eq!(
        identifiant_de_racine(&cle(0x42)),
        une,
        "la même clé doit donner le même identifiant, à chaque démarrage"
    );
}

#[test]
fn deux_cles_donnent_deux_identifiants() {
    assert_ne!(
        identifiant_de_racine(&cle(0x42)),
        identifiant_de_racine(&cle(0x43))
    );
}

#[test]
fn ce_sont_les_seize_premiers_octets_d_un_sha_256_a_domaine_separe() {
    // **LA DÉRIVATION EST ÉCRITE DANS LA SPÉCIFICATION** (`replication.md`
    // §2.2), et l'autre racine doit la calculer pareil pour épingler la clé :
    // l'essai la refait à la main, pour qu'un changement d'ordre ou de domaine
    // se voie ici et non chez l'autre.
    let publique = cle(0x42);
    let mut condensat = sha2::Sha256::new();
    condensat.update(DOMAINE_IDENTITE_RACINE);
    condensat.update(publique.octets());
    let entier = condensat.finalize();
    assert_eq!(identifiant_de_racine(&publique).octets(), &entier[..16]);

    // Et sans le domaine, ce n'est pas le même : le condensat nu d'une clé ne
    // doit jamais valoir identifiant.
    let nu = sha2::Sha256::digest(publique.octets());
    assert_ne!(identifiant_de_racine(&publique).octets(), &nu[..16]);
}
