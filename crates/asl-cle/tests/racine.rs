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

// ── Les deux preuves d'une racine (`replication.md` §2.2) ───────────────────

fn defi(marque: u8) -> asl_cle::Defi {
    let mut octets = [0x01; 32];
    octets[0] = marque;
    asl_cle::Defi::depuis_octets(octets)
}

fn liaison(marque: u8) -> asl_cle::LiaisonDeCanal {
    let mut octets = [0x02; 32];
    octets[0] = marque;
    asl_cle::LiaisonDeCanal::depuis_octets(octets)
}

#[test]
fn la_racine_qui_tire_signe_comme_une_machine_sous_le_genre_n() {
    // **PREMIER TEMPS** : le tireur prouve sa clé d'identité par `POST
    // /v1/defi`, avec son `n-…` et le message d'une machine. Le verbe existe,
    // la preuve existe ; il y a un genre de plus.
    let secrete = CleSecrete::depuis_entropie([0x42; 32]);
    let racine = identifiant_de_racine(&secrete.publique());
    let signature = secrete
        .signer(racine, &defi(1), &liaison(1))
        .expect("une racine signe");
    assert!(
        secrete
            .publique()
            .verifie(racine, &defi(1), &liaison(1), &signature)
    );

    // Et le genre entre dans le message : la même signature ne vaut pas pour
    // une MACHINE qui porterait les mêmes seize octets.
    let machine = asl_id::Identifiant::depuis_entropie(Genre::Machine, *racine.octets());
    assert!(
        !secrete
            .publique()
            .verifie(machine, &defi(1), &liaison(1), &signature)
    );
}

#[test]
fn la_racine_tiree_prouve_son_identite_sous_un_domaine_propre() {
    // **SECOND TEMPS** : le tireur pose un défi, la racine tirée le signe.
    let secrete = CleSecrete::depuis_entropie([0x42; 32]);
    let (racine, signature) = secrete.prouver_la_racine(&defi(1), &liaison(1));
    assert_eq!(racine, identifiant_de_racine(&secrete.publique()));
    assert!(
        secrete
            .publique()
            .prouve_la_racine(racine, &defi(1), &liaison(1), &signature)
    );

    // Le message est celui qu'on croit — le domaine en tête, puis le genre,
    // l'identifiant, le défi, la liaison.
    let message = asl_cle::message_de_preuve_de_racine(racine, &defi(1), &liaison(1));
    assert_eq!(message.len(), asl_cle::MESSAGE_PREUVE_DE_RACINE_OCTETS);
    assert!(message.starts_with(asl_cle::DOMAINE_PREUVE_DE_RACINE));
    let apres_domaine = &message[asl_cle::DOMAINE_PREUVE_DE_RACINE.len()..];
    assert_eq!(apres_domaine[0], b'n');
    assert_eq!(&apres_domaine[1..17], racine.octets());
    assert_eq!(&apres_domaine[17..49], defi(1).octets());
    assert_eq!(&apres_domaine[49..], liaison(1).octets());
}

#[test]
fn la_preuve_de_racine_lie_le_defi_la_liaison_et_la_cle() {
    let secrete = CleSecrete::depuis_entropie([0x42; 32]);
    let publique = secrete.publique();
    let (racine, signature) = secrete.prouver_la_racine(&defi(1), &liaison(1));

    // Un autre défi : c'est le rejeu.
    assert!(!publique.prouve_la_racine(racine, &defi(2), &liaison(1), &signature));
    // Une autre liaison : c'est le relais.
    assert!(!publique.prouve_la_racine(racine, &defi(1), &liaison(2), &signature));
    // Une autre clé : ce n'est pas la racine épinglée.
    let autre = CleSecrete::depuis_entropie([0x43; 32]).publique();
    assert!(!autre.prouve_la_racine(racine, &defi(1), &liaison(1), &signature));
    // Un `n-…` qui n'est pas celui de la clé : refusé AVANT même de vérifier
    // — le tireur compare à la clé qu'il tient, jamais au fil.
    let usurpe = identifiant_de_racine(&autre);
    assert!(!publique.prouve_la_racine(usurpe, &defi(1), &liaison(1), &signature));
}

#[test]
fn les_deux_preuves_ne_se_valent_pas_l_une_l_autre() {
    // **C'EST LA RAISON DU TROISIÈME DOMAINE.** Une signature du premier temps
    // — celle que le tireur émet — ne doit jamais valoir pour le second, où
    // c'est le serveur qui signe ce qu'un client lui présente. Sinon le
    // serveur serait un oracle pour la preuve d'authentification.
    let secrete = CleSecrete::depuis_entropie([0x42; 32]);
    let publique = secrete.publique();
    let racine = identifiant_de_racine(&publique);
    let premier = secrete
        .signer(racine, &defi(1), &liaison(1))
        .expect("elle signe");
    let (_, second) = secrete.prouver_la_racine(&defi(1), &liaison(1));
    assert_ne!(premier, second);
    assert!(!publique.prouve_la_racine(racine, &defi(1), &liaison(1), &premier));
    assert!(!publique.verifie(racine, &defi(1), &liaison(1), &second));
}
