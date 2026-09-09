//! Les clés et le message signé.
//!
//! **Les essais qui comptent ne sont pas ceux qui vérifient qu'une signature
//! juste passe** — c'est ce que la bibliothèque garantit. Ce sont ceux qui
//! vérifient que le message signé LIE ce qu'il doit lier : le domaine, la
//! machine, le défi, la connexion. Un champ qui n'entrerait pas dans le message
//! serait un champ qu'un attaquant peut changer sans invalider la signature.

use asl_cle::{
    CLE_PUBLIQUE_OCTETS, CleSecrete, DOMAINE, Defi, Faute, LIAISON_OCTETS, LiaisonDeCanal,
    MESSAGE_OCTETS, SIGNATURE_OCTETS, Signature, message_a_signer,
};
use asl_id::{Genre, Identifiant};

fn machine(marque: u8) -> Identifiant {
    let mut octets = [0x11; 16];
    octets[0] = marque;
    Identifiant::depuis_entropie(Genre::Machine, octets)
}

fn cle() -> CleSecrete {
    CleSecrete::depuis_entropie([0x42; 32])
}

fn defi(marque: u8) -> Defi {
    let mut octets = [0x01; 32];
    octets[0] = marque;
    Defi::depuis_octets(octets)
}

fn liaison(marque: u8) -> LiaisonDeCanal {
    let mut octets = [0x02; 32];
    octets[0] = marque;
    LiaisonDeCanal::depuis_octets(octets)
}

// ── Le tour normal ──────────────────────────────────────────────────────────

#[test]
fn une_signature_juste_verifie() {
    let secrete = cle();
    let publique = secrete.publique();
    let signature = secrete.signer(machine(1), &defi(1), &liaison(1)).unwrap();
    assert!(publique.verifie(machine(1), &defi(1), &liaison(1), &signature));
}

#[test]
fn la_cle_publique_se_relit() {
    let publique = cle().publique();
    let octets = publique.octets();
    assert_eq!(octets.len(), CLE_PUBLIQUE_OCTETS);
    let relue = asl_cle::ClePublique::depuis_octets(octets).unwrap();
    assert_eq!(relue, publique);
}

// ── Ce que le message LIE ───────────────────────────────────────────────────

#[test]
fn changer_la_machine_invalide_la_signature() {
    // Sans le champ, une signature d'une machine vaudrait pour une autre.
    let secrete = cle();
    let signature = secrete.signer(machine(1), &defi(1), &liaison(1)).unwrap();
    assert!(
        !secrete
            .publique()
            .verifie(machine(2), &defi(1), &liaison(1), &signature)
    );
}

#[test]
fn changer_le_defi_invalide_la_signature() {
    // C'est ce qui ferme le REJEU.
    let secrete = cle();
    let signature = secrete.signer(machine(1), &defi(1), &liaison(1)).unwrap();
    assert!(
        !secrete
            .publique()
            .verifie(machine(1), &defi(2), &liaison(1), &signature)
    );
}

#[test]
fn changer_la_liaison_de_canal_invalide_la_signature() {
    // C'est ce qui ferme le RELAIS : un intermédiaire qui transmet le défi et
    // renvoie la signature ne travaille pas sur la même connexion.
    let secrete = cle();
    let signature = secrete.signer(machine(1), &defi(1), &liaison(1)).unwrap();
    assert!(
        !secrete
            .publique()
            .verifie(machine(1), &defi(1), &liaison(2), &signature)
    );
}

#[test]
fn une_autre_cle_ne_verifie_pas() {
    let signature = cle().signer(machine(1), &defi(1), &liaison(1)).unwrap();
    let autre = CleSecrete::depuis_entropie([0x43; 32]);
    assert!(
        !autre
            .publique()
            .verifie(machine(1), &defi(1), &liaison(1), &signature)
    );
}

#[test]
fn une_signature_quelconque_ne_verifie_pas() {
    let publique = cle().publique();
    for octets in [[0x00; SIGNATURE_OCTETS], [0xFF; SIGNATURE_OCTETS]] {
        let signature = Signature::depuis_octets(octets);
        assert!(!publique.verifie(machine(1), &defi(1), &liaison(1), &signature));
        assert_eq!(signature.octets().len(), SIGNATURE_OCTETS);
    }
}

// ── La forme du message ─────────────────────────────────────────────────────

#[test]
fn le_message_a_la_forme_annoncee() {
    let message = message_a_signer(machine(0xAB), &defi(0xCD), &liaison(0xEF));
    assert_eq!(message.len(), MESSAGE_OCTETS);

    // Le séparateur de domaine vient en premier, et il est terminé par un octet
    // nul — un domaine qui serait le préfixe d'un autre ne pourrait pas se
    // confondre avec lui.
    assert!(message.starts_with(DOMAINE));
    assert_eq!(DOMAINE.last(), Some(&0x00));

    // Puis le genre, l'identifiant, le défi, la liaison — à leur place exacte.
    let mut rang = DOMAINE.len();
    assert_eq!(message[rang], b'm');
    rang += 1;
    assert_eq!(&message[rang..rang + 16], machine(0xAB).octets());
    rang += 16;
    assert_eq!(&message[rang..rang + 32], defi(0xCD).octets());
    rang += 32;
    assert_eq!(
        &message[rang..rang + LIAISON_OCTETS],
        liaison(0xEF).octets()
    );
}

#[test]
fn deux_messages_differents_ne_se_confondent_jamais() {
    // **La propriété qu'assurent les champs de longueur FIXE.** Avec des champs
    // variables, déplacer la frontière entre deux d'entre eux permettrait de
    // faire valoir une signature pour un message qu'on n'a pas écrit.
    let base = message_a_signer(machine(1), &defi(1), &liaison(1));
    for autre in [
        message_a_signer(machine(2), &defi(1), &liaison(1)),
        message_a_signer(machine(1), &defi(2), &liaison(1)),
        message_a_signer(machine(1), &defi(1), &liaison(2)),
    ] {
        assert_ne!(base, autre);
        assert_eq!(base.len(), autre.len(), "la longueur est toujours la même");
    }
}

// ── Les genres ──────────────────────────────────────────────────────────────

#[test]
fn signer_avec_autre_chose_qu_une_machine_est_refuse() {
    // Refusé ICI, et non plus tard : la signature serait valide, mais pour un
    // message que l'annuaire ne composera jamais — et le daemon chercherait la
    // panne du côté de sa clé.
    let secrete = cle();
    // **L'APPAREIL N'EST PLUS DANS CETTE LISTE**, et c'est le seul changement :
    // un téléphone enrôlé signe le défi de sa connexion exactement comme une
    // machine signe le sien. Les deux genres restent DISTINGUÉS, puisque le
    // genre entre dans le message signé — une preuve de machine ne vaut pas
    // pour un appareil, et réciproquement.
    for genre in [
        Genre::Utilisateur,
        Genre::Service,
        Genre::Autorisation,
        Genre::Annuaire,
    ] {
        let autre = Identifiant::depuis_entropie(genre, [0x11; 16]);
        assert_eq!(
            secrete.signer(autre, &defi(1), &liaison(1)).map(|_| ()),
            Err(Faute::PasUnPair { obtenu: genre })
        );
        // Et la vérification refuse aussi, pour que la faute se voie des deux
        // côtés.
        let signature = Signature::depuis_octets([0x00; SIGNATURE_OCTETS]);
        assert!(
            !secrete
                .publique()
                .verifie(autre, &defi(1), &liaison(1), &signature)
        );
    }
}

// ── Les clés mal formées ────────────────────────────────────────────────────

#[test]
fn une_cle_publique_qui_n_est_pas_un_point_est_refusee() {
    // Tous les tableaux de trente-deux octets ne sont pas des clés Ed25519 :
    // une ordonnée qui n'est sur la courbe est refusée, et c'est environ la
    // moitié d'entre elles. En accepter une ferait échouer toute vérification
    // ultérieure sans qu'on sache pourquoi.
    //
    // `[0x02; 32]` en est une — trouvée en cherchant, pas en devinant : le
    // premier motif essayé, `[0xFF; 32]`, se trouvait être un point VALIDE.
    assert_eq!(
        asl_cle::ClePublique::depuis_octets([0x02; CLE_PUBLIQUE_OCTETS]).map(|_| ()),
        Err(Faute::ClePubliqueInvalide)
    );

    // Et il en existe assez pour que ce ne soit pas un cas de bord isolé.
    let refusees = (0_u8..=255)
        .filter(|graine| {
            asl_cle::ClePublique::depuis_octets([*graine; CLE_PUBLIQUE_OCTETS]).is_err()
        })
        .count();
    assert!(
        refusees > 50,
        "seulement {refusees} motifs uniformes refusés"
    );
}

#[test]
fn deux_entropies_differentes_donnent_deux_cles() {
    let une = CleSecrete::depuis_entropie([0x01; 32]);
    let autre = CleSecrete::depuis_entropie([0x02; 32]);
    assert_ne!(une.publique(), autre.publique());

    // Et la même entropie donne la même clé — une clé n'est pas aléatoire à
    // chaque appel, sinon un ré-enrôlement changerait d'identité.
    assert_eq!(
        CleSecrete::depuis_entropie([0x01; 32]).publique(),
        une.publique()
    );
}

#[test]
fn les_valeurs_rendent_ce_qu_on_leur_a_donne() {
    let d = defi(7);
    assert_eq!(d.octets()[0], 7);
    let l = liaison(8);
    assert_eq!(l.octets()[0], 8);
    assert_eq!(Defi::depuis_octets(*d.octets()), d);
    assert_eq!(LiaisonDeCanal::depuis_octets(*l.octets()), l);
}

// ── La liaison de canal, exportée de la connexion ───────────────────────────

#[test]
fn l_etiquette_de_liaison_porte_la_version_du_protocole() {
    // **LES DEUX CAMPS DONNENT LA MÊME ÉTIQUETTE À LEUR EXPORTATEUR**, sans quoi
    // rien ne vérifie et la panne est indiscernable d'une clé fausse. Elle est
    // donc écrite ICI, une fois, et cet essai la fige.
    assert_eq!(
        asl_cle::ETIQUETTE_LIAISON,
        b"air-service-locator/v1/liaison-de-canal"
    );
    // Une liaison dérivée pour `v1` ne doit jamais valoir pour `v2`.
    assert!(
        asl_cle::ETIQUETTE_LIAISON.windows(4).any(|f| f == b"/v1/"),
        "l'étiquette doit porter la version"
    );
}

#[test]
fn une_signature_faite_pour_une_autre_connexion_ne_vaut_pas_ici() {
    // **L'ESSAI QUI JUSTIFIE LA LIAISON.** La même machine, le même défi, deux
    // connexions : c'est exactement la manœuvre de l'intermédiaire qui
    // transmettrait un défi et rapporterait la signature.
    //
    // Ce que l'exportateur change par rapport à une empreinte de certificat :
    // les deux valeurs ci-dessous seraient les MÊMES si l'intermédiaire servait
    // le certificat du vrai annuaire. Elles diffèrent parce qu'elles sont
    // dérivées de deux poignées de main, et non de deux identités.
    let secrete = asl_cle::CleSecrete::depuis_entropie([9; 32]);
    let publique = secrete.publique();
    let machine = asl_id::Identifiant::depuis_entropie(asl_id::Genre::Machine, [1; 16]);
    let defi = asl_cle::Defi::depuis_octets([2; 32]);

    let chez_nous = asl_cle::LiaisonDeCanal::depuis_octets([0xA1; asl_cle::LIAISON_OCTETS]);
    let chez_l_intrus = asl_cle::LiaisonDeCanal::depuis_octets([0xB2; asl_cle::LIAISON_OCTETS]);

    let signee = secrete
        .signer(machine, &defi, &chez_l_intrus)
        .expect("une machine signe");
    assert!(
        !publique.verifie(machine, &defi, &chez_nous, &signee),
        "une signature faite pour une autre connexion a été acceptée"
    );
    assert!(
        publique.verifie(machine, &defi, &chez_l_intrus, &signee),
        "et elle vaut bien pour celui pour lequel elle a été faite"
    );
}

// ── Le code d'enrôlement ────────────────────────────────────────────────────
//
// **CES ESSAIS VIENNENT D'`asl-auth`**, avec le type qu'ils éprouvent. La
// grammaire d'un code est un justificatif, et le daemon doit savoir la composer
// sans embarquer les décisions de l'annuaire — voir l'en-tête de la section
// correspondante dans `asl-cle`.

use asl_cle::CodeEnrolement;

#[test]
fn un_code_se_fabrique_se_lit_et_se_relit() {
    let code = CodeEnrolement::depuis_entropie([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]);
    let texte = code.texte();
    assert_eq!(texte.len(), 10);
    assert!(texte.bytes().all(|o| asl_id::base32::valeur(o).is_some()));

    let relu = CodeEnrolement::analyser(texte).expect("un code canonique se relit");
    assert_eq!(relu.texte(), texte);
    // **C'EST L'EMPREINTE QUI IDENTIFIE**, puisque c'est elle qu'on range.
    assert_eq!(relu.empreinte(), code.empreinte());
}

#[test]
fn la_forme_groupee_s_affiche_et_se_retape() {
    let code = CodeEnrolement::analyser("4K9M2P7R1T").unwrap();
    let groupe = code.texte_groupe();
    assert_eq!(groupe.as_str(), "4K9M2-P7R1T");

    // Ce qu'on AFFICHE se retape tel quel, et vaut ce qu'on a affiché.
    let retape = CodeEnrolement::analyser(groupe.as_str()).expect("la forme groupée se relit");
    assert_eq!(retape.empreinte(), code.empreinte());
    assert_eq!(retape.texte(), "4K9M2P7R1T");
}

#[test]
fn un_tiret_egare_ne_passe_pas() {
    // La bonne longueur, mais le tiret ailleurs qu'à sa place.
    assert_eq!(
        CodeEnrolement::analyser("4K9M2P-7R1T").map(|_| ()),
        Err(Faute::CodeLongueur {
            attendue: 10,
            obtenue: 11
        })
    );
}

#[test]
fn deux_codes_differents_ont_deux_empreintes() {
    let un = CodeEnrolement::analyser("0123456789").unwrap();
    let autre = CodeEnrolement::analyser("9876543210").unwrap();
    assert_ne!(un.empreinte(), autre.empreinte());
    assert_eq!(un.empreinte().len(), 32);
}

#[test]
fn le_rattrapage_de_crockford_vaut_aussi_pour_un_code() {
    // C'est un humain qui le tape sur un terminal.
    let reference = CodeEnrolement::analyser("0123456789").unwrap();
    for variante in ["O123456789", "o123456789", "0I23456789", "0L23456789"] {
        let lu = CodeEnrolement::analyser(variante).unwrap();
        assert_eq!(
            lu.empreinte(),
            reference.empreinte(),
            "{variante} devrait valoir la référence"
        );
        // Et ce qu'on range est la forme CANONIQUE.
        assert_eq!(lu.texte(), "0123456789");
    }
}

#[test]
fn un_code_mal_forme_est_refuse() {
    for texte in ["", "012345678", "01234567890"] {
        assert_eq!(
            CodeEnrolement::analyser(texte).map(|_| ()),
            Err(Faute::CodeLongueur {
                attendue: 10,
                obtenue: texte.len()
            }),
            "{texte:?}"
        );
    }
    assert_eq!(
        CodeEnrolement::analyser("01234U6789").map(|_| ()),
        Err(Faute::CodeSymboleInvalide { position: 5 })
    );
    assert_eq!(
        CodeEnrolement::analyser("!123456789").map(|_| ()),
        Err(Faute::CodeSymboleInvalide { position: 0 })
    );
}

#[test]
fn les_cinquante_bits_de_poids_fort_sont_employes() {
    // Changer un bit de POIDS FORT change le code ; changer les quatorze bits
    // de poids faible ne le change pas.
    let base = CodeEnrolement::depuis_entropie([0x00; 8]);
    let poids_fort = CodeEnrolement::depuis_entropie([0x80, 0, 0, 0, 0, 0, 0, 0]);
    let poids_faible = CodeEnrolement::depuis_entropie([0, 0, 0, 0, 0, 0, 0x3F, 0xFF]);

    assert_ne!(base.empreinte(), poids_fort.empreinte());
    assert_eq!(base.empreinte(), poids_faible.empreinte());
}

#[test]
fn le_texte_groupe_s_affiche() {
    // Il se recopie d'un écran vers un terminal : il doit s'écrire.
    let code = CodeEnrolement::analyser("4K9M2P7R1T").unwrap();
    assert_eq!(code.texte_groupe().to_string(), "4K9M2-P7R1T");
}
