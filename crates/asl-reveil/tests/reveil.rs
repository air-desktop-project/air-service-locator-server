//! Les décisions du réveil, une par une : chaque famille d'adresses, la
//! requête octet pour octet, la ligne de statut, et les trois freins.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use asl_api::point::UrlDePoussee;
use asl_id::{Genre, Identifiant};
use asl_reveil::{
    EN_VOL_MAX, Frein, Freins, Issue, LIGNE_DE_STATUT_MAX, MINUTE_MS, PAR_HOTE_ET_PAR_MINUTE,
    Regle, Statut, TTL_SECONDES, issue, juger, juger_toutes, lire_le_statut, requete,
};

/// Le jugement de cette adresse écrite.
fn jugee(texte: &str) -> Result<(), Regle> {
    juger(texte.parse::<IpAddr>().expect("une adresse"))
}

// ── Les adresses, famille par famille ───────────────────────────────────────

#[test]
fn une_ipv4_publique_passe_et_chaque_famille_non_globale_est_refusee() {
    for publique in [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "172.32.0.1",
        "100.128.0.1",
    ] {
        assert_eq!(jugee(publique), Ok(()), "{publique}");
    }
    let refusees: &[(&str, Regle)] = &[
        ("127.0.0.1", Regle::Bouclage),
        ("127.255.255.254", Regle::Bouclage),
        ("0.0.0.0", Regle::NonSpecifiee),
        ("0.1.2.3", Regle::Reservee),
        ("10.0.0.1", Regle::Privee),
        ("172.16.0.1", Regle::Privee),
        ("172.31.255.255", Regle::Privee),
        ("192.168.1.1", Regle::Privee),
        ("169.254.169.254", Regle::LienLocal),
        ("100.64.0.1", Regle::Partage),
        ("100.127.255.255", Regle::Partage),
        ("224.0.0.1", Regle::Multidiffusion),
        ("239.255.255.250", Regle::Multidiffusion),
        ("192.0.2.1", Regle::Documentation),
        ("198.51.100.7", Regle::Documentation),
        ("203.0.113.9", Regle::Documentation),
        ("192.0.0.8", Regle::Reservee),
        ("198.18.0.1", Regle::Reservee),
        ("198.19.255.255", Regle::Reservee),
        ("192.88.99.1", Regle::Reservee),
        ("240.0.0.1", Regle::Reservee),
        ("255.255.255.255", Regle::Reservee),
    ];
    for (texte, regle) in refusees {
        assert_eq!(jugee(texte), Err(*regle), "{texte}");
    }
}

#[test]
fn une_ipv6_publique_passe_et_chaque_famille_non_globale_est_refusee() {
    // `3fff:1000::` est juste après le préfixe de documentation `3fff::/20`.
    for publique in [
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
        "2a00:1450::1",
        "3fff:1000::1",
        "3ffe::1",
    ] {
        assert_eq!(jugee(publique), Ok(()), "{publique}");
    }
    let refusees: &[(&str, Regle)] = &[
        ("::", Regle::NonSpecifiee),
        ("::1", Regle::Bouclage),
        ("fc00::1", Regle::Privee),
        ("fd12:3456::1", Regle::Privee),
        ("fe80::1", Regle::LienLocal),
        ("febf::1", Regle::LienLocal),
        ("ff02::1", Regle::Multidiffusion),
        ("2001:db8::1", Regle::Documentation),
        ("3fff::1", Regle::Documentation),
        ("3fff:fff::1", Regle::Documentation),
        // Hors de `2000::/3`, rien n'est global.
        ("100::1", Regle::Reservee),
        ("fec0::1", Regle::Reservee),
        ("64:ff9b:1::1", Regle::Reservee),
        ("::a00:1", Regle::Reservee),
        ("4000::1", Regle::Reservee),
        // Les assignations de protocole de l'IETF, hors Teredo.
        ("2001:2::1", Regle::Reservee),
        ("2001:10::1", Regle::Reservee),
    ];
    for (texte, regle) in refusees {
        assert_eq!(jugee(texte), Err(*regle), "{texte}");
    }
}

#[test]
fn une_ipv4_enfouie_se_juge_comme_l_ipv4_qu_elle_porte() {
    // `::ffff:0:0/96` : la forme que prend une IPv4 sur une socket double pile.
    assert_eq!(jugee("::ffff:127.0.0.1"), Err(Regle::Bouclage));
    assert_eq!(jugee("::ffff:169.254.169.254"), Err(Regle::LienLocal));
    assert_eq!(jugee("::ffff:8.8.8.8"), Ok(()));
    // `64:ff9b::/96` : NAT64.
    assert_eq!(jugee("64:ff9b::10.0.0.1"), Err(Regle::Privee));
    assert_eq!(jugee("64:ff9b::8.8.8.8"), Ok(()));
    // `2002::/16` : 6to4, l'IPv4 aux octets 2 à 5.
    assert_eq!(jugee("2002:a00:1::1"), Err(Regle::Privee));
    assert_eq!(jugee("2002:7f00:1::"), Err(Regle::Bouclage));
    assert_eq!(jugee("2002:808:808::1"), Ok(()));
    // Teredo, `2001::/32` : le serveur en clair, le client inversé. L'exemple
    // de RFC 4380 porte un client de documentation, 192.0.2.45.
    assert_eq!(
        jugee("2001:0:4136:e378:8000:63bf:3fff:fdd2"),
        Err(Regle::Documentation)
    );
    // Un serveur privé suffit à refuser.
    assert_eq!(jugee("2001:0:a00:1::"), Err(Regle::Privee));
    // Serveur et client publics : 65.54.227.120 et 8.8.8.8 inversé.
    let client = !u32::from(Ipv4Addr::new(8, 8, 8, 8));
    let [w, x, y, z] = client.to_be_bytes();
    let teredo = Ipv6Addr::new(
        0x2001,
        0,
        0x4136,
        0xe378,
        0,
        0,
        u16::from_be_bytes([w, x]),
        u16::from_be_bytes([y, z]),
    );
    assert_eq!(juger(IpAddr::V6(teredo)), Ok(()));
}

#[test]
fn une_seule_adresse_refusee_refuse_le_nom() {
    let publique: IpAddr = "8.8.8.8".parse().unwrap();
    let interne: IpAddr = "10.1.2.3".parse().unwrap();
    assert_eq!(
        juger_toutes(&[]),
        Ok(()),
        "aucune adresse n'est pas un refus"
    );
    assert_eq!(juger_toutes(&[publique]), Ok(()));
    assert_eq!(
        juger_toutes(&[publique, interne, publique]),
        Err((interne, Regle::Privee)),
        "on ne se rabat pas sur la publique"
    );
}

#[test]
fn chaque_regle_a_un_nom_pour_le_journal() {
    let regles = [
        Regle::Bouclage,
        Regle::NonSpecifiee,
        Regle::Privee,
        Regle::LienLocal,
        Regle::Partage,
        Regle::Multidiffusion,
        Regle::Documentation,
        Regle::Reservee,
    ];
    let noms: Vec<&str> = regles.iter().map(|regle| regle.nom()).collect();
    for (rang, nom) in noms.iter().enumerate() {
        assert!(!nom.is_empty());
        assert!(!noms[..rang].contains(nom), "{nom} en double");
    }
}

// ── La requête ──────────────────────────────────────────────────────────────

#[test]
fn la_requete_est_constante_sauf_l_url() {
    let point = UrlDePoussee::analyser("https://ntfy.example.org:443/upAb3?x=1").unwrap();
    assert_eq!(
        String::from_utf8(requete(&point)).unwrap(),
        "POST /upAb3?x=1 HTTP/1.1\r\nHost: ntfy.example.org\r\nTTL: 86400\r\n\
         Topic: nouvelles\r\nUrgency: normal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    assert_eq!(TTL_SECONDES, 86_400);
    // Sans chemin, la cible est `/`, et une requête sans chemin reçoit le sien.
    for (texte, ligne) in [
        ("https://ntfy.sh", "POST / HTTP/1.1\r\n"),
        ("https://ntfy.sh?x", "POST /?x HTTP/1.1\r\n"),
    ] {
        let point = UrlDePoussee::analyser(texte).unwrap();
        assert!(
            String::from_utf8(requete(&point))
                .unwrap()
                .starts_with(ligne),
            "{texte}"
        );
    }
}

// ── La réponse ──────────────────────────────────────────────────────────────

#[test]
fn seule_la_ligne_de_statut_se_lit() {
    assert_eq!(lire_le_statut(b""), Statut::Incomplet);
    assert_eq!(lire_le_statut(b"HTTP/1.1 20"), Statut::Incomplet);
    assert_eq!(
        lire_le_statut(b"HTTP/1.1 201 Created\r\n"),
        Statut::Code(201)
    );
    assert_eq!(
        lire_le_statut(b"HTTP/1.1 410 Gone\r\nContent-Length: 999999\r\n\r\ncorps"),
        Statut::Code(410)
    );
    assert_eq!(lire_le_statut(b"HTTP/1.0 404\r\n"), Statut::Code(404));
    for illisible in [
        &b"HTTP/2 200\r\n"[..],
        b"HTTP/1.1 20\r\n",
        b"HTTP/1.1 2000\r\n",
        b"HTTP/1.1 2x0 OK\r\n",
        // Le fuzz l'a trouvé : trois chiffres, mais aucune classe de statut.
        b"HTTP/1.1 014\r\n",
        b"HTTP/1.1 600 Au-dela\r\n",
        b"http/1.1 200 OK\r\n",
        b"SSH-2.0-OpenSSH\r\n",
        b"\r\n",
    ] {
        assert_eq!(
            lire_le_statut(illisible),
            Statut::Illisible,
            "{}",
            String::from_utf8_lossy(illisible)
        );
    }
    // Une ligne sans fin ne se lit pas au-delà de la borne.
    let longue = vec![b'H'; LIGNE_DE_STATUT_MAX];
    assert_eq!(lire_le_statut(&longue), Statut::Incomplet);
    let trop = vec![b'H'; LIGNE_DE_STATUT_MAX + 1];
    assert_eq!(lire_le_statut(&trop), Statut::Illisible);
}

#[test]
fn seuls_404_et_410_disent_un_point_mort() {
    for code in [200, 201, 202, 204, 299] {
        assert_eq!(issue(code), Issue::Reussi, "{code}");
    }
    assert_eq!(issue(404), Issue::Mort);
    assert_eq!(issue(410), Issue::Mort);
    // Une redirection est un échec, jamais un chemin.
    for code in [
        100, 199, 301, 302, 307, 400, 401, 403, 413, 429, 500, 503, 999,
    ] {
        assert_eq!(issue(code), Issue::Abandonne, "{code}");
    }
}

// ── Les freins ──────────────────────────────────────────────────────────────

/// Un appareil, reproductible.
fn a(graine: u8) -> Identifiant {
    Identifiant::depuis_entropie(Genre::Appareil, [graine; 16])
}

/// L'identité d'un point.
fn p(compteur: u64) -> (u64, Identifiant) {
    (
        compteur,
        Identifiant::depuis_entropie(Genre::Annuaire, [0xEE; 16]),
    )
}

#[test]
fn un_appareil_se_reveille_une_fois_par_minute() {
    let mut freins = Freins::neufs();
    assert_eq!(freins.admettre(a(1), p(1), "ntfy.sh", 1_000), Ok(()));
    freins.rendre();
    // Dix autorisations dans la minute font un seul réveil.
    assert_eq!(
        freins.admettre(a(1), p(1), "ntfy.sh", 1_000 + MINUTE_MS - 1),
        Err(Frein::Appareil)
    );
    // Un autre appareil n'est pas freiné par le premier.
    assert_eq!(freins.admettre(a(2), p(1), "ntfy.sh", 2_000), Ok(()));
    freins.rendre();
    // La minute passée, il se réveille de nouveau.
    assert_eq!(
        freins.admettre(a(1), p(1), "ntfy.sh", 1_000 + MINUTE_MS),
        Ok(())
    );
    freins.rendre();
    assert_eq!(freins.en_vol(), 0);
}

#[test]
fn l_instant_zero_compte_comme_les_autres() {
    // Une horloge monotone démarre à zéro : ce qui y est envoyé reste freiné
    // toute la minute.
    let mut freins = Freins::neufs();
    assert_eq!(freins.admettre(a(1), p(1), "ntfy.sh", 0), Ok(()));
    freins.rendre();
    assert_eq!(
        freins.admettre(a(1), p(1), "ntfy.sh", 30_000),
        Err(Frein::Appareil)
    );
}

#[test]
fn un_hote_recoit_soixante_envois_par_minute_au_plus() {
    let mut freins = Freins::neufs();
    for graine in 0..PAR_HOTE_ET_PAR_MINUTE {
        let graine = u8::try_from(graine).unwrap();
        assert_eq!(
            freins.admettre(a(graine), p(1), "Ntfy.SH", 10_000),
            Ok(()),
            "{graine}"
        );
        freins.rendre();
    }
    // Le soixante et unième est refusé — la casse de l'hôte ne le cache pas.
    assert_eq!(
        freins.admettre(a(200), p(1), "ntfy.sh", 10_001),
        Err(Frein::Hote)
    );
    // **UN REFUS NE COÛTE RIEN** : l'appareil freiné par l'hôte part vers un
    // autre hôte tout de suite.
    assert_eq!(
        freins.admettre(a(200), p(1), "autre.example", 10_002),
        Ok(())
    );
    freins.rendre();
    // La minute glisse : l'hôte reçoit de nouveau.
    assert_eq!(
        freins.admettre(a(201), p(1), "ntfy.sh", 10_000 + MINUTE_MS),
        Ok(())
    );
}

#[test]
fn huit_envois_au_plus_sont_en_vol() {
    let mut freins = Freins::neufs();
    for graine in 0..EN_VOL_MAX {
        let graine = u8::try_from(graine).unwrap();
        let hote = format!("h{graine}.example");
        assert_eq!(freins.admettre(a(graine), p(1), &hote, 0), Ok(()));
    }
    assert_eq!(freins.en_vol(), EN_VOL_MAX);
    assert_eq!(
        freins.admettre(a(100), p(1), "autre.example", 0),
        Err(Frein::EnVol)
    );
    freins.rendre();
    assert_eq!(freins.admettre(a(100), p(1), "autre.example", 0), Ok(()));
}

#[test]
fn un_point_mort_ne_recoit_plus_rien_jusqu_au_point_neuf() {
    let mut freins = Freins::neufs();
    assert_eq!(freins.admettre(a(1), p(7), "ntfy.sh", 0), Ok(()));
    freins.rendre();
    freins.marquer_mort(a(1), p(7));
    // Même une minute plus tard : un point mort ne ressuscite pas seul.
    assert_eq!(
        freins.admettre(a(1), p(7), "ntfy.sh", 5 * MINUTE_MS),
        Err(Frein::Mort)
    );
    // L'appareil dépose un point neuf : son estampille change, il revit.
    assert_eq!(
        freins.admettre(a(1), p(8), "ntfy.sh", 5 * MINUTE_MS),
        Ok(())
    );
    freins.rendre();
    assert_eq!(
        freins.admettre(a(1), p(8), "ntfy.sh", 7 * MINUTE_MS),
        Ok(()),
        "l'ancienne mort est oubliée"
    );
}
