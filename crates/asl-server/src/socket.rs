//! La socket d'écoute, en double pile.
//!
//! # POURQUOI CE MODULE EXISTE PLUTÔT QU'UN `UdpSocket::bind("[::]:6630")`
//!
//! Une socket IPv6 accepte-t-elle aussi l'IPv4 ? **Cela dépend d'un réglage du
//! noyau que nous ne contrôlons pas** : `net.ipv6.bindv6only`. Il vaut zéro sur
//! la plupart des Linux, ce qui donne la double pile — et un annuaire déployé
//! sur une machine où il vaut un n'entendrait plus un seul client IPv4, sans
//! qu'aucun message ne le dise.
//!
//! « IPv6 d'abord, IPv4 en repli » est une décision de PRODUIT (`modele.md`
//! §1). La laisser dépendre d'un sysctl reviendrait à ne pas l'avoir prise.
//!
//! `std` ne permet pas de régler une option avant `bind`, et il faut donc
//! descendre à la libc — trois appels, et l'on remonte aussitôt.
//!
//! # CE QUI DIFFÈRE ENTRE LINUX ET LES BSD (macOS COMPRIS)
//!
//! L'annuaire a vocation à tourner sur Linux, macOS et Windows, et cette socket
//! est l'un des rares endroits où le système se voit. Linux règle `O_NONBLOCK`
//! et `FD_CLOEXEC` à la création, d'un seul appel, sans fenêtre où la socket
//! bloque ou s'hérite. Les BSD n'ont pas ces drapeaux : on les pose juste
//! après, par `fcntl`, avant que quiconque ait pu la voir — le descripteur
//! n'est encore confié à personne, et rien ne se lance entre les deux. Et
//! leur `sockaddr_in6` porte une longueur, `sin6_len`, que Linux n'a pas.
//!
//! # CE QUE LA DOUBLE PILE CHANGE POUR LA BOUCLE
//!
//! Un pair IPv4 se présente en adresse **mappée** : `::ffff:203.0.113.7`. La
//! boucle la range telle quelle et la compare telle quelle, donc rien à y
//! changer — et l'annuaire notera cette forme dans ce qu'il a CONSTATÉ, ce qui
//! est exact : c'est bien ainsi que nous l'avons vu.

use std::io;
use std::os::fd::FromRawFd as _;

/// Ouvre une socket UDP en double pile sur ce port, toutes adresses.
///
/// # Errors
///
/// [`io::Error`] si la socket ne peut être ni créée, ni réglée, ni liée.
pub fn ecouter(port: u16) -> io::Result<std::net::UdpSocket> {
    // SAFETY: `socket` ne touche à aucune mémoire que nous possédons. Le
    // descripteur rendu nous appartient dès qu'il est positif ; en dessous de
    // zéro, il n'y a rien à fermer.
    //
    // `SOCK_NONBLOCK` dès la création : tokio l'EXIGE, et le régler après
    // laisserait une fenêtre où la socket bloque.
    // `SOCK_CLOEXEC` : rien de ce que nous lançons n'a à hériter de cette
    // socket, et un descripteur hérité par mégarde survit à qui l'a ouvert.
    #[cfg(target_os = "linux")]
    let descripteur = unsafe {
        libc::socket(
            libc::AF_INET6,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    // SAFETY: même contrat ; les deux drapeaux se posent juste après.
    #[cfg(not(target_os = "linux"))]
    let descripteur = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if descripteur < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: le descripteur vient d'être créé par `socket` et n'a été confié à
    // personne d'autre. `from_raw_fd` en prend la propriété, donc la fermeture
    // est assurée même si ce qui suit échoue.
    let socket = unsafe { std::net::UdpSocket::from_raw_fd(descripteur) };

    // Sur les BSD, ce que Linux a fait à la création : non bloquante, et
    // fermée à l'`exec`. `std` sait le premier de façon portable ; le second
    // est un `fcntl`.
    #[cfg(not(target_os = "linux"))]
    {
        socket.set_nonblocking(true)?;
        // SAFETY: `descripteur` est vivant (`socket` le possède), et `F_SETFD`
        // avec `FD_CLOEXEC` ne touche à rien d'autre que ses drapeaux.
        let ferme = unsafe { libc::fcntl(descripteur, libc::F_SETFD, libc::FD_CLOEXEC) };
        if ferme < 0 {
            return Err(io::Error::last_os_error());
        }
    }

    // **LE CŒUR DE CE MODULE** : `IPV6_V6ONLY` à zéro, explicitement.
    let non: libc::c_int = 0;
    // SAFETY: `descripteur` est vivant (`socket` le possède et n'est pas encore
    // détruit) ; `&non` pointe une valeur bien alignée de la taille annoncée.
    let regle = unsafe {
        libc::setsockopt(
            descripteur,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            core::ptr::from_ref(&non).cast::<libc::c_void>(),
            #[expect(
                clippy::cast_possible_truncation,
                reason = "la taille d'un c_int tient dans une socklen_t"
            )]
            {
                core::mem::size_of::<libc::c_int>() as libc::socklen_t
            },
        )
    };
    if regle < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut ou: libc::sockaddr_in6 = unsafe { core::mem::zeroed() };
    // `sa_family_t` : `u16` sur Linux, `u8` sur les BSD — le type de la libc
    // suit le système, et c'est lui qu'on demande.
    ou.sin6_family = libc::sa_family_t::try_from(libc::AF_INET6).unwrap_or(0);
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "la taille d'une sockaddr_in6 tient dans un u8 — c'est ce que sin6_len attend"
    )]
    {
        ou.sin6_len = core::mem::size_of::<libc::sockaddr_in6>() as u8;
    }
    ou.sin6_port = port.to_be();
    // `sin6_addr` reste à zéro : c'est `in6addr_any`, toutes les adresses.

    // SAFETY: `ou` est une `sockaddr_in6` entièrement initialisée, et la taille
    // passée est exactement la sienne.
    let lie = unsafe {
        libc::bind(
            descripteur,
            core::ptr::from_ref(&ou).cast::<libc::sockaddr>(),
            #[expect(
                clippy::cast_possible_truncation,
                reason = "la taille d'une sockaddr_in6 tient dans une socklen_t"
            )]
            {
                core::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
            },
        )
    };
    if lie < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::ecouter;

    #[test]
    fn une_socket_ephemere_s_ouvre_et_dit_son_adresse() {
        let socket = ecouter(0).expect("une socket éphémère");
        let ou = socket.local_addr().expect("une adresse");
        assert!(ou.is_ipv6(), "la socket doit être IPv6 : {ou}");
        assert_ne!(ou.port(), 0, "le noyau a attribué un port");
    }

    #[test]
    fn elle_entend_un_pair_ipv4_en_adresse_mappee() {
        // **C'EST L'ESSAI QUI JUSTIFIE TOUT LE MODULE.** Sans `IPV6_V6ONLY` à
        // zéro, ce datagramme n'arriverait jamais — et sur une machine où le
        // sysctl vaut un, personne ne le saurait avant la production.
        let ecoute = ecouter(0).expect("une socket");
        let port = ecoute.local_addr().expect("une adresse").port();
        ecoute
            .set_nonblocking(false)
            .expect("bloquante, le temps de l'essai");

        let client = std::net::UdpSocket::bind("127.0.0.1:0").expect("un client IPv4");
        client
            .send_to(b"bonjour", ("127.0.0.1", port))
            .expect("le datagramme part");

        let mut recu = [0_u8; 16];
        let (combien, pair) = ecoute.recv_from(&mut recu).expect("il arrive");
        assert_eq!(recu.get(..combien), Some(&b"bonjour"[..]));
        assert!(
            pair.is_ipv6(),
            "un pair IPv4 doit se présenter en adresse mappée : {pair}"
        );
        assert!(
            pair.to_string().contains("127.0.0.1"),
            "et la mappée doit porter l'adresse d'origine : {pair}"
        );
    }

    #[test]
    fn deux_ecoutes_sur_le_meme_port_ne_se_marchent_pas_dessus() {
        // Sans `SO_REUSEPORT` — que nous ne demandons pas —, la seconde doit
        // échouer. Un annuaire lancé deux fois par erreur doit le dire, pas
        // partager silencieusement sa porte.
        let premiere = ecouter(0).expect("la première");
        let port = premiere.local_addr().expect("une adresse").port();
        assert!(
            ecouter(port).is_err(),
            "deux annuaires se sont liés au même port"
        );
    }
}
