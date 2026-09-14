//! D'où viennent les défis.
//!
//! # LE CSPRNG DU NOYAU, ET NON UN GÉNÉRATEUR À NOUS
//!
//! Un défi qui se devine ne défie personne : il suffirait de le prédire pour
//! préparer une signature à l'avance. C'est donc le CSPRNG du noyau, et rien
//! d'autre — pas un congruentiel comme celui des identifiants de connexion, qui
//! n'a besoin que d'être non corrélable.
//!
//! # POURQUOI PAS UNE CRATE
//!
//! `getrandom` la crate ferait une unité de plus dans un graphe que C4 borne, et
//! `libc` est déjà là — nous l'employons pour `geteuid`. L'appel tient en
//! quinze lignes, boucle comprise.
//!
//! # UN APPEL PAR SYSTÈME, LA MÊME BOUCLE
//!
//! L'annuaire a vocation à tourner sur Linux, macOS et Windows. Le noyau se
//! demande différemment selon le système, et c'est le SEUL endroit du binaire
//! où cela se voit :
//!
//! - Linux : `getrandom(2)`. Il peut rendre MOINS d'octets qu'on n'en demande,
//!   et échouer avec `EINTR` si un signal arrive.
//! - macOS et les BSD : `getentropy(2)`. Il remplit tout ou échoue, mais refuse
//!   plus de 256 octets par appel.
//! - Windows : à venir (`BCryptGenRandom`), quand le reste du binaire y sera.
//!
//! La boucle qui suit sert les deux : prendre le premier retour pour argent
//! comptant laisserait un défi partiellement nul — c'est-à-dire un défi qu'on
//! devine en partie.

use std::io;

use asl_cle::{DEFI_OCTETS, Defi};

/// Tire un défi imprévisible.
///
/// # Errors
///
/// [`io::Error`] si le noyau refuse de fournir de l'entropie.
pub fn un_defi() -> io::Result<Defi> {
    let mut octets = [0_u8; DEFI_OCTETS];
    remplir(&mut octets)?;
    Ok(Defi::depuis_octets(octets))
}

/// Tire seize octets, pour un identifiant.
///
/// **LE MÊME CSPRNG QUE LES DÉFIS**, et pour une raison voisine : un
/// identifiant de service qui se devine laisserait deviner ce qui existe, et
/// C10 tient précisément à ce que rien ne le laisse deviner.
///
/// # Errors
///
/// [`io::Error`] si le noyau refuse de fournir de l'entropie.
pub fn un_identifiant() -> io::Result<[u8; 16]> {
    let mut octets = [0_u8; 16];
    remplir(&mut octets)?;
    Ok(octets)
}

/// Remplit ces octets depuis le noyau, entièrement.
fn remplir(quoi: &mut [u8]) -> io::Result<()> {
    let mut ecrits = 0_usize;
    while ecrits < quoi.len() {
        let reste = quoi.get_mut(ecrits..).unwrap_or_default();
        let combien = tirer(reste);
        if combien < 0 {
            let faute = io::Error::last_os_error();
            // **`EINTR` N'EST PAS UNE PANNE**, c'est un signal qui est passé.
            if faute.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(faute);
        }
        let combien = usize::try_from(combien).unwrap_or(0);
        if combien == 0 {
            return Err(io::Error::other("le noyau n'a rendu aucun octet"));
        }
        ecrits = ecrits.saturating_add(combien);
    }
    Ok(())
}

/// Un appel au noyau : le nombre d'octets écrits au début de `reste`, ou un
/// négatif avec `errno` posé. Le contrat est celui de `getrandom(2)`, et
/// l'autre système s'y plie.
#[cfg(target_os = "linux")]
fn tirer(reste: &mut [u8]) -> isize {
    // SAFETY: `reste` est une tranche vivante que nous possédons, et la
    // longueur passée est exactement la sienne. `getrandom` n'écrit rien
    // au-delà.
    unsafe { libc::getrandom(reste.as_mut_ptr().cast::<libc::c_void>(), reste.len(), 0) }
}

/// `getentropy(2)` : tout ou rien, et pas plus de 256 octets — on demande donc
/// au plus 256, et l'on rend ce qui a été écrit, comme `getrandom` le ferait.
#[cfg(not(target_os = "linux"))]
fn tirer(reste: &mut [u8]) -> isize {
    const PAR_APPEL: usize = 256;
    let combien = reste.len().min(PAR_APPEL);
    // SAFETY: `reste` est une tranche vivante que nous possédons, et `combien`
    // ne dépasse ni sa longueur ni ce que `getentropy` accepte.
    let issue = unsafe { libc::getentropy(reste.as_mut_ptr().cast::<libc::c_void>(), combien) };
    if issue < 0 {
        return -1;
    }
    isize::try_from(combien).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{remplir, un_defi, un_identifiant};

    #[test]
    fn deux_defis_ne_se_ressemblent_pas() {
        // **C'EST TOUTE LA PROPRIÉTÉ QU'ON PEUT ÉPROUVER ICI.** La qualité du
        // CSPRNG est celle du noyau ; ce qu'on vérifie est qu'on l'appelle bien,
        // et qu'on ne rend pas deux fois la même chose.
        let un = un_defi().expect("le noyau fournit");
        let autre = un_defi().expect("le noyau fournit");
        assert_ne!(un.octets(), autre.octets());
    }

    #[test]
    fn un_defi_n_est_pas_tout_a_zero() {
        // Un tampon jamais rempli passerait le premier essai une fois sur
        // 2^256 ; celui-ci l'attrape tout de suite.
        let defi = un_defi().expect("le noyau fournit");
        assert_ne!(defi.octets(), &[0_u8; asl_cle::DEFI_OCTETS]);
    }

    #[test]
    fn deux_identifiants_ne_se_ressemblent_pas() {
        let un = un_identifiant().expect("le noyau fournit");
        let autre = un_identifiant().expect("le noyau fournit");
        assert_ne!(un, autre);
        assert_ne!(un, [0_u8; 16]);
    }

    #[test]
    fn remplir_une_tranche_vide_reussit_sans_rien_faire() {
        remplir(&mut []).expect("rien à remplir");
    }

    #[test]
    fn remplir_une_grande_tranche_la_remplit_entierement() {
        // **C'EST LA BOUCLE QU'ON ÉPROUVE ICI** : au-delà de 256 octets,
        // `getrandom` a le droit de rendre moins que demandé, et `getentropy`
        // refuse tout net.
        let mut grande = [0_u8; 4096];
        remplir(&mut grande).expect("le noyau fournit");
        let nuls = grande.iter().filter(|octet| **octet == 0).count();
        assert!(
            nuls < 200,
            "{nuls} octets nuls sur 4096 : la tranche n'a pas été remplie entièrement"
        );
    }
}
