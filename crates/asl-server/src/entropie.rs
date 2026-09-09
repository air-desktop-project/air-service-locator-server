//! D'où viennent les défis.
//!
//! # `getrandom(2)`, ET NON UN GÉNÉRATEUR À NOUS
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
//! # LA BOUCLE N'EST PAS DE LA PRUDENCE DÉCORATIVE
//!
//! `getrandom(2)` peut rendre MOINS d'octets qu'on n'en demande, et peut échouer
//! avec `EINTR` si un signal arrive. Prendre le premier retour pour argent
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

/// Remplit ces octets depuis le noyau, entièrement.
fn remplir(quoi: &mut [u8]) -> io::Result<()> {
    let mut ecrits = 0_usize;
    while ecrits < quoi.len() {
        let reste = quoi.get_mut(ecrits..).unwrap_or_default();
        // SAFETY: `reste` est une tranche vivante que nous possédons, et la
        // longueur passée est exactement la sienne. `getrandom` n'écrit rien
        // au-delà.
        let combien =
            unsafe { libc::getrandom(reste.as_mut_ptr().cast::<libc::c_void>(), reste.len(), 0) };
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

#[cfg(test)]
mod tests {
    use super::{remplir, un_defi};

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
    fn remplir_une_tranche_vide_reussit_sans_rien_faire() {
        remplir(&mut []).expect("rien à remplir");
    }

    #[test]
    fn remplir_une_grande_tranche_la_remplit_entierement() {
        // **C'EST LA BOUCLE QU'ON ÉPROUVE ICI** : au-delà de 256 octets,
        // `getrandom` a le droit de rendre moins que demandé.
        let mut grande = [0_u8; 4096];
        remplir(&mut grande).expect("le noyau fournit");
        let nuls = grande.iter().filter(|octet| **octet == 0).count();
        assert!(
            nuls < 200,
            "{nuls} octets nuls sur 4096 : la tranche n'a pas été remplie entièrement"
        );
    }
}
