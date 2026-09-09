//! Le refus de tourner en root (C8).
//!
//! # POURQUOI UN ANNUAIRE N'A AUCUNE RAISON D'ÊTRE ROOT
//!
//! Il écoute sur un port **au-dessus de 1024** ([`asl_proto::PORT_PAR_DEFAUT`]),
//! écrit dans un seul fichier, et ne touche à rien d'autre. La seule raison
//! historique d'être root — se lier à un port privilégié — n'existe donc pas
//! ici, et le choix du port par défaut a été fait en partie pour cela.
//!
//! # CE QUE LE REFUS ACHÈTE, ET CE QU'IL N'ACHÈTE PAS
//!
//! Il n'empêche aucune faille. Il **borne ce qu'une faille obtient** : une
//! exécution de code arbitraire dans un processus non privilégié ne peut ni
//! lire `/etc/shadow`, ni charger un module, ni écrire ailleurs que là où le
//! compte de service a le droit d'écrire.
//!
//! **Et il refuse plutôt que d'abandonner ses privilèges.** Un service qui
//! démarre en root puis fait `setuid` garde des descripteurs ouverts sous
//! privilège, et l'abandon lui-même est un endroit où l'on se trompe — l'ordre
//! de `setgid` et `setuid`, les groupes supplémentaires, les capacités
//! résiduelles. Refuser de démarrer n'a aucun de ces pièges.
//!
//! # LA DÉCISION EST PURE, L'APPEL SYSTÈME NE L'EST PAS
//!
//! [`interdit`] ne fait rien d'autre que comparer un nombre : elle est
//! éprouvable sans être root, ce qu'aucun essai de ce dépôt ne peut être.
//! [`refuser_root`] lit l'identifiant effectif et lui pose la question.

/// Ce qui empêche de démarrer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EstRoot {
    /// L'identifiant effectif trouvé.
    pub euid: u32,
}

impl core::fmt::Display for EstRoot {
    fn fmt(&self, sortie: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            sortie,
            "cet annuaire refuse de tourner en root (euid {}). Il écoute au-dessus \
             de 1024 et n'a besoin d'aucun privilège : lancez-le sous un compte \
             de service.",
            self.euid
        )
    }
}

impl std::error::Error for EstRoot {}

/// Cet identifiant effectif interdit-il de démarrer ?
///
/// **ZÉRO, ET RIEN D'AUTRE.** On ne refuse pas « les identifiants bas » : sur un
/// système donné, `1` ou `999` peuvent être des comptes de service parfaitement
/// ordinaires, et les refuser empêcherait un déploiement légitime pour une
/// raison que personne ne devinerait.
#[must_use]
pub const fn interdit(euid: u32) -> bool {
    euid == 0
}

/// Refuse de continuer si ce processus est root.
///
/// # Errors
///
/// [`EstRoot`] si l'identifiant effectif est zéro.
pub fn refuser_root() -> Result<(), EstRoot> {
    // SAFETY: `geteuid` ne prend aucun paramètre, ne peut pas échouer, et ne
    // touche à aucune mémoire que nous possédons. POSIX la déclare toujours
    // réussie.
    let euid = unsafe { libc::geteuid() };
    if interdit(euid) {
        return Err(EstRoot { euid });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{EstRoot, interdit, refuser_root};

    #[test]
    fn zero_est_interdit() {
        assert!(interdit(0));
    }

    #[test]
    fn aucun_autre_identifiant_ne_l_est() {
        // **PAS DE SEUIL**, et c'est le sujet de cet essai : `1` et `999` sont
        // des comptes de service ordinaires sur bien des systèmes.
        for euid in [1_u32, 2, 100, 999, 1000, 65_534, u32::MAX] {
            assert!(!interdit(euid), "{euid} a été refusé à tort");
        }
    }

    #[test]
    fn le_refus_dit_quoi_faire_et_pas_seulement_non() {
        // Un message qui dit « refusé » sans dire comment s'y prendre fait
        // chercher dans le code ce qui aurait dû être dans la sortie.
        let dit = alloc::format!("{}", EstRoot { euid: 0 });
        assert!(dit.contains("compte de service"), "{dit}");
        assert!(dit.contains("1024"), "{dit}");
    }

    #[test]
    fn ce_processus_ci_n_est_pas_root() {
        // **CET ESSAI VÉRIFIE LE BANC AUTANT QUE LE CODE.** S'il échoue, c'est
        // que les essais tournent en root — et il faut alors corriger cela, pas
        // l'essai.
        assert_eq!(refuser_root(), Ok(()), "les essais tournent en root");
    }

    extern crate alloc;
}
