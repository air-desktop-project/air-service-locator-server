//! Ce qui autorise : jetons, portées, et le lien entre une session et l'appareil
//! qui l'a ouverte.
//!
//! # La contrainte du produit, énoncée là où elle s'applique
//!
//! Les applications mobiles ne s'installent que sur des appareils capables de
//! confirmer localement l'identité de leur porteur — Face ID, Touch ID, ou leur
//! équivalent Android. **Cette vérification a lieu SUR L'APPAREIL, et le serveur
//! ne la voit jamais.** Aucune empreinte, aucun gabarit facial ne traverse le
//! réseau ; ces données ne quittent pas l'enclave sécurisée du téléphone, et le
//! système d'exploitation ne les rend pas.
//!
//! Ce que le serveur peut donc constater n'est PAS « cet humain est bien lui »,
//! mais « cette requête est signée par une clé qui vit dans le matériel
//! sécurisé d'un appareil enrôlé, et que cet appareil n'a débloquée qu'après
//! une confirmation biométrique ». La nuance n'est pas rhétorique : elle dit
//! exactement ce que le protocole doit transporter — une signature et une
//! attestation, pas un résultat de comparaison.
//!
//! Confondre les deux mènerait à un serveur qui croit vérifier une identité
//! alors qu'il fait confiance à un booléen envoyé par le client.
//!
//! # Ce qui est arrêté par `docs/protocole.md` §2 et `docs/modele.md` §2
//!
//! - **L'attestation manquante ou en échec fait REFUSER** en v1, et c'est
//!   journalisé. Un refus se relâche plus tard ; une acceptation ne se resserre
//!   jamais sans casser des comptes déjà ouverts.
//! - **Un daemon ne fait pas de biométrie.** Il porte le *secret d'annonce* de
//!   sa machine, posé par l'application mobile à la déclaration et montré une
//!   seule fois. Il est par MACHINE et non par daemon — l'énoncé du produit veut
//!   qu'un daemon quelconque puisse s'annoncer sans avoir été déclaré d'avance.
//!   Le prix : tout daemon de cette machine peut s'annoncer sous n'importe quel
//!   nom, et pas au-delà.
//! - **Un appareil ne peut pas se révoquer lui-même.** Sinon un téléphone volé
//!   et déverrouillé révoque les autres et confisque le compte.
//!
//! # Les comparaisons se font en temps constant (contrainte C9)
//!
//! Une clé inconnue et un service inexistant rendent la même réponse après le
//! même délai. L'annuaire sait où écoutent des services qui ne publient pas leur
//! port : un écart de temps de réponse dit à un inconnu qu'une machine existe,
//! et c'est tout ce qu'il cherchait.
//!
//! # État
//!
//! Vide. Spécifié, pas écrit.
