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
//! # Ce qui reste à trancher
//!
//! - Quelle attestation matérielle exiger, et quel est le repli quand elle
//!   manque : refus, ou compte dégradé ?
//! - Un daemon ne fait pas de biométrie. Par quoi s'authentifie-t-il, et
//!   comment ce secret arrive-t-il sur la machine ?
//! - La perte d'un appareil : que révoque-t-on, et qui peut le faire ?
//!
//! # État
//!
//! Vide.
