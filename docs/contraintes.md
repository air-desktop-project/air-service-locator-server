# Contraintes — À ÉCRIRE

Ce document devra énoncer les règles que le découpage du workspace tient, et
qu'un contrôle automatique peut faire respecter. Sur `air-mail-server`, ce sont
les `C1`…`C14` que `Cargo.toml` cite par leur numéro et que `scripts/check-*.sh`
éprouvent.

**Rien n'est arrêté ici.** Ce qui suit est la liste des questions, pas des
réponses.

## Les candidates évidentes, héritées d'`air-mail-server`

Elles ne sont PAS reprises par principe : chacune coûte quelque chose, et ce
dépôt n'a pas les mêmes enjeux qu'un serveur de courrier exposé à l'Internet
hostile depuis quarante ans.

- **Sans entrée-sortie aux étages 1 et 2.** La seule qui soit déjà appliquée : le
  découpage en crates la suppose (`Cargo.toml`). Elle appelle un
  `check-etages.sh`, qui n'existe pas encore.
- **100 % de couverture sur les étages 1 et 2.** À confirmer. Le gate n'a de sens
  qu'avec du code à mesurer ; posé sur un workspace vide, il rend 100 % et
  n'atteste de rien.
- **Aucune ligne de C.** À trancher, et la réponse dépend de la persistance : un
  SQLite lie du C, un magasin écrit ici n'en lie pas.
- **Refus de démarrer en root.**
- **Fuzz des décodeurs.** Dès qu'`asl-proto` décodera quoi que ce soit : les
  octets viennent d'un inconnu.

## Les contraintes propres à CE produit

- **`asl-client` est embarqué par du code tiers.** Son graphe de dépendances est
  un engagement envers des gens qu'on ne connaît pas. Quelle borne se donne-t-on,
  et quel contrôle la fait respecter ?
- **L'annuaire est une cible de reconnaissance.** Il sait où écoutent des
  services qui, précisément, ne publient pas leur port. Qui a le droit de
  demander quoi, et que voit un inconnu ?
- **La biométrie ne quitte pas l'appareil, et le serveur ne la voit jamais.**
  Ce que le serveur constate est une signature matérielle, pas une identité (cf.
  `crates/asl-auth/src/lib.rs`). La contrainte est de ne jamais écrire de code
  qui suppose le contraire.
