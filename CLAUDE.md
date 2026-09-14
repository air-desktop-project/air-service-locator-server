# air-service-locator-server — consignes de travail

Ce fichier porte ce qui ne se déduit ni du code ni des documents : les règles
que toute contribution suit. Le reste est dans `README.md` (les barrières,
l'installation) et `docs/` (le modèle, le protocole, les contraintes).

## La version

**Chaque PR change la version semver (`MAJOR.MINOR.PATCH`) de l'application,
dans le commit qui porte le changement ; une PR qui ne change pas la version ne
se merge pas.**

- La version vit à UN endroit : `[workspace.package] version` dans `Cargo.toml`.
  Toutes les crates la partagent (`version.workspace = true`), et les arêtes
  internes de `[workspace.dependencies]` la répètent — en lockstep.
- Le cran est un jugement sur le changement : un ajout compatible est mineur
  (`0.1.0 → 0.2.0`), une correction est un patch, une rupture de protocole ou
  de format d'enregistrement est majeure. La revue le porte ; la barrière ne
  juge que le fait qu'elle ait bougé, et dans le bon sens.
- La règle vaut pour TOUTE PR, documentation comprise : un lecteur qui tient
  une version doit pouvoir retrouver ce qu'elle décrit.
- Après le bump : `cargo update --workspace --offline` dans le dépôt ET dans
  `fuzz/`, pour que les deux verrous suivent — `--locked` le refuserait sinon.
- `scripts/check-version.sh` tient tout cela, et la CI le lance sur chaque
  pull request. `asl-server --version` dit la version et le commit du binaire ;
  `GET /v1/version` la rend à qui interroge l'annuaire.
- **Ce qui est exempté, et c'est tranché (Thierry, 2026-09-14) : les notes de
  coordination.** Elles vont sur `main` en commit direct, sans PR ni bump —
  ici, ce fichier n'en porte pas encore ; côté client, c'est la section « Ce
  que l'autre session attend » de son `CLAUDE.md` et ses réponses. **Tout ce
  qui touche au code, aux spécifications (`docs/`), à la CI ou aux scripts
  passe par PR et change la version.**
