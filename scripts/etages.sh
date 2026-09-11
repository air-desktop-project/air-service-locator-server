# etages.sh — LA classification des crates en étages. Une seule, ici.
#
# Ce fichier ne s'exécute pas : il se source.
#
#     . "$(dirname "$0")/etages.sh"
#
# # POURQUOI IL EXISTE
#
# `check-etages.sh` et `check-couverture.sh` portaient chacun sa copie de ces
# listes, avec un commentaire honnête qui annonçait le défaut : « le jour où
# elles divergeront, `check-etages` classera une crate que celui-ci ignorera ».
#
# **Ce jour est arrivé le 2026-09-09**, avec `asl-session`. `check-etages` l'a
# réclamée — il vérifie que TOUT membre du workspace est classé, et refuse
# sinon. `check-couverture`, lui, n'a rien dit : il mesure sa liste, et une
# crate absente de la liste ne manque à personne.
#
# La leçon n'est pas « il fallait fusionner plus tôt ». Elle est que **des deux
# contrôles, celui qui a tenu est celui qui savait ce qu'il devait trouver**, et
# non celui qui se contentait de vérifier ce qu'on lui donnait.
#
# # LES ÉTAGES
#
#   1. GRAMMAIRES — des octets vers des messages, et retour. Aucune socket,
#      aucun fichier, aucune horloge.
#   2. DÉCISIONS  — des machines à états. Elles reçoivent des messages et
#      l'heure ; elles n'attendent jamais.
#   3. EXÉCUTION  — les seules crates qui lisent, écrivent et attendent. Elles
#      ne décident de rien, et sont donc HORS des deux contrôles.

etage1=(asl-id asl-proto asl-api asl-registre asl-attest)

# `asl-session` EST À L'ÉTAGE 2 BIEN QU'ELLE DÉPENDE DE LA PILE HTTP/3, et c'est
# le classement qui demande le plus d'explication.
#
# Elle tire `ams-h3` et `ams-proto-http`, qui portent chacune en tête de son
# manifeste « sans entrée-sortie » : ce sont des grammaires et un conducteur,
# pas des boucles. Ce qui est interdit à cet étage, c'est ce qui ATTEND — une
# socket, un fichier, une horloge —, pas un type qui décrit une réponse.
#
# `check-etages.sh` le vérifie plutôt que de le croire : `tokio` y reste refusé.
etage2=(asl-annuaire asl-auth asl-cle asl-session)

hors=(asl-store asl-loop-tokio asl-server)
