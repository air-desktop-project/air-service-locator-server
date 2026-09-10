# Le banc de NAT — combien de temps un daemon peut-il se taire

## La question

`modele.md` §4.1 pose un keepalive de **15 s** et une inactivité de **45 s**.
Ces deux nombres n'ont jamais été mesurés : ils ont été posés au doigt, et le
document le dit. Ce banc les confronte à un vrai lien résidentiel.

**Ce qu'il mesure est le sens ENTRANT**, et lui seul. Un datagramme SORTANT passe
toujours — il crée un mappage au passage —, donc vérifier qu'il arrive ne dit
rien d'un NAT. Ce qui casse est le retour : la poussée de verdict que
`protocole.md` §1.4 fait voyager sur la connexion tenue, et qui part de
l'annuaire vers un daemon qui n'a rien demandé depuis un moment.

## Comment

```sh
# sur l'annuaire
python3 repondeur.py

# sur la machine qu'on éprouve
python3 sondeur.py nitrogen.air-desktop.org --famille 4 --delais 16,18,20,22,24,26,28,30
```

Le sondeur demande à être rappelé dans N secondes, puis **se tait**. Une seule
socket par délai, toutes lancées ensemble : un mappage mort ne se répare pas, et
tout ce qui repasserait par la même socket en créerait un neuf.

**Il n'emploie pas la vraie pile**, et c'est délibéré : `asl-client-tokio`
annonce soixante secondes d'inactivité, et QUIC ferme au plus court des deux
bouts. Mesurer avec elle plafonnerait à ce que NOUS avons décidé. Ce banc mesure
le réseau ; les minuteries du produit se choisissent ENSUITE, contre son nombre.

## Ce qui a été mesuré

**2026-09-10, lien résidentiel Free (Livebox), vers `nitrogen.air-desktop.org`.**

| Silence | IPv4 (derrière NAT) | IPv6 (adresse globale, pas de NAT) |
|---|---|---|
| 16 s | tenu | tenu |
| 18 s | tenu | tenu |
| 20 s | tenu | tenu |
| 22 s | tenu | tenu |
| 24 s | tenu | tenu |
| 26 s | tenu | tenu |
| 28 s | **tenu** | **tenu** |
| 30 s | **perdu** | **perdu** |
| 45 s et au-delà, jusqu'à 420 s | perdu | perdu |

**LE CHIFFRE EST LE MÊME EN IPv4 ET EN IPv6**, et c'est le résultat le plus
instructif : ce n'est donc PAS la traduction d'adresses qui borne, c'est le
**pare-feu à état** de la box. Passer en IPv6 ne dispense de rien.

Trente secondes est la valeur par défaut de `nf_conntrack_udp_timeout` sous
Linux, ce qu'est très probablement cette box.

**L'échauffement ne change rien.** La mesure a été refaite en établissant
d'abord un aller-retour, pour distinguer un flux « jamais répondu » d'un flux
établi — Linux les traite différemment (30 s contre 120 s). Le résultat est
identique : cette box ne promeut pas ses flux UDP.

## Ce que cela veut dire, et ce qu'il reste à décider

**Le keepalive de 15 s tient**, avec une marge d'un facteur deux. Mais elle est
plus mince qu'elle n'en a l'air : **un seul keepalive perdu fait 30 s de
silence**, c'est-à-dire exactement la borne. Sur un lien qui perd un paquet de
temps en temps, l'annonce tombera régulièrement sans que rien n'ait mal tourné.

**L'inactivité de 45 s, elle, n'est pas atteignable.** Le chemin meurt à 30 s :
une connexion ne peut jamais rester inactive quarante-cinq secondes puis
reprendre. Ce nombre promet une tolérance que le réseau ne rend pas.

Ce que la mesure suggère :

- **un keepalive de 10 s**, qui laisse perdre DEUX keepalives d'affilée avant
  d'atteindre la borne ;
- **une inactivité alignée sur la durée de vie observée**, et non au-delà.

**Ces deux changements ne sont pas faits.** Une décision de produit ne se prend
pas sur un échantillon de UN — cette box-ci, ce soir-là. Il faut d'autres liens :
un autre opérateur, un partage de connexion mobile (les NAT des opérateurs
mobiles sont les plus courts, souvent 20 à 30 s), un réseau d'entreprise. Le banc
est là pour qu'on puisse les ajouter, et ce tableau pour qu'on les compare.

## Ce que le banc a trouvé d'autre

En le montant, la vraie cliente a parlé au vrai serveur pour la première fois —
et **rien ne s'est connecté**. Les essais des deux côtés emploient chacun leur
doublure, et la paire n'avait jamais été mise face à face. Le défaut est décrit
dans le commit `fix(quic): un ClientHello en deux paquets montait deux
connexions`.
