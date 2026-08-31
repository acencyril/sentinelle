# Contribuer

## ⚠ Les commentaires ne sont pas du bruit

C'est la seule règle qui compte vraiment ici.

Chaque garde-fou de ce code vient d'un incident réel, et le commentaire qui
l'accompagne explique **pourquoi** il existe. Les supprimer lors d'un
« nettoyage » revient à effacer la mémoire du projet : le prochain à toucher au
blocage automatique refera l'erreur qu'on a déjà payée.

Trois exemples de ce qui ne doit pas disparaître :

- pourquoi le quota anti-flood coupe l'écriture **mais pas le comptage** ;
- pourquoi `isProtectedProvider()` n'est appelé que depuis `block()` ;
- pourquoi une requête déjà refusée reçoit son propre type d'événement.

Chacun de ces trois est un piège dans lequel on est tombé.

## Mettre en place

```bash
git clone https://github.com/acencyril/sentinelle-bundle
cd sentinelle-bundle
composer install
```

Pour l'éprouver dans une application, un dépôt local évite les allers-retours
par GitHub :

```json
{ "repositories": [ { "type": "path", "url": "../sentinelle-bundle" } ] }
```

```bash
composer require acencyril/sentinelle-bundle:@dev
```

Composer pose un lien symbolique : vos modifications sont prises en compte
immédiatement.

## Avant une pull request

```bash
find src -name "*.php" -exec php -l {} \;
composer validate --strict
```

⚠ `php -l` ne suffit pas. Les six défauts corrigés avant la première publication
étaient tous syntaxiquement corrects — c'est le **montage** qui ne l'était pas.
Faites tourner le bundle dans une vraie application avant de proposer une
modification touchant à la configuration ou aux services.

## Ce qui est particulièrement bienvenu

**Des prestataires manquants.** La liste de `IpIdentifier` ne contient que les
plus répandus. Si le vôtre manque, c'est exactement le genre de connaissance qui
gagne à être mise en commun — et une pull request d'une ligne.

**Des motifs d'attaque non couverts**, avec l'URL réelle qui les a déclenchés.

**Des faux positifs.** Si Sentinelle a qualifié d'attaque une requête légitime,
c'est un défaut sérieux : dites-le, avec le chemin exact.

## Ce qui ne sera pas retenu

Rendre configurables les motifs de détection **au point de pouvoir en retirer**.
On peut en ajouter, jamais en enlever : *ce qu'on rend configurable, on le rend
désactivable par mégarde*, et personne ne veut découvrir après coup que son
installation avait la détection Log4Shell éteinte.
