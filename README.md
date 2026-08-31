# Sentinelle

Un bundle Symfony qui **journalise les visites, reconnaît les attaques, bloque les
adresses fautives et vous prévient** — sans jamais bloquer un prestataire dont
votre site dépend.

*English documentation: [README.en.md](README.en.md)*

```bash
composer require acencyril/sentinelle-bundle
```

---

## Le problème

Un site en production reçoit des sondes en permanence. Des scanners cherchent
`/.env`, `/wp-login.php`, `/.git/config`. D'autres tentent des injections SQL,
des traversées de répertoire, du Log4Shell. La plupart n'aboutissent à rien —
mais on ne le sait qu'après coup, et seulement si on regarde.

Les réponses habituelles ont chacune leur défaut. Lire les journaux du serveur
web : personne ne le fait tous les jours. `fail2ban` : il travaille sur les
fichiers de log, hors de l'application, et ne sait rien de vos routes ni de vos
utilisateurs. Un pare-feu applicatif hébergé : il voit tout votre trafic, et il
coûte.

Sentinelle fait le travail **dans l'application**, où l'on sait qui est
authentifié, quelle route a répondu, et quel code HTTP est sorti.

---

## Ce qu'il fait

**Il enregistre tout**, pas seulement les attaques. Une tentative ne se reconnaît
pas seule : elle se reconnaît par contraste avec le trafic ordinaire. Sans les
pages vues, on n'a plus qu'une liste d'alarmes sans échelle, et l'on ne sait pas
si trois 404 sont un scan ou un lien mort.

**Il qualifie chaque requête** — page vue, page introuvable, accès refusé, sonde,
tentative d'exploitation — à partir du chemin, des paramètres et du code de
réponse.

**Il bloque tout seul**, progressivement : 24 heures à la première récidive, 7
jours à la deuxième, définitif à la troisième. Les blocages expirent, et c'est
volontaire.

**Il prévient par courriel**, une fois par adresse et par heure au maximum.

**Et il refuse de bloquer ce dont vous dépendez.** C'est la pièce qui manque
partout ailleurs, et celle qui justifie ce bundle.

---

## Pourquoi ce dernier point compte

Ce bundle est né d'un incident. Une adresse est apparue dans le tableau de bord,
signalée comme suspecte après une erreur 401. Elle a été bloquée à la main, d'un
clic. C'était un serveur de Mailgun : **toute la réception de courriel du site
serait morte en silence**, et personne ne l'aurait su avant des heures.

Le 401 venait d'une clé de signature qui n'était pas encore arrivée dans
l'environnement du conteneur. Un incident de configuration, pas une attaque.

D'où trois garde-fous que Sentinelle applique :

**Chaque adresse porte le nom de son propriétaire**, résolu par DNS inverse.
Vous ne décidez plus devant une suite de chiffres.

**Les prestataires critiques sont refusés au blocage**, automatique *et* manuel.
Le bouton ne fonctionne pas, et il vous dit pourquoi.

**Certains chemins ne déclenchent jamais de blocage.** Un webhook qui répond 401
le temps qu'une clé arrive ne doit pas faire bannir celui qui l'appelle.

> Une protection qui casse une fonction du site protège moins qu'elle ne détruit.

---

## Installation

### 1. Enregistrer le bundle

```php
// config/bundles.php
return [
    // …
    Acencyril\SentinelleBundle\SentinelleBundle::class => ['all' => true],
];
```

### 2. Configurer

```yaml
# config/packages/sentinelle.yaml
sentinelle:
    alerte:
        destinataire: '%env(SENTINELLE_ALERTE_EMAIL)%'
        expediteur:   'no-reply@mon-site.fr'
        nom_du_site:  'Mon Site'

    acces:
        role:           ROLE_ADMIN
        gabarit_parent: 'base.html.twig'
        route_retour:   'tableau_de_bord'

    jamais_bloquer:
        # ⚠ À REMPLIR AVANT LA MISE EN PRODUCTION.
        # Au minimum votre propre adresse de sortie : sans elle, une fausse
        # manœuvre vous ferme la porte de votre propre site.
        ips: '%env(default::SENTINELLE_ALLOWLIST)%'

        # Vos webhooks. Un 401 y est un incident de configuration, pas une attaque.
        chemins: ['/api/webhook/', '/stripe/callback']

        # Vos prestataires, en plus de ceux du bundle.
        prestataires: ['.mon-prestataire-signature.com', '.mon-cdn.net']
```

### 3. Les routes

```yaml
# config/routes/sentinelle.yaml
sentinelle:
    resource: '@SentinelleBundle/config/routes.php'
    type: php
```

### 4. Le schéma

```bash
php bin/console doctrine:migrations:diff
php bin/console doctrine:migrations:migrate
```

Deux tables : `sentinelle_visite` et `sentinelle_ip_bloquee`.

### 5. La purge

Sans elle, la table grossit sans fin **et les récidives ne se réinitialisent
jamais** : une adresse bloquée il y a six mois repasse directement en deuxième
récidive au premier scan.

```
0 4 * * *  php /chemin/bin/console sentinelle:purger
```

---

## Le tableau de bord

`/admin/activite` — préfixe et rôle configurables.

Le journal des requêtes, filtrable sur les seules lignes suspectes. Les adresses
bloquées, avec leur motif, leur nombre de récidives et le décompte des requêtes
refusées depuis. Les adresses les plus actives sur sept jours. Et sous chacune,
**le nom de son propriétaire** quand le DNS inverse le donne.

Le blocage manuel est permanent par défaut : une adresse qu'on bloque à la main
est un choix délibéré, pas une détection.

---

## Ce qu'il détecte

**Critique — bloque et alerte immédiatement.** Exécution de code (`php://input`,
`system(`), injection SQL (`UNION SELECT`, `OR 1=1`), traversée de répertoire,
Log4Shell (`${jndi:`), désérialisation PHP.

**Sondes — alertent en rafale.** Fichiers sensibles (`.env`, `.sql`, `.pem`),
répertoires de configuration (`/.git`, `/.aws`, `/.ssh`), chemins WordPress et
phpMyAdmin, injections de script. Une sonde isolée est du bruit ; quinze en dix
minutes sont un scan.

**Force brute.** Dix refus d'accès en dix minutes.

Vous pouvez **ajouter** vos propres motifs. Vous ne pouvez pas retirer ceux du
bundle : *ce qu'on rend configurable, on le rend désactivable par mégarde*, et
personne ne veut découvrir après coup que son installation avait la détection
Log4Shell désactivée.

---

## Trois décisions qui méritent d'être expliquées

### La journalisation ne coûte rien au visiteur

Elle se fait sur `kernel.terminate`, après l'envoi de la réponse. C'est aussi le
seul moment où le code HTTP est connu.

### Le blocage passe avant le routeur

L'écouteur est branché en priorité **300**, avant le routeur (32) et le pare-feu
(8). Une adresse bannie ne consomme ni résolution de route, ni session, ni
requête en base. Elle reçoit un 403 nu, sans page d'erreur : répondre en détail à
un scanner lui apprend seulement ce qu'il a déclenché.

### Le quota anti-flood coupe l'écriture, pas le comptage

Un scan de 155 requêtes en 16 secondes ne doit pas produire 155 lignes. Mais le
quota ne bloque **que** l'insertion : les compteurs continuent. Sinon le seuil de
rafale, fixé à 15, ne serait jamais atteint après 5 sondes, et le mécanisme
d'alerte s'auto-neutraliserait au moment précis où il devient utile.

C'est le genre de piège qu'on ne voit qu'après l'avoir vécu.

---

## Ce qu'il ne fait pas

**Il n'inspecte pas le corps des requêtes** — coûteux, et souvent des données
personnelles qu'on ne veut pas stocker. Seuls le chemin et les paramètres d'URL
sont examinés.

**Il ne remplace pas votre serveur web.** Les sondes les plus grossières sont
mieux arrêtées en amont, avant d'atteindre PHP.

**Il ne vous protège pas d'une faille applicative.** Il vous prévient qu'on la
cherche.

**Il masque les secrets avant écriture.** Un paramètre `?token=…` est enregistré
`token=***` : sans cela, chaque appel légitime écrirait un secret en clair dans
une table consultable depuis l'interface d'administration.

---

## Quand ça se dégrade

Toutes les défaillances vont dans le même sens : **laisser passer plutôt que tout
refuser**.

Cache indisponible, base injoignable, échec d'écriture, mail non parti — la
requête continue et l'erreur part dans les journaux. Un blocage raté est moins
grave qu'un site qui refuse tout le monde.

---

## Licence

MIT.

## Contribuer

Les motifs de détection et la liste des prestataires connus s'améliorent par
l'usage. Si votre prestataire manque à la liste par défaut, ou si vous rencontrez
un motif d'attaque non couvert, ouvrez une issue — c'est exactement le genre de
connaissance qui gagne à être mise en commun.
