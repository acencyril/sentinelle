# Journal des versions

Toutes les modifications notables de Sentinelle.
Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/),
versionnage [SemVer](https://semver.org/lang/fr/).

## [Non publié]

### Ajouté
- Mode `dry_run` : détecte et alerte sans jamais bloquer. À utiliser les
  premières semaines sur un site en production, pour voir ce que le bundle
  *aurait* bloqué avant de lui donner la main.
- Commande `sentinelle:verifier` : contrôle que le cache répond, que le mailer
  est joignable, que la liste blanche n'est pas vide et que les tables existent.
- Recette Flex : crée les deux fichiers de configuration à l'installation.

## [0.1.1] — 2026-08-31

### Modifié
- Accroche des deux README alignée sur la description du paquet.
- Capture du tableau de bord ajoutée.
- README anglais par défaut, français en `README.fr.md`. *Packagist affiche
  `README.md`, et l'écosystème PHP est anglophone.*

## [0.1.0] — 2026-08-31

Première version publiée, après une mise au point complète en conditions
réelles. Six défauts d'intégration ont été corrigés avant publication — tous du
même genre : du code juste, mal raccordé.

### Corrigé avant publication
- `Bundle` au lieu de `AbstractBundle` : ce dernier porte sa configuration
  lui-même et **ignore en silence** toute classe d'extension écrite à côté. Le
  bundle se chargeait avec un arbre de configuration vide.
- `getPath()` : sans lui, `@SentinelleBundle/config/…` pointe sur `src/config/`.
- Un `use` resté sur l'ancien namespace après extraction, provoquant une
  `ClassNotFoundError` à chaque requête — et pas une ligne journalisée.
- Le contrôleur n'hérite plus d'`AbstractController`, qui attend un conteneur
  restreint construit par autoconfiguration — mécanisme désactivé dans un bundle
  où l'on déclare tout à la main. Les dépendances sont injectées explicitement.
- Filtre du journal : `tout` et `all` désignaient la même chose sans se
  connaître, séquelle d'une traduction partielle.
- Le motif détecté et la requête sont affichés dans le journal. Sans eux, deux
  tentatives d'exploitation apparaissaient comme deux lignes identiques.

### Fonctionnalités
- Journalisation de toutes les requêtes sur `kernel.terminate`.
- Détection : exécution de code, injection SQL, traversée de répertoire,
  Log4Shell, désérialisation ; sondes ; force brute.
- Blocage progressif : 24 h, 7 jours, puis définitif.
- **Refus de bloquer un prestataire critique**, automatiquement et manuellement.
- Alerte par courriel, au plus une par adresse et par heure.
- Tableau de bord avec DNS inverse sous chaque adresse.
- Commande `sentinelle:purger`.
