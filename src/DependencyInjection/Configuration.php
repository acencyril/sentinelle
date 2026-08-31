<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * Ce qu'un projet peut régler, et ce qu'il ne peut pas.
 *
 * ⚠ LES MOTIFS D'ATTAQUE SONT EXTENSIBLES, JAMAIS SUBSTITUABLES. Un projet peut
 * AJOUTER ses propres motifs et ses propres prestataires à protéger ; il ne peut
 * pas retirer ceux du bundle. Sinon on obtient une installation qui a désactivé
 * la détection Log4Shell sans que personne ne s'en aperçoive, en croyant
 * simplement « adapter la configuration à son projet ».
 *
 * *Ce qu'on rend configurable, on le rend désactivable par mégarde.*
 */
class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $arbre = new TreeBuilder('sentinelle');

        $arbre->getRootNode()
            ->children()
                ->arrayNode('alerte')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('destinataire')->isRequired()
                            ->info('À qui partent les alertes. Sans destinataire, le bundle détecte sans prévenir.')
                        ->end()
                        ->scalarNode('expediteur')->defaultValue('no-reply@localhost')->end()
                        ->scalarNode('nom_expediteur')->defaultValue('Sentinelle')->end()
                        ->scalarNode('nom_du_site')->defaultValue('le site')
                            ->info('Apparaît dans le sujet : « Alerte sécurité <nom> ».')
                        ->end()
                        ->integerNode('repit')->defaultValue(3600)
                            ->info("Secondes entre deux alertes pour une même IP. Un mail par attaque noie l'information dès le premier scan sérieux.")
                        ->end()
                    ->end()
                ->end()

                ->arrayNode('acces')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('role')->defaultValue('ROLE_ADMIN')->end()
                        ->scalarNode('prefixe')->defaultValue('/admin/activite')->end()
                        ->scalarNode('gabarit_parent')->defaultValue('base.html.twig')->end()
                        ->scalarNode('route_retour')->defaultNull()
                            ->info('Route du bouton de retour. Null : pas de bouton.')
                        ->end()
                    ->end()
                ->end()

                ->booleanNode('essai')
                    ->defaultFalse()
                    ->info("Mode d'essai : détecte, alerte et journalise, mais ne bloque JAMAIS. "
                          ."À laisser actif les premières semaines sur un site en production — "
                          ."on veut voir ce que le bundle AURAIT bloqué avant de lui donner la main.")
                ->end()

                ->arrayNode('seuils')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->integerNode('rafale')->defaultValue(15)->end()
                        ->integerNode('rafale_fenetre')->defaultValue(600)->end()
                        ->integerNode('bruteforce')->defaultValue(10)->end()
                        ->integerNode('bruteforce_fenetre')->defaultValue(600)->end()
                        ->integerNode('flood_max')->defaultValue(5)
                            ->info("Lignes d'erreur par IP et par fenêtre. Au-delà on cesse d'écrire, mais on continue de COMPTER — sinon le seuil de rafale ne serait jamais atteint et l'alerte s'auto-neutraliserait.")
                        ->end()
                        ->integerNode('flood_fenetre')->defaultValue(3600)->end()
                    ->end()
                ->end()

                ->arrayNode('jamais_bloquer')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('ips')->defaultNull()
                            ->info('IP ou CIDR séparés par des virgules. Y mettre au minimum ta propre IP de sortie.')
                        ->end()
                        ->arrayNode('chemins')
                            ->scalarPrototype()->end()
                            ->defaultValue(['/api/webhook/'])
                            ->info("Chemins dont les refus ne déclenchent jamais de blocage. Un webhook qui répond 401 le temps qu'une clé arrive ferait bannir le prestataire.")
                        ->end()
                        ->arrayNode('prestataires')
                            ->scalarPrototype()->end()
                            ->defaultValue([])
                            ->info('Suffixes de reverse DNS AJOUTÉS à ceux du bundle. Le blocage y est refusé, même à la main.')
                        ->end()
                    ->end()
                ->end()

                ->arrayNode('motifs_critiques')
                    ->useAttributeAsKey('nom')
                    ->scalarPrototype()->end()
                    ->defaultValue([])
                    ->info("Expressions régulières AJOUTÉES à celles du bundle. On n'en retire jamais.")
                ->end()

                ->arrayNode('ignorer')
                    ->scalarPrototype()->end()
                    ->defaultValue([])
                    ->info('Préfixes jamais journalisés, en plus de ceux du bundle.')
                ->end()
            ->end();

        return $arbre;
    }
}
