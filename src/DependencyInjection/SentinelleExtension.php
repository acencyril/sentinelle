<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;

/**
 * Traduit la configuration du projet en paramètres du conteneur.
 *
 * ⚠ ON AJOUTE, ON NE REMPLACE PAS. Les motifs critiques et les prestataires
 * protégés que le projet déclare sont FUSIONNÉS avec ceux du bundle, jamais
 * substitués. Un projet peut protéger son propre webhook ; il ne peut pas
 * retirer la détection Log4Shell en croyant simplement adapter sa
 * configuration.
 */
class SentinelleExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container): void
    {
        $config = $this->processConfiguration(new Configuration(), $configs);
        if (empty($config['alert']['recipient'])) {
            throw new \InvalidArgumentException(
                'Sentinelle : « sentinelle.alert.recipient » est absent. '
                .'Sans destinataire, le bundle détecte sans prévenir personne. '
                .'Crée config/packages/sentinelle.yaml — voir '
                .'https://github.com/acencyril/sentinelle-bundle#installation'
            );
        }
        $loader = new PhpFileLoader($container, new FileLocator(\dirname(__DIR__, 2).'/config'));
        $loader->load('services.php');

        foreach ([
            'sentinelle.alert.recipient'   => $config['alert']['recipient'],
            'sentinelle.alert.sender'     => $config['alert']['sender'],
            'sentinelle.alert.sender_name' => $config['alert']['sender_name'],
            'sentinelle.alert.site_name'    => $config['alert']['site_name'],
            'sentinelle.alert.cooldown'          => $config['alert']['cooldown'],

            'sentinelle.access.role'            => $config['access']['role'],
            'sentinelle.access.prefix'         => $config['access']['prefix'],
            'sentinelle.access.parent_template'  => $config['access']['parent_template'],
            'sentinelle.access.back_route'    => $config['access']['back_route'],

            'sentinelle.thresholds'                => $config['thresholds'],
            'sentinelle.dry_run'                 => $config['dry_run'],

            'sentinelle.allowlist'             => $config['never_block']['ips'],
            'sentinelle.exempt_paths'      => $config['never_block']['paths'],
            // fusionnés, jamais substitués — voir la remarque en tête de classe
            'sentinelle.extra_providers'      => $config['never_block']['providers'],
            'sentinelle.extra_patterns'            => $config['critical_patterns'],
            'sentinelle.extra_ignored'           => $config['ignore'],
        ] as $nom => $valeur) {
            $container->setParameter($nom, $valeur);
        }
    }

    public function getAlias(): string
    {
        return 'sentinelle';
    }
}
