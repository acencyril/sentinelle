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
    public function load(array $configs, ContainerBuilder $conteneur): void
    {
        $config = $this->processConfiguration(new Configuration(), $configs);

        $chargeur = new PhpFileLoader($conteneur, new FileLocator(\dirname(__DIR__, 2).'/config'));
        $chargeur->load('services.php');

        foreach ([
            'sentinelle.alerte.destinataire'   => $config['alerte']['destinataire'],
            'sentinelle.alerte.expediteur'     => $config['alerte']['expediteur'],
            'sentinelle.alerte.nom_expediteur' => $config['alerte']['nom_expediteur'],
            'sentinelle.alerte.nom_du_site'    => $config['alerte']['nom_du_site'],
            'sentinelle.alerte.repit'          => $config['alerte']['repit'],

            'sentinelle.acces.role'            => $config['acces']['role'],
            'sentinelle.acces.prefixe'         => $config['acces']['prefixe'],
            'sentinelle.acces.gabarit_parent'  => $config['acces']['gabarit_parent'],
            'sentinelle.acces.route_retour'    => $config['acces']['route_retour'],

            'sentinelle.seuils'                => $config['seuils'],

            'sentinelle.allowlist'             => $config['jamais_bloquer']['ips'],
            'sentinelle.chemins_exemptes'      => $config['jamais_bloquer']['chemins'],
            // fusionnés, jamais substitués — voir la remarque en tête de classe
            'sentinelle.prestataires_sus'      => $config['jamais_bloquer']['prestataires'],
            'sentinelle.motifs_sus'            => $config['motifs_critiques'],
            'sentinelle.ignorer_sus'           => $config['ignorer'],
        ] as $nom => $valeur) {
            $conteneur->setParameter($nom, $valeur);
        }
    }

    public function getAlias(): string
    {
        return 'sentinelle';
    }
}
