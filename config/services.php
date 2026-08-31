<?php

declare(strict_types=1);

use Acencyril\SentinelleBundle\Controller\ActiviteController;
use Acencyril\SentinelleBundle\Command\PurgerCommand;
use Acencyril\SentinelleBundle\Command\VerifierCommand;
use Acencyril\SentinelleBundle\EventListener\BlockedIpListener;
use Acencyril\SentinelleBundle\EventListener\SiteActivityListener;
use Acencyril\SentinelleBundle\Repository\IpBloqueeRepository;
use Acencyril\SentinelleBundle\Repository\VisiteRepository;
use Acencyril\SentinelleBundle\Service\AlerteSecurite;
use Acencyril\SentinelleBundle\Service\IpBlocklist;
use Acencyril\SentinelleBundle\Service\IpIdentifier;
use Acencyril\SentinelleBundle\Service\SiteEventLogger;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

return static function (Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator $c): void {
    $services = $c->services()->defaults()->autoconfigure(false);

    $services->set(IpBloqueeRepository::class)
        ->args([service('doctrine')])
        ->tag('doctrine.repository_service');

    $services->set(VisiteRepository::class)
        ->args([service('doctrine')])
        ->tag('doctrine.repository_service');

    $services->set(IpIdentifier::class)
        ->args([service('cache.app'), '%sentinelle.prestataires_sus%']);

    $services->set(IpBlocklist::class)
        ->args([
            service(IpBloqueeRepository::class),
            service('doctrine.orm.entity_manager'),
            service('cache.app'),
            service('logger'),
            service(IpIdentifier::class),
            '%sentinelle.allowlist%',
            '%sentinelle.essai%',
        ]);

    $services->set(AlerteSecurite::class)
        ->args([
            service('mailer.mailer'),
            service('logger'),
            service('router'),
            '%sentinelle.alerte.destinataire%',
            '%sentinelle.alerte.expediteur%',
            '%sentinelle.alerte.nom_expediteur%',
            '%sentinelle.alerte.nom_du_site%',
        ]);

    $services->set(SiteEventLogger::class)
        ->args([
            service('doctrine.dbal.default_connection'),
            service('cache.app'),
            service('logger'),
            service(AlerteSecurite::class),
            service(IpBlocklist::class),
            '%sentinelle.seuils%',
            '%sentinelle.alerte.repit%',
            '%sentinelle.chemins_exemptes%',
            '%sentinelle.motifs_sus%',
            '%sentinelle.ignorer_sus%',
            '%sentinelle.acces.prefixe%',
        ]);

    /* ⚠ PRIORITÉ 300, AVANT LE ROUTEUR (32) ET LE PARE-FEU (8). Une adresse
       bannie ne doit consommer ni résolution de route, ni session, ni requête en
       base. Placé après, le blocage coûterait presque aussi cher qu'un accès. */
    $services->set(BlockedIpListener::class)
        ->args([service(IpBlocklist::class)])
        ->tag('kernel.event_listener', [
            'event' => 'kernel.request', 'method' => 'onKernelRequest', 'priority' => 300,
        ]);

    /* Sur `kernel.terminate` : la réponse est partie, l'écriture ne coûte rien au
       visiteur — et c'est le seul moment où le code HTTP est connu. */
    $services->set(SiteActivityListener::class)
        ->args([service(SiteEventLogger::class)])
        ->tag('kernel.event_listener', [
            'event' => 'kernel.terminate', 'method' => 'onKernelTerminate',
        ]);

    $services->set(ActiviteController::class)
        ->args([
            service(VisiteRepository::class),
            service(IpBlocklist::class),
            service(IpIdentifier::class),
            '%sentinelle.acces.role%',
            '%sentinelle.acces.gabarit_parent%',
            '%sentinelle.acces.route_retour%',
        ])
        ->tag('controller.service_arguments')
        ->call('setContainer', [service('service_container')]);

    $services->set(VerifierCommand::class)
        ->args([
            service('doctrine.dbal.default_connection'),
            service('cache.app'),
            service(IpBlocklist::class),
            '%sentinelle.allowlist%',
            '%sentinelle.essai%',
            '%sentinelle.alerte.destinataire%',
        ])
        ->tag('console.command');

    $services->set(PurgerCommand::class)
        ->args([service(IpBlocklist::class), service('doctrine.dbal.default_connection')])
        ->tag('console.command');
};
