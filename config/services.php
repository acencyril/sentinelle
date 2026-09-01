<?php

declare(strict_types=1);

use Acencyril\SentinelleBundle\Controller\ActivityController;
use Acencyril\SentinelleBundle\Command\PurgeCommand;
use Acencyril\SentinelleBundle\Command\CheckCommand;
use Acencyril\SentinelleBundle\EventListener\BlockedIpListener;
use Acencyril\SentinelleBundle\EventListener\SiteActivityListener;
use Acencyril\SentinelleBundle\Repository\BlockedIpRepository;
use Acencyril\SentinelleBundle\Repository\VisitRepository;
use Acencyril\SentinelleBundle\Service\SecurityAlert;
use Acencyril\SentinelleBundle\Service\IpBlocklist;
use Acencyril\SentinelleBundle\Service\IpIdentifier;
use Acencyril\SentinelleBundle\Service\SiteEventLogger;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

return static function (Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator $c): void {
    $services = $c->services()->defaults()->autoconfigure(false);

    $services->set(BlockedIpRepository::class)
        ->args([service('doctrine')])
        ->tag('doctrine.repository_service');

    $services->set(VisitRepository::class)
        ->args([service('doctrine')])
        ->tag('doctrine.repository_service');

    $services->set(IpIdentifier::class)
        ->args([service('cache.app'), '%sentinelle.extra_providers%']);

    $services->set(IpBlocklist::class)
        ->args([
            service(BlockedIpRepository::class),
            service('doctrine.orm.entity_manager'),
            service('cache.app'),
            service('logger'),
            service(IpIdentifier::class),
            '%sentinelle.allowlist%',
            '%sentinelle.dry_run%',
        ]);

    $services->set(SecurityAlert::class)
        ->args([
            service('mailer.mailer'),
            service('logger'),
            service('router'),
            '%sentinelle.alert.recipient%',
            '%sentinelle.alert.sender%',
            '%sentinelle.alert.sender_name%',
            '%sentinelle.alert.site_name%',
        ]);

    $services->set(SiteEventLogger::class)
        ->args([
            service('doctrine.dbal.default_connection'),
            service('cache.app'),
            service('logger'),
            service(SecurityAlert::class),
            service(IpBlocklist::class),
            '%sentinelle.thresholds%',
            '%sentinelle.alert.cooldown%',
            '%sentinelle.exempt_paths%',
            '%sentinelle.extra_patterns%',
            '%sentinelle.extra_ignored%',
            '%sentinelle.access.prefix%',
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

        $services->set(ActivityController::class)
        ->args([
            service(VisitRepository::class),
            service(IpBlocklist::class),
            service(IpIdentifier::class),
            service('security.authorization_checker'),
            service('twig'),
            service('router'),
            service('security.csrf.token_manager'),
            '%sentinelle.access.role%',
            '%sentinelle.access.parent_template%',
            '%sentinelle.access.back_route%',
        ])
        ->tag('controller.service_arguments');

    $services->set(CheckCommand::class)
        ->args([
            service('doctrine.dbal.default_connection'),
            service('cache.app'),
            service(IpBlocklist::class),
            '%sentinelle.allowlist%',
            '%sentinelle.dry_run%',
            '%sentinelle.alert.recipient%',
        ])
        ->tag('console.command');

    $services->set(PurgeCommand::class)
        ->args([service(IpBlocklist::class), service('doctrine.dbal.default_connection')])
        ->tag('console.command');
};
