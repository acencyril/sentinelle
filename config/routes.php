<?php

declare(strict_types=1);

use Acencyril\SentinelleBundle\Controller\ActivityController;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/* The prefix is configurable: two applications do not necessarily share the
   same convention for admin URLs. */
return static function (RoutingConfigurator $routes): void {
    $prefix = '%sentinelle.access.prefix%';

    $routes->add('sentinelle_activity', $prefix.'/')
        ->controller([ActivityController::class, 'index'])
        ->methods(['GET']);

    $routes->add('sentinelle_block', $prefix.'/block')
        ->controller([ActivityController::class, 'block'])
        ->methods(['POST']);

    $routes->add('sentinelle_unblock', $prefix.'/unblock')
        ->controller([ActivityController::class, 'unblock'])
        ->methods(['POST']);
};