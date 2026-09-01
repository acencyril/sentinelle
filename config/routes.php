<?php

declare(strict_types=1);

use Acencyril\SentinelleBundle\Controller\ActivityController;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/* Le préfixe est configurable : deux applications n'ont pas forcément la même
   convention d'URL d'administration. */
return static function (RoutingConfigurator $routes): void {
    $prefixe = '%sentinelle.access.prefix%';

    $routes->add('sentinelle_activity', $prefixe.'/')
        ->controller([ActivityController::class, 'index'])
        ->methods(['GET']);

    $routes->add('sentinelle_block', $prefixe.'/bloquer')
        ->controller([ActivityController::class, 'block'])
        ->methods(['POST']);

    $routes->add('sentinelle_unblock', $prefixe.'/debloquer')
        ->controller([ActivityController::class, 'unblock'])
        ->methods(['POST']);
};
