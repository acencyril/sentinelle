<?php

declare(strict_types=1);

use Acencyril\SentinelleBundle\Controller\ActiviteController;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/* Le préfixe est configurable : deux applications n'ont pas forcément la même
   convention d'URL d'administration. */
return static function (RoutingConfigurator $routes): void {
    $prefixe = '%sentinelle.acces.prefixe%';

    $routes->add('sentinelle_activite', $prefixe.'/')
        ->controller([ActiviteController::class, 'index'])
        ->methods(['GET']);

    $routes->add('sentinelle_bloquer', $prefixe.'/bloquer')
        ->controller([ActiviteController::class, 'bloquer'])
        ->methods(['POST']);

    $routes->add('sentinelle_debloquer', $prefixe.'/debloquer')
        ->controller([ActiviteController::class, 'debloquer'])
        ->methods(['POST']);
};
