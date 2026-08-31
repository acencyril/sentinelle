<?php

namespace Acencyril\SentinelleBundle\EventListener;

use Acencyril\SentinelleBundle\Service\SiteEventLogger;
use Symfony\Component\HttpKernel\Event\TerminateEvent;

/**
 * Journalise chaque requete apres envoi de la reponse.
 *
 * Branche sur kernel.terminate et non kernel.request : c'est le seul moment ou
 * le code HTTP est connu, et l'insertion en base n'ajoute alors aucune latence
 * pour le visiteur. kernel.terminate ne se declenche que sur la requete
 * principale, ce qui elimine au passage les doublons de sous-requetes.
 */
class SiteActivityListener
{
    public function __construct(private SiteEventLogger $logger) {}

    public function onKernelTerminate(TerminateEvent $event): void
    {
        $this->logger->logRequest($event->getRequest(), $event->getResponse());
    }
}
