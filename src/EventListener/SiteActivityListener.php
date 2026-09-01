<?php

namespace Acencyril\SentinelleBundle\EventListener;

use Acencyril\SentinelleBundle\Service\SiteEventLogger;
use Symfony\Component\HttpKernel\Event\TerminateEvent;

/**
 * Records every request once the response has been sent.
 *
 * Hooked on kernel.terminate rather than kernel.request: that is the only
 * moment the status code is known, and writing to the database then costs the
 * visitor nothing. kernel.terminate only fires on the main request, which also
 * removes duplicates from sub-requests.
 */
class SiteActivityListener
{
    public function __construct(private SiteEventLogger $logger) {}

    public function onKernelTerminate(TerminateEvent $event): void
    {
        $this->logger->logRequest($event->getRequest(), $event->getResponse());
    }
}