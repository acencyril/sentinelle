<?php

namespace Acencyril\SentinelleBundle\EventListener;

use Acencyril\SentinelleBundle\Service\IpBlocklist;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;

/**
 * Turns away requests coming from a blocked IP.
 *
 * Hooked very early on kernel.request, ahead of the router (priority 32) and
 * the firewall (priority 8): a banned address must consume no route
 * resolution, no session and no database query.
 *
 * The response is a bare 403, with no error page and no hint as to why. Telling
 * a scanner what happened only teaches it what it triggered.
 */
class BlockedIpListener
{
    /** Flag read back by SiteEventLogger to label the row "ip_blocked". */
    public const REQUEST_ATTRIBUTE = '_ip_blocked';

    public function __construct(private IpBlocklist $blocklist) {}

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $ip = $event->getRequest()->getClientIp();
        if ($ip === null || !$this->blocklist->isBlocked($ip)) {
            return;
        }

        $event->getRequest()->attributes->set(self::REQUEST_ATTRIBUTE, true);
        $this->blocklist->registerHit($ip);

        $event->setResponse(new Response('Forbidden', Response::HTTP_FORBIDDEN, [
            'Content-Type' => 'text/plain; charset=UTF-8',
            // No intermediate cache should remember this 403: the block
            // expires, and the response must not outlive it.
            'Cache-Control' => 'no-store, private',
        ]));
    }
}