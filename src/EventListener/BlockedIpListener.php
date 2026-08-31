<?php

namespace Acencyril\SentinelleBundle\EventListener;

use Acencyril\SentinelleBundle\Service\IpBlocklist;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;

/**
 * Refuse les requetes venant d'une IP bloquee.
 *
 * Branche tres tot sur kernel.request, avant le routeur (priorite 32) et le
 * pare-feu (priorite 8) : une IP bannie ne doit consommer ni resolution de
 * route, ni session, ni requete en base.
 *
 * La reponse est un 403 nu, sans page d'erreur ni indice sur la raison du refus.
 * Repondre en detail a un scanner lui apprend seulement ce qu'il a declenche.
 */
class BlockedIpListener
{
    /** Marqueur relu par SiteEventLogger pour etiqueter la ligne "ip_blocked". */
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
            // Ne pas laisser un cache intermediaire memoriser ce 403 : le blocage
            // expire, la reponse ne doit pas lui survivre.
            'Cache-Control' => 'no-store, private',
        ]));
    }
}
