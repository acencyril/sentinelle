<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Controller;

use Acencyril\SentinelleBundle\Entity\BlockedIp;
use Acencyril\SentinelleBundle\Entity\Visit;
use Acencyril\SentinelleBundle\Repository\VisitRepository;
use Acencyril\SentinelleBundle\Service\IpBlocklist;
use Acencyril\SentinelleBundle\Service\IpIdentifier;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Twig\Environment;

/**
 * Le tableau de bord : ce qui s'est passe, et ce qu'on decide d'en faire.
 *
 * ⚠ N'HERITE PAS DE `AbstractController`, ET C'EST DELIBERE. Cette classe de
 * base attend un conteneur RESTREINT que Symfony construit par
 * autoconfiguration — mecanisme desactive dans un bundle ou l'on declare tout
 * a la main. Les symptomes sont deroutants et se contredisent :
 *
 *   · sans conteneur       : « has no container set »
 *   · avec le conteneur global : « SecurityBundle is not registered »
 *
 * Deux messages tres differents pour une seule cause, et aucun ne designe le
 * vrai probleme. Injecter directement ce dont on a besoin — le verificateur de
 * droits, Twig, le routeur — supprime la question au lieu de la resoudre.
 *
 * *Une classe de base commode dans une application peut etre un piege dans un
 * bundle : elle suppose un cablage qu'on ne fait plus.*
 *
 * ⚠ NI ROLE NI GABARIT EN DUR non plus : un bundle qui impose son role force
 * chaque projet a adopter une hierarchie de droits qu'il n'a pas choisie.
 */
class ActivityController
{
    public function __construct(
        private VisitRepository $visits,
        private IpBlocklist $blocklist,
        private IpIdentifier $identifier,
        private AuthorizationCheckerInterface $authChecker,
        private Environment $twig,
        private UrlGeneratorInterface $routeur,
        private CsrfTokenManagerInterface $csrf,
        private string $role,
        private string $parentTemplate,
        private ?string $backRoute,
    ) {
    }

    public function index(Request $request): Response
    {
        $this->denyUnlessGranted();

        $filter = $request->query->getString('filter', 'tout');
        $blocked = $this->blocklist->activeEntries();
        $events = $this->visits->findLatest($filter);
        $topIps = $this->visits->topSuspiciousIps(new \DateTimeImmutable('-7 days'));

        /* ⚠ L'ORDRE COMPTE. Le nombre de resolutions inverses est plafonne par
           affichage : les IP sur lesquelles on va DECIDER doivent etre nommees
           en premier, meme si le plafond tombe avant la fin du journal. Une
           adresse sans nom est une adresse qu'on bloque au hasard. */
        $ips = [
            ...array_column($topIps, 'ip'),
            ...array_map(static fn (BlockedIp $b): string => $b->getIp(), $blocked),
            ...array_filter(array_map(static fn (Visit $e): ?string => $e->getIp(), $events)),
        ];

        return new Response($this->twig->render('@Sentinelle/activity.html.twig', [
            'events' => $events,
            'filter' => $filter,
            'summary' => $this->visits->summarySince(new \DateTimeImmutable('-24 hours')),
            'topIps' => $topIps,
            'blocked' => $blocked,
            'identities' => $this->identifier->identifyMany($ips),
            'blockedByIp' => array_combine(
                array_map(static fn (BlockedIp $b): string => $b->getIp(), $blocked),
                $blocked
            ),
            'parent_template' => $this->parentTemplate,
            'back_route' => $this->backRoute,
        ]));
    }

    /**
     * Blocage manuel. Permanent par defaut : une IP qu'on bloque a la main est
     * un choix delibere, pas une detection.
     */
    public function block(Request $request): Response
    {
        $this->denyUnlessGranted();
        $ip = trim($request->request->getString('ip'));

        if (!$this->isTokenValid($request)) {
            $this->flash($request, 'error', 'Invalid token, action cancelled.');
        } elseif (false === filter_var($ip, \FILTER_VALIDATE_IP)) {
            $this->flash($request, 'error', sprintf('"%s" is not a valid IP address.', $ip));
        } elseif ($this->blocklist->isAllowed($ip)) {
            $this->flash($request, 'error', sprintf('%s is allowlisted and cannot be blocked.', $ip));
        } elseif (null === $this->blocklist->block($ip, 'Manual block from the dashboard', BlockedIp::SOURCE_MANUAL)) {
            /* ⚠ C'EST ICI QUE L'INCIDENT SE REJOUERAIT. Une IP de prestataire
               critique, reconnue a son DNS inverse : la bloquer couperait une
               fonction du site. Le bouton refuse, et il dit pourquoi. */
            $this->flash($request, 'error', sprintf(
                '%s belongs to a provider the site depends on and cannot be blocked.',
                $ip
            ));
        } else {
            $this->flash($request, 'success', sprintf('%s blocked.', $ip));
        }

        return new RedirectResponse($this->router->generate('sentinelle_activity'));
    }

    public function unblock(Request $request): Response
    {
        $this->denyUnlessGranted();
        $ip = trim($request->request->getString('ip'));

        if (!$this->isTokenValid($request)) {
            $this->flash($request, 'error', 'Invalid token, action cancelled.');
        } elseif ($this->blocklist->unblock($ip)) {
            $this->flash($request, 'success', sprintf('%s unblocked.', $ip));
        } else {
            $this->flash($request, 'error', sprintf('%s was not blocked.', $ip));
        }

        return new RedirectResponse($this->router->generate('sentinelle_activity'));
    }

    private function denyUnlessGranted(): void
    {
        if (!$this->authChecker->isGranted($this->role)) {
            throw new AccessDeniedException();
        }
    }

    private function isTokenValid(Request $request): bool
    {
        return $this->csrf->isTokenValid(
            new CsrfToken('sentinelle_block', $request->request->getString('_token'))
        );
    }

    /** Les messages passent par la session, quand il y en a une. */
    private function flash(Request $request, string $genre, string $message): void
    {
        if ($request->hasSession()) {
            $request->getSession()->getFlashBag()->add('sentinelle_'.$genre, $message);
        }
    }
}
