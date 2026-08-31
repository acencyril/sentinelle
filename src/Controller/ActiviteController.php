<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Controller;

use Acencyril\SentinelleBundle\Entity\IpBloquee;
use Acencyril\SentinelleBundle\Entity\Visite;
use Acencyril\SentinelleBundle\Repository\VisiteRepository;
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
class ActiviteController
{
    public function __construct(
        private VisiteRepository $visites,
        private IpBlocklist $blocklist,
        private IpIdentifier $identifier,
        private AuthorizationCheckerInterface $droits,
        private Environment $twig,
        private UrlGeneratorInterface $routeur,
        private CsrfTokenManagerInterface $jetons,
        private string $role,
        private string $gabaritParent,
        private ?string $routeRetour,
    ) {
    }

    public function index(Request $request): Response
    {
        $this->exigeLeDroit();

        $filtre = $request->query->getString('filtre', 'tout');
        $bloquees = $this->blocklist->activeEntries();
        $evenements = $this->visites->findLatest($filtre);
        $tetes = $this->visites->topSuspiciousIps(new \DateTimeImmutable('-7 days'));

        /* ⚠ L'ORDRE COMPTE. Le nombre de resolutions inverses est plafonne par
           affichage : les IP sur lesquelles on va DECIDER doivent etre nommees
           en premier, meme si le plafond tombe avant la fin du journal. Une
           adresse sans nom est une adresse qu'on bloque au hasard. */
        $ips = [
            ...array_column($tetes, 'ip'),
            ...array_map(static fn (IpBloquee $b): string => $b->getIp(), $bloquees),
            ...array_filter(array_map(static fn (Visite $e): ?string => $e->getIp(), $evenements)),
        ];

        return new Response($this->twig->render('@Sentinelle/activite.html.twig', [
            'evenements' => $evenements,
            'filtre' => $filtre,
            'resume' => $this->visites->summarySince(new \DateTimeImmutable('-24 hours')),
            'tetes' => $tetes,
            'bloquees' => $bloquees,
            'identites' => $this->identifier->identifyMany($ips),
            'bloqueesParIp' => array_combine(
                array_map(static fn (IpBloquee $b): string => $b->getIp(), $bloquees),
                $bloquees
            ),
            'gabarit_parent' => $this->gabaritParent,
            'route_retour' => $this->routeRetour,
        ]));
    }

    /**
     * Blocage manuel. Permanent par defaut : une IP qu'on bloque a la main est
     * un choix delibere, pas une detection.
     */
    public function bloquer(Request $request): Response
    {
        $this->exigeLeDroit();
        $ip = trim($request->request->getString('ip'));

        if (!$this->jetonValide($request)) {
            $this->dis($request, 'erreur', 'Jeton invalide, action annulee.');
        } elseif (false === filter_var($ip, \FILTER_VALIDATE_IP)) {
            $this->dis($request, 'erreur', sprintf('« %s » n\'est pas une adresse IP valide.', $ip));
        } elseif ($this->blocklist->isAllowed($ip)) {
            $this->dis($request, 'erreur', sprintf('%s est en liste blanche et ne peut pas etre bloquee.', $ip));
        } elseif (null === $this->blocklist->block($ip, 'Blocage manuel depuis le tableau de bord', IpBloquee::SOURCE_MANUAL)) {
            /* ⚠ C'EST ICI QUE L'INCIDENT SE REJOUERAIT. Une IP de prestataire
               critique, reconnue a son DNS inverse : la bloquer couperait une
               fonction du site. Le bouton refuse, et il dit pourquoi. */
            $this->dis($request, 'erreur', sprintf(
                '%s appartient a un prestataire dont le site depend et ne peut pas etre bloquee.',
                $ip
            ));
        } else {
            $this->dis($request, 'ok', sprintf('%s bloquee.', $ip));
        }

        return new RedirectResponse($this->routeur->generate('sentinelle_activite'));
    }

    public function debloquer(Request $request): Response
    {
        $this->exigeLeDroit();
        $ip = trim($request->request->getString('ip'));

        if (!$this->jetonValide($request)) {
            $this->dis($request, 'erreur', 'Jeton invalide, action annulee.');
        } elseif ($this->blocklist->unblock($ip)) {
            $this->dis($request, 'ok', sprintf('%s debloquee.', $ip));
        } else {
            $this->dis($request, 'erreur', sprintf('%s n\'etait pas bloquee.', $ip));
        }

        return new RedirectResponse($this->routeur->generate('sentinelle_activite'));
    }

    private function exigeLeDroit(): void
    {
        if (!$this->droits->isGranted($this->role)) {
            throw new AccessDeniedException();
        }
    }

    private function jetonValide(Request $request): bool
    {
        return $this->jetons->isTokenValid(
            new CsrfToken('sentinelle_bloquer', $request->request->getString('_token'))
        );
    }

    /** Les messages passent par la session, quand il y en a une. */
    private function dis(Request $request, string $genre, string $message): void
    {
        if ($request->hasSession()) {
            $request->getSession()->getFlashBag()->add('sentinelle_'.$genre, $message);
        }
    }
}
