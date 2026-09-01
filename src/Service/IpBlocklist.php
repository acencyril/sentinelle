<?php

namespace Acencyril\SentinelleBundle\Service;

use Acencyril\SentinelleBundle\Entity\BlockedIp;
use Acencyril\SentinelleBundle\Repository\BlockedIpRepository;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerInterface;

/**
 * Liste des IP interdites d'acces, et decision de les y inscrire.
 *
 * Lue sur chaque requete par BlockedIpListener, ecrite par SiteEventLogger
 * quand une IP franchit un seuil. La lecture passe par le cache : un aller en
 * base par requete pour une liste qui contient une poignee d'adresses serait
 * disproportionne.
 */
class IpBlocklist
{
    /**
     * Duree du blocage selon le nombre de recidives. Au 3e passage, permanent.
     *
     * Progressif et non definitif d'emblee : la plupart des IP de scan sont des
     * machines compromises ou des adresses cloud reattribuees en permanence.
     * Une IP qui revient apres 24 h puis apres 7 jours, elle, est deliberee.
     */
    private const TTL_BY_STRIKE = [1 => '+24 hours', 2 => '+7 days'];

    /** Cle de cache portant la liste complete ; invalidee a chaque ecriture. */
    private const CACHE_KEY = 'ip_blocklist_active';
    private const CACHE_TTL = 300;

    /**
     * Jamais blocked, quoi qu'elles fassent.
     *
     * Les plages privees couvrent le reseau Docker : sans reverse-proxy
     * correctement configure, toutes les requetes semblent venir de la passerelle
     * du conteneur, et un seul scanner ferait bannir le site entier.
     *
     * @var string[] notation CIDR
     */
    private const ALWAYS_ALLOWED = [
        '127.0.0.0/8',
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '::1/128',
    ];

    /** @var string[]|null Allowlist configuree, decomposee au premier acces. */
    private ?array $configuredAllowlist = null;

    public function __construct(
        private BlockedIpRepository $repository,
        private EntityManagerInterface $em,
        private CacheItemPoolInterface $cache,
        private LoggerInterface $logger,
        private IpIdentifier $identifier,
        // Nullable : '%env(default::IP_BLOCK_ALLOWLIST)%' vaut null quand la
        // variable n'est pas definie, pas la chaine vide.
        private ?string $allowlist = null,
        /**
         * ⚠ MODE D'ESSAI : ON DÉTECTE, ON ALERTE, ON NE BLOQUE PAS.
         *
         * Personne de sensé ne branche un blocage automatique sur un site en
         * production sans savoir ce qu'il va fermer. Les premières semaines, on
         * veut lire le journal et se demander « aurais-je voulu bloquer
         * celle-ci ? » — pas découvrir a posteriori qu'un client a été banni.
         *
         * Le refus est journalisé avec ce qui AURAIT été décidé, durée
         * comprise : c'est exactement ce qu'il faut pour juger avant de
         * basculer.
         *
         * *Un mécanisme qu'on ne peut pas essayer sans risque ne sera pas
         * essayé — il sera installé et desactivé au premier incident.*
         */
        private bool $dryRun = false,
    ) {}

    /**
     * Cette IP doit-elle etre refusee maintenant ?
     */
    public function isBlocked(string $ip): bool
    {
        if ($this->isAllowed($ip)) {
            return false;
        }

        return in_array($ip, $this->activeIps(), true);
    }

    /**
     * Une IP protegee ne peut etre ni bloquee automatiquement, ni manuellement.
     */
    public function isAllowed(string $ip): bool
    {
        foreach (self::ALWAYS_ALLOWED as $cidr) {
            if (self::matchesCidr($ip, $cidr)) {
                return true;
            }
        }

        foreach ($this->configuredAllowlist() as $entry) {
            if ($entry === $ip || (str_contains($entry, '/') && self::matchesCidr($ip, $entry))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Inscrit ou prolonge un blocage. Renvoie l'entree, ou null si l'IP est
     * protegee par l'allowlist.
     *
     * Idempotent : rappeler avec la meme IP pendant que le blocage court ne
     * cree pas de recidive, seul un nouveau blocage apres expiration compte.
     */
    public function block(string $ip, string $reason, string $source = BlockedIp::SOURCE_AUTO, ?string $ttl = null): ?BlockedIp
    {
        if ($this->isAllowed($ip)) {
            $this->logger->info('Block skipped: IP is allowlisted', ['ip' => $ip, 'reason' => $reason]);

            return null;
        }

        if ($this->isProtectedProvider($ip)) {
            $this->logger->warning('Block refused: IP belongs to a critical provider', ['ip' => $ip, 'reason' => $reason]);

            return null;
        }

        if ($this->dryRun) {
            $this->logger->warning('Sentinelle dry-run: block SIMULATED', [
                'ip' => $ip,
                'reason' => $reason,
                'source' => $source,
                'would_have_lasted' => $ttl ?? ($source === BlockedIp::SOURCE_MANUAL ? 'permanent' : '24 hours'),
            ]);

            return null;
        }

        try {
            $existing = $this->repository->findOneByIp($ip);

            if ($existing !== null && !$existing->isExpired()) {
                return $existing;
            }

            $entry = $existing ?? new BlockedIp($ip, $reason, $source);
            $strikes = $existing !== null ? $existing->getStrikes() + 1 : 1;

            $entry->setReason($reason)->setSource($source)->setStrikes($strikes);
            $entry->setExpiresAt($this->expiryFor($strikes, $source, $ttl));

            $this->em->persist($entry);
            $this->em->flush();
            $this->invalidate();

            $this->logger->warning('IP blocked', [
                'ip'         => $ip,
                'reason'     => $reason,
                'source'     => $source,
                'strikes'    => $strikes,
                'expires_at' => $entry->getExpiresAt()?->format('c') ?? 'jamais',
            ]);

            return $entry;
        } catch (\Throwable $e) {
            // Le blocage est une protection, pas une fonction vitale : s'il
            // echoue, la requete en cours doit continuer normalement.
            $this->logger->error('Failed to block IP', ['ip' => $ip, 'error' => $e->getMessage()]);

            return null;
        }
    }

    public function unblock(string $ip): bool
    {
        $entry = $this->repository->findOneByIp($ip);
        if ($entry === null) {
            return false;
        }

        $this->em->remove($entry);
        $this->em->flush();
        $this->invalidate();

        $this->logger->info('IP unblocked', ['ip' => $ip]);

        return true;
    }

    /**
     * Comptabilise une requete refusee, pour montrer dans le dashboard si l'IP
     * insiste encore apres son blocage.
     */
    public function registerHit(string $ip): void
    {
        try {
            $entry = $this->repository->findOneByIp($ip);
            if ($entry !== null) {
                $entry->registerHit();
                $this->em->flush();
            }
        } catch (\Throwable $e) {
            $this->logger->warning('Failed to count hit on blocked IP', ['ip' => $ip, 'error' => $e->getMessage()]);
        }
    }

    /**
     * @return BlockedIp[]
     */
    public function activeEntries(): array
    {
        return $this->repository->findActive();
    }

    public function purgeExpired(\DateTimeImmutable $before): int
    {
        $deleted = $this->repository->purgeExpired($before);
        $this->invalidate();

        return $deleted;
    }

    /**
     * @return string[]
     */
    private function activeIps(): array
    {
        try {
            $item = $this->cache->getItem(self::CACHE_KEY);
            if ($item->isHit()) {
                return $item->get();
            }

            $ips = $this->repository->findActiveIps();
            $item->set($ips)->expiresAfter(self::CACHE_TTL);
            $this->cache->save($item);

            return $ips;
        } catch (\Throwable $e) {
            // Cache ou base indisponible : on laisse passer. Un blocage rate est
            // moins grave qu'un site qui refuse tout le monde.
            $this->logger->warning('Could not read the blocklist', ['error' => $e->getMessage()]);

            return [];
        }
    }

    private function invalidate(): void
    {
        try {
            $this->cache->deleteItem(self::CACHE_KEY);
        } catch (\Throwable) {
            // Sans importance : l'entree expire d'elle-meme en 5 minutes.
        }
    }

    /**
     * Null = permanent.
     */
    private function expiryFor(int $strikes, string $source, ?string $ttl): ?\DateTimeImmutable
    {
        if ($ttl !== null) {
            return $ttl === 'permanent' ? null : new \DateTimeImmutable($ttl);
        }

        // Un blocage manuel sans duree explicite est un choix delibere : permanent.
        if ($source === BlockedIp::SOURCE_MANUAL) {
            return null;
        }

        $interval = self::TTL_BY_STRIKE[$strikes] ?? null;

        return $interval === null ? null : new \DateTimeImmutable($interval);
    }

    /**
     * L'IP appartient-elle a un prestataire dont le blocage casserait une
     * fonction du site (livraison d'emails, paiements, signatures) ?
     *
     * Une IP de Mailgun a un jour ete bloquee A LA MAIN depuis le tableau de bord :
     * elle y figurait comme suspecte apres un 401. Toute reception d'email
     * serait morte en silence, et personne ne l'aurait su avant des heures.
     * L'exemption de chemin ne couvrait que le blocage AUTOMATIQUE.
     *
     * Volontairement appele depuis block() seulement, et pas depuis isBlocked() :
     * une resolution inverse par requete entrante serait ruineuse. Le cout est
     * paye une fois, au moment de la decision.
     */
    private function isProtectedProvider(string $ip): bool
    {
        return $this->identifier->identify($ip)['critical'];
    }

    /**
     * @return string[]
     */
    private function configuredAllowlist(): array
    {
        if ($this->configuredAllowlist === null) {
            $this->configuredAllowlist = array_values(array_filter(
                array_map('trim', explode(',', $this->allowlist ?? ''))
            ));
        }

        return $this->configuredAllowlist;
    }

    /**
     * Test d'appartenance a un CIDR, IPv4 et IPv6.
     */
    private static function matchesCidr(string $ip, string $cidr): bool
    {
        [$subnet, $bits] = array_pad(explode('/', $cidr, 2), 2, null);

        $ipBin = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);

        if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
            return false;
        }

        $bits = $bits === null ? strlen($ipBin) * 8 : (int) $bits;
        $wholeBytes = intdiv($bits, 8);
        $remainingBits = $bits % 8;

        if ($wholeBytes > 0 && substr($ipBin, 0, $wholeBytes) !== substr($subnetBin, 0, $wholeBytes)) {
            return false;
        }

        if ($remainingBits === 0) {
            return true;
        }

        $mask = 0xFF << (8 - $remainingBits) & 0xFF;

        return (ord($ipBin[$wholeBytes]) & $mask) === (ord($subnetBin[$wholeBytes]) & $mask);
    }
}
