<?php

namespace Acencyril\SentinelleBundle\Service;

use Psr\Cache\CacheItemPoolInterface;

/**
 * Puts a name on an IP address.
 *
 * The dashboard used to show bare addresses. You cannot decide anything looking
 * at a string of digits: the one that seems suspicious may be the server
 * delivering your email, and blocking it cuts off all incoming mail. Without
 * this column the only sensible strategy is to block everything at random — or
 * nothing.
 *
 * Identification relies on reverse DNS, which is declarative and can lie. That
 * does not matter here: it is used to recognise legitimate providers you must
 * not block, not to grant a right. A hostile address posing as Mailgun would
 * only gain not being blocked automatically, and its reverse DNS would have to
 * be genuinely delegated by the owner of the range for that.
 */
class IpIdentifier
{
    /**
     * Recognition by reverse DNS suffix.
     *
     * 'critical' marks providers whose blocking breaks a working part of the
     * site: those are refused by IpBlocklist and flagged in red.
     *
     * A starting point, not an inventory: only the most widespread providers
     * are listed here. Yours — e-signature, invoicing, media hosting — go in
     * `sentinelle.never_block.providers` and are added to these.
     *
     * Leaving them out is a bet that automatic blocking will never reach them.
     * That bet has been lost before.
     *
     * @var array<string,array{label:string,critical:bool}>
     */
    private const KNOWN_SUFFIXES = [
        '.mgsend.net'          => ['label' => 'Mailgun (inbound email)',  'critical' => true],
        '.mailgun.org'         => ['label' => 'Mailgun (inbound email)',  'critical' => true],
        '.sendgrid.net'        => ['label' => 'SendGrid (email)',         'critical' => true],
        '.sendinblue.com'      => ['label' => 'Brevo (email)',            'critical' => true],
        '.postmarkapp.com'     => ['label' => 'Postmark (email)',         'critical' => true],
        '.stripe.com'          => ['label' => 'Stripe (payments)',        'critical' => true],
        '.googlebot.com'       => ['label' => 'Googlebot',                'critical' => false],
        '.google.com'          => ['label' => 'Google',                   'critical' => false],
        '.search.msn.com'      => ['label' => 'Bingbot',                  'critical' => false],
        '.crawl.yahoo.net'     => ['label' => 'Yahoo Slurp',              'critical' => false],
        '.applebot.apple.com'  => ['label' => 'Applebot',                 'critical' => false],
        '.bc.googleusercontent.com' => ['label' => 'Google Cloud',        'critical' => false],
        '.amazonaws.com'       => ['label' => 'AWS',                      'critical' => false],
        '.cloudfront.net'      => ['label' => 'AWS CloudFront',           'critical' => false],
        '.azure.com'           => ['label' => 'Microsoft Azure',          'critical' => false],
        '.ovh.net'             => ['label' => 'OVH',                      'critical' => false],
        '.scaleway.com'        => ['label' => 'Scaleway',                 'critical' => false],
        '.hetzner.com'         => ['label' => 'Hetzner',                  'critical' => false],
        '.digitalocean.com'    => ['label' => 'DigitalOcean',             'critical' => false],
        '.orangecustomers.net' => ['label' => 'Orange (consumer ISP)',    'critical' => false],
        '.proxad.net'          => ['label' => 'Free (consumer ISP)',      'critical' => false],
        '.bbox.fr'             => ['label' => 'Bouygues (ISP)',           'critical' => false],
        '.sfr.net'             => ['label' => 'SFR (ISP)',                'critical' => false],
        '.numericable.fr'      => ['label' => 'SFR (ISP)',                'critical' => false],
    ];

    /** The reverse DNS of an address almost never changes. */
    private const CACHE_TTL = 604800;

    /**
     * Cap on lookups actually performed per page render.
     *
     * A cold reverse lookup can take seconds; without a cap, a table of 200
     * rows carrying that many unknown addresses would make the dashboard
     * unusable. Addresses beyond the cap are still shown, simply without a
     * name — they get resolved on the next visit.
     */
    private const MAX_LOOKUPS_PER_BATCH = 30;

    /**
     * @param array<string,string> $extra suffix => label, all critical. Merged
     *                                    with KNOWN_SUFFIXES, never
     *                                    substituted: protection is not removed
     *                                    by configuration.
     */
    public function __construct(
        private CacheItemPoolInterface $cache,
        private array $extra = [],
    ) {}

    /**
     * @return array<string,array{label:string,critical:bool}>
     */
    private function knownSuffixes(): array
    {
        $all = self::KNOWN_SUFFIXES;
        foreach ($this->extra as $suffix => $label) {
            // Entries declared by the project are always critical: listing a
            // provider means "never block this", and there is no other reason
            // to list one.
            $all[$suffix] = ['label' => $label, 'critical' => true];
        }

        return $all;
    }

    /**
     * Identifies a batch of addresses in one pass.
     *
     * @param  iterable<string> $ips
     * @return array<string,array{hostname:?string,label:?string,critical:bool}> keyed by IP
     */
    public function identifyMany(iterable $ips): array
    {
        $result = [];
        $budget = self::MAX_LOOKUPS_PER_BATCH;

        foreach ($ips as $ip) {
            if ($ip === null || $ip === '' || isset($result[$ip])) {
                continue;
            }

            $cached = $this->fromCache($ip);

            if ($cached !== null) {
                $result[$ip] = $cached;
                continue;
            }

            if ($budget <= 0) {
                $result[$ip] = ['hostname' => null, 'label' => null, 'critical' => false];
                continue;
            }

            $budget--;
            $result[$ip] = $this->resolve($ip);
        }

        return $result;
    }

    /**
     * @return array{hostname:?string,label:?string,critical:bool}
     */
    public function identify(string $ip): array
    {
        return $this->fromCache($ip) ?? $this->resolve($ip);
    }

    /**
     * @return array{hostname:?string,label:?string,critical:bool}|null
     */
    private function fromCache(string $ip): ?array
    {
        try {
            $item = $this->cache->getItem($this->key($ip));

            return $item->isHit() ? $item->get() : null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * @return array{hostname:?string,label:?string,critical:bool}
     */
    private function resolve(string $ip): array
    {
        $hostname = @gethostbyaddr($ip);

        // gethostbyaddr returns the address itself when resolution fails.
        if ($hostname === false || $hostname === $ip) {
            $hostname = null;
        } else {
            $hostname = rtrim(strtolower($hostname), '.');
        }

        $identity = ['hostname' => $hostname, 'label' => null, 'critical' => false];

        if ($hostname !== null) {
            foreach ($this->knownSuffixes() as $suffix => $known) {
                if (str_ends_with($hostname, $suffix)) {
                    $identity['label'] = $known['label'];
                    $identity['critical'] = $known['critical'];
                    break;
                }
            }
        }

        try {
            $item = $this->cache->getItem($this->key($ip));
            $item->set($identity)->expiresAfter(self::CACHE_TTL);
            $this->cache->save($item);
        } catch (\Throwable) {
            // Without a cache the lookup happens again: slower, not wrong.
        }

        return $identity;
    }

    private function key(string $ip): string
    {
        return 'ipid_' . preg_replace('/[^a-z0-9]/i', '_', $ip);
    }
}