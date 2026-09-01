<?php

namespace Acencyril\SentinelleBundle\Service;

use Psr\Cache\CacheItemPoolInterface;

/**
 * Met un nom sur une adresse IP.
 *
 * Le tableau de bord n'affichait que des IP nues. Impossible de decider quoi
 * que ce soit devant une suite de chiffres : celle qui vous semble suspecte est
 * peut-etre le serveur qui vous livre vos emails, et la bloquer coupe toute
 * reception. Sans cette colonne, la seule strategie raisonnable est de tout
 * bloquer au hasard -- ou rien.
 *
 * L'identification repose sur le reverse DNS, qui est declaratif et peut mentir
 * pour un attaquant. C'est sans importance ici : on s'en sert pour reconnaitre
 * les prestataires legitimes qu'on ne veut surtout pas bloquer, pas pour
 * accorder un droit. Une IP hostile qui se ferait passer pour Mailgun gagnerait
 * seulement de ne pas etre bloquee automatiquement, et son reverse DNS devrait
 * pour cela etre reellement delegue par le proprietaire de la plage.
 */
class IpIdentifier
{
    /**
     * Reconnaissance par suffixe de reverse DNS.
     *
     * 'critical' marque les prestataires dont le blocage casse une fonction du
     * site : ils sont refuses par IpBlocklist et signales en rouge.
     *
     * ⚠ CETTE LISTE EST UN POINT DE DÉPART, PAS UN INVENTAIRE. Elle ne contient
     * que des prestataires très répandus. Les tiens — signature électronique,
     * facturation, hébergeur de médias — se déclarent dans
     * `sentinelle.never_block.providers` : ils s'AJOUTENT à ceux-ci.
     *
     * Ne pas les y mettre revient à parier que le blocage automatique ne les
     * atteindra jamais. C'est exactement ce pari qui a été perdu une fois.
     *
     * @var array<string,array{label:string,critical:bool}>
     */
    private const KNOWN_SUFFIXES = [
        '.mgsend.net'          => ['label' => 'Mailgun (emails entrants)', 'critical' => true],
        '.mailgun.org'         => ['label' => 'Mailgun (emails entrants)', 'critical' => true],
        '.sendgrid.net'        => ['label' => 'SendGrid (emails)',         'critical' => true],
        '.sendinblue.com'      => ['label' => 'Brevo (emails)',            'critical' => true],
        '.postmarkapp.com'     => ['label' => 'Postmark (emails)',         'critical' => true],
        '.stripe.com'          => ['label' => 'Stripe (paiements)',        'critical' => true],
        '.googlebot.com'       => ['label' => 'Googlebot',                 'critical' => false],
        '.google.com'          => ['label' => 'Google',                    'critical' => false],
        '.search.msn.com'      => ['label' => 'Bingbot',                   'critical' => false],
        '.crawl.yahoo.net'     => ['label' => 'Yahoo Slurp',               'critical' => false],
        '.applebot.apple.com'  => ['label' => 'Applebot',                  'critical' => false],
        '.bc.googleusercontent.com' => ['label' => 'Google Cloud',         'critical' => false],
        '.amazonaws.com'       => ['label' => 'AWS',                       'critical' => false],
        '.cloudfront.net'      => ['label' => 'AWS CloudFront',            'critical' => false],
        '.azure.com'           => ['label' => 'Microsoft Azure',           'critical' => false],
        '.ovh.net'             => ['label' => 'OVH',                       'critical' => false],
        '.scaleway.com'        => ['label' => 'Scaleway',                  'critical' => false],
        '.hetzner.com'         => ['label' => 'Hetzner',                   'critical' => false],
        '.digitalocean.com'    => ['label' => 'DigitalOcean',              'critical' => false],
        '.orangecustomers.net' => ['label' => 'Orange (FAI grand public)', 'critical' => false],
        '.proxad.net'          => ['label' => 'Free (FAI grand public)',   'critical' => false],
        '.bbox.fr'             => ['label' => 'Bouygues (FAI)',            'critical' => false],
        '.sfr.net'             => ['label' => 'SFR (FAI)',                 'critical' => false],
        '.numericable.fr'      => ['label' => 'SFR (FAI)',                 'critical' => false],
    ];

    /** Le reverse DNS d'une IP ne change quasiment jamais. */
    private const CACHE_TTL = 604800;

    /**
     * Plafond de resolutions reellement effectuees par affichage de page.
     *
     * Une resolution inverse froide prend jusqu'a quelques secondes ; sans
     * plafond, un tableau de 200 lignes portant autant d'IP inconnues rendrait
     * le dashboard inutilisable. Les IP au-dela restent affichees, simplement
     * sans nom -- elles seront resolues au prochain passage.
     */
    private const MAX_LOOKUPS_PER_BATCH = 30;

    /**
     * @param array<string,string> $extra suffixe => libelle, tous critiques.
     *                                     Fusionnes avec KNOWN_SUFFIXES, jamais
     *                                     substitues : on n'enleve pas une
     *                                     protection par configuration.
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
        $tous = self::KNOWN_SUFFIXES;
        foreach ($this->extra as $suffixe => $libelle) {
            // ⚠ LES AJOUTS DU PROJET SONT TOUJOURS CRITIQUES. Declarer un
            // prestataire, c'est dire « ne le bloque jamais » ; il n'y aurait
            // aucune raison de l'inscrire pour autre chose.
            $tous[$suffixe] = ['label' => $libelle, 'critical' => true];
        }

        return $tous;
    }

    /**
     * Identifie un lot d'IP d'un coup.
     *
     * @param  iterable<string> $ips
     * @return array<string,array{hostname:?string,label:?string,critical:bool}> indexe par IP
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

        // gethostbyaddr renvoie l'IP telle quelle quand la resolution echoue.
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
            // Sans cache on refera la resolution : plus lent, pas faux.
        }

        return $identity;
    }

    private function key(string $ip): string
    {
        return 'ipid_' . preg_replace('/[^a-z0-9]/i', '_', $ip);
    }
}
