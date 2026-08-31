<?php

namespace Acencyril\SentinelleBundle\Service;

use Acencyril\SentinelleBundle\EventListener\BlockedIpListener;
use Doctrine\DBAL\Connection;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Journalisation des requetes dans site_event.
 *
 * Appele depuis SiteActivityListener sur kernel.terminate : la reponse est deja
 * partie chez le client, l'insertion ne coute donc rien en latence percue.
 *
 * Trois objectifs, dans cet ordre :
 *   1. ne pas laisser un scanner remplir la table (anti-flood par IP) ;
 *   2. qualifier ce qui est anormal (code HTTP + type d'evenement) ;
 *   3. alerter par mail sur ce qui est reellement dangereux.
 *
 * Insertion en DBAL brut et non via l'ORM : ecriture append-only appelee sur
 * chaque requete, inutile de charger l'UnitOfWork, et immunise contre un
 * EntityManager deja ferme par une exception plus tot dans la requete.
 */
class SiteEventLogger
{
    // Bruit pur, jamais journalise.
    // Le prefixe d'administration s'y ajoute au vol : un outil d'observation ne doit pas se journaliser
    // lui-meme. Sans ca, consulter le tableau de bord remplissait la table de ses
    // propres visites (8 lignes sur 15 lors du premier essai) et le referent
    // exposait la navigation admin.
    private const IGNORED_PREFIXES = ['/_wdt', '/_profiler', '/_fragment', '/health', '/favicon.ico', ];

    /**
     * Charges utiles critiques : execution de code, injection SQL, traversee de
     * repertoire, Log4Shell. Ce sont les seules qui atteignent encore PHP, les
     * sondes /.env, /.git, /wp-* etant souvent arretees en amont par le serveur web.
     * Declenchent un mail immediat.
     */
    private const CRITICAL_PATTERNS = [
        'rce_php_wrapper' => '#php://(input|filter)|auto_prepend_file|allow_url_include#i',
        'rce_exec'        => '#eval-stdin|\b(system|exec|passthru|shell_exec|proc_open)\s*\(#i',
        'sql_injection'   => '#(\bunion\b[\s/*]+\bselect\b)|(\bor\b\s+1\s*=\s*1\b)|\bsleep\s*\(\s*\d|\bbenchmark\s*\(|information_schema|\bdrop\s+table\b#i',
        'path_traversal'  => '#(\.\.[/\\\\]){2,}|/etc/passwd|/proc/self/environ#i',
        'log4shell'       => '#\$\{jndi:#i',
        'deserialization' => '#O:\d+:"[a-z_\\\\]+":\d+:\{#i',
    ];

    /**
     * Sondes plus banales : bruyantes mais sans danger immediat. Journalisees
     * comme scan_probe, sans mail unitaire -- c'est la rafale qui alerte.
     */
    private const SUSPICIOUS_PATTERNS = [
        '#\.(env|sql|bak|old|orig|ya?ml|ini|pem|key|log)$#i',
        '#/\.(git|aws|azure|kube|docker|ssh|gcloud|anthropic|openai|cursor)#i',
        '#(wp-|wordpress|xmlrpc|phpmyadmin|adminer|actuator|cgi-bin|\.well-known/security)#i',
        '#(credentials|secrets?|service.?account|serviceaccountkey|id_rsa|client_secret)#i',
        '#<script\b|javascript:|onerror\s*=#i',
    ];

    /** Au-dela, une IP ne cree plus de ligne d'erreur pendant la fenetre. */
    private const FLOOD_MAX_ERRORS_PER_IP = 5;
    private const FLOOD_WINDOW_SECONDS = 3600;

    /** Rafale de sondes : seuil de declenchement du mail. */
    private const BURST_THRESHOLD = 15;
    private const BURST_WINDOW_SECONDS = 600;

    /** Echecs d'authentification repetes (401/403) avant alerte. */
    private const BRUTEFORCE_THRESHOLD = 10;
    private const BRUTEFORCE_WINDOW_SECONDS = 600;

    /** Un mail par IP et par heure maximum, tous motifs confondus. */
    private const ALERT_COOLDOWN_SECONDS = 3600;

    /**
     * Chemins dont les refus ne declenchent jamais de blocage automatique.
     *
     * Un webhook entrant repond 401 des que la signature ne colle pas. C'est
     * deja arrive pour une livraison parfaitement legitime, le temps qu'une cle
     * de signature parvienne a l'environnement du conteneur. Avec le blocage
     * automatique, cet incident de CONFIGURATION aurait banni le prestataire et
     * coupe toute reception d'email -- une panne bien pire que celle qu'on
     * cherche a eviter.
     */
    private const NEVER_AUTOBLOCK_PREFIXES = ['/api/webhook/'];

    /**
     * ⚠ SIX CONSTANTES DE CLASSE SONT DEVENUES DES ARGUMENTS. Elles étaient
     * justes pour l'application d'origine ; un site à fort trafic voudra un
     * quota anti-flood plus large, un site confidentiel des seuils plus bas.
     * Les valeurs par défaut restent celles qui ont été éprouvées.
     */
    public function __construct(
        private Connection $connection,
        private CacheItemPoolInterface $cache,
        private LoggerInterface $logger,
        private AlerteSecurite $notifier,
        private IpBlocklist $blocklist,
        /** @var array{rafale:int,rafale_fenetre:int,bruteforce:int,bruteforce_fenetre:int,flood_max:int,flood_fenetre:int} */
        private array $seuils = [],
        private int $repitAlerte = 3600,
        /** @var string[] */
        private array $cheminsExemptes = ['/api/webhook/'],
        /** @var array<string,string> */
        private array $motifsAjoutes = [],
        /** @var string[] */
        private array $ignorerAjoutes = [],
        private string $prefixeAdmin = '/admin/activite',
    ) {
        $this->seuils += [
            'rafale' => 15, 'rafale_fenetre' => 600,
            'bruteforce' => 10, 'bruteforce_fenetre' => 600,
            'flood_max' => 5, 'flood_fenetre' => 3600,
        ];}

    /**
     * Point d'entree principal : journalise une requete terminee.
     */
    /**
     * Point d'entree principal : journalise une requete terminee.
     *
     * ⚠ TOUT LE CORPS EST PROTEGE, PAS SEULEMENT L'ECRITURE. Le `try/catch`
     * n'entourait que l'insertion : une erreur dans la qualification ou dans les
     * compteurs remontait librement — et comme on est sur `kernel.terminate`, la
     * reponse est deja partie, l'exception ne va nulle part. Le site repond 200,
     * la table reste vide, et rien ne le signale.
     *
     * C'est exactement ce qui s'est produit : un `use` reste sur l'ancien
     * namespace apres extraction, une `ClassNotFoundError` a chaque requete, et
     * pas une seule ligne journalisee pendant qu'on cherchait la cause du cote
     * de la base.
     *
     * *Un journaliseur qui peut echouer en silence est pire qu'un journaliseur
     * absent : on croit qu'il tourne.*
     */
    public function logRequest(Request $request, Response $response): void
    {
        try {
            $this->journalise($request, $response);
        } catch (\Throwable $e) {
            $this->logger->error('Sentinelle : journalisation impossible', [
                'erreur'  => $e->getMessage(),
                'fichier' => $e->getFile().':'.$e->getLine(),
            ]);
        }
    }

    private function journalise(Request $request, Response $response): void
    {
        $path = $request->getPathInfo();

        // ⚠ ON AJOUTE, ON NE REMPLACE PAS. Le prefixe d'administration est
        // configurable : l'outil d'observation ne doit jamais se journaliser
        // lui-meme, quel que soit l'endroit ou le projet l'a monte.
        $ignores = array_merge(self::IGNORED_PREFIXES, $this->ignorerAjoutes, [$this->prefixeAdmin]);
        foreach ($ignores as $prefix) {
            if (str_starts_with($path, $prefix)) {
                return;
            }
        }

        $status = $response->getStatusCode();
        $ip = $request->getClientIp() ?? 'unknown';
        $query = $request->getQueryString() ?? '';
        // Ce qu'on soumet aux motifs : chemin + query. Le corps POST n'est pas
        // inspecte (couteux, et souvent des donnees personnelles a ne pas stocker).
        $haystack = rawurldecode($path . ($query !== '' ? '?' . $query : ''));

        $critical = $this->matchCritical($haystack);
        $suspicious = $critical === null && $this->isSuspicious($haystack);

        // Une requete deja refusee par BlockedIpListener recoit son propre type.
        // Sans ca elle tomberait en 'access_denied', gonflerait le compteur de
        // bruteforce de l'IP et prolongerait son blocage a l'infini -- une IP
        // bloquee ne pourrait alors plus jamais sortir de la liste.
        $alreadyBlocked = $request->attributes->getBoolean(BlockedIpListener::REQUEST_ATTRIBUTE);

        $type = match (true) {
            $alreadyBlocked    => 'ip_blocked',
            $critical !== null => 'attack_attempt',
            $suspicious        => 'scan_probe',
            $status >= 500     => 'server_error',
            $status === 404    => 'not_found',
            $status === 401 || $status === 403 => 'access_denied',
            $status >= 400     => 'client_error',
            default            => 'page_view',
        };

        $meta = array_filter([
            'method'  => $request->getMethod(),
            'query'   => $query !== '' ? mb_substr($this->redact($query), 0, 500) : null,
            'pattern' => $critical,
            'referer' => $request->headers->get('Referer'),
        ]);

        // Anti-flood : un scan de 155 requetes en 16 s ne doit pas produire
        // 155 lignes. Les pages vues normales et les attaques critiques passent
        // toujours -- ce sont elles qu'on veut completes.
        //
        // Le quota ne coupe QUE l'insertion : evaluateAlerts doit continuer a
        // compter, sinon le seuil de rafale ne serait jamais atteint et le
        // mecanisme d'alerte s'auto-neutraliserait au bout de 5 sondes.
        $flooding = $type !== 'page_view' && $critical === null && $this->isFlooding($ip, $type);

        if (!$flooding) {
            $this->insert($type, $path, $status, $ip, $request->headers->get('User-Agent'), $meta);
        }

        $this->evaluateAlerts($type, $critical, $path, $status, $ip, $request, $meta);
    }

    /**
     * Journalisation manuelle depuis le code metier (signature historique).
     */
    public function log(string $type, ?string $url = null, ?string $ip = null, ?string $userAgent = null, array $meta = []): void
    {
        $this->insert($type, $url, null, $ip, $userAgent, $meta);
    }

    private function insert(string $type, ?string $url, ?int $status, ?string $ip, ?string $userAgent, array $meta): void
    {
        try {
            $this->connection->insert('sentinelle_visite', [
                'event_type'  => mb_substr($type, 0, 255),
                'url'         => $url !== null ? mb_substr($url, 0, 255) : null,
                'status_code' => $status,
                'ip'          => $ip !== null ? mb_substr($ip, 0, 45) : null,
                'user_agent'  => $userAgent !== null ? mb_substr($userAgent, 0, 255) : null,
                'meta'        => json_encode($meta, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                'created_at'  => (new \DateTimeImmutable())->format('Y-m-d H:i:s'),
            ]);
        } catch (\Throwable $e) {
            // Journaliser ne doit jamais casser une requete, ni fermer l'EntityManager.
            $this->logger->warning('site_event insert failed', ['error' => $e->getMessage()]);
        }
    }

    /**
     * Masque les valeurs sensibles avant ecriture en base.
     *
     * Le webhook inbound accepte son secret en parametre d'URL quand le
     * prestataire ne sait pas envoyer d'en-tete. Sans ce masquage, chaque appel
     * legitime ecrirait le secret en clair dans site_event, consultable depuis
     * le dashboard admin.
     */
    private function redact(string $query): string
    {
        return preg_replace(
            '/\b(secret|token|api[-_]?key|password|signature)=[^&]*/i',
            '$1=***',
            $query
        ) ?? $query;
    }

    private function matchCritical(string $haystack): ?string
    {
        // Les motifs du projet s'ajoutent : on n'en retire jamais.
        foreach (array_merge(self::CRITICAL_PATTERNS, $this->motifsAjoutes) as $name => $pattern) {
            if (preg_match($pattern, $haystack) === 1) {
                return $name;
            }
        }

        return null;
    }

    private function isSuspicious(string $haystack): bool
    {
        foreach (self::SUSPICIOUS_PATTERNS as $pattern) {
            if (preg_match($pattern, $haystack) === 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * Vrai si cette IP a deja depasse son quota de lignes d'erreur sur la fenetre.
     */
    private function isFlooding(string $ip, string $type): bool
    {
        return $this->bump('flood_' . $ip . '_' . $type, $this->seuils['flood_fenetre']) > $this->seuils['flood_max'];
    }

    private function evaluateAlerts(
        string $type,
        ?string $critical,
        string $path,
        int $status,
        string $ip,
        Request $request,
        array $meta,
    ): void {
        // Deja bloquee : rien a reevaluer, et surtout aucun compteur a incrementer.
        if ($type === 'ip_blocked') {
            return;
        }

        $reason = null;
        $detail = null;

        if ($critical !== null) {
            $reason = 'Tentative d\'exploitation';
            $detail = 'Motif detecte : ' . $critical;
        } elseif ($type === 'access_denied') {
            $count = $this->bump('bf_' . $ip, $this->seuils['bruteforce_fenetre']);
            // >= et non == : deux requetes concurrentes peuvent faire sauter la
            // valeur exacte. Le cooldown par IP empeche deja la repetition du mail.
            if ($count >= $this->seuils['bruteforce']) {
                $reason = 'Bruteforce probable';
                $detail = sprintf('%d refus d\'acces en moins de %d minutes', $count, $this->seuils['bruteforce_fenetre'] / 60);
            }
        } elseif ($type === 'scan_probe' || $type === 'not_found') {
            $count = $this->bump('burst_' . $ip, $this->seuils['rafale_fenetre']);
            if ($count >= $this->seuils['rafale']) {
                $reason = 'Scan automatise';
                $detail = sprintf('%d sondes en moins de %d minutes', $count, $this->seuils['rafale_fenetre'] / 60);
            }
        }

        if ($reason === null) {
            return;
        }

        // Le blocage suit exactement les seuils qui declenchaient deja l'alerte
        // mail : ce qui meritait qu'on previenne un humain merite qu'on ferme la
        // porte. La difference, c'est que la porte se referme sans attendre
        // qu'on lise ses mails.
        $blocked = $this->autoBlock($ip, $path, $reason, $detail);

        if (!$this->acquireAlertSlot($ip)) {
            return;
        }

        if ($blocked !== null) {
            $detail .= sprintf(
                ' — IP bloquee automatiquement (%s)',
                $blocked->isPermanent() ? 'definitivement' : 'jusqu\'au ' . $blocked->getExpiresAt()->format('d/m/Y H:i')
            );
        }

        $this->notifier->prevenir([
            'reason'     => $reason,
            'detail'     => $detail,
            'ip'         => $ip,
            'path'       => $path,
            'method'     => $request->getMethod(),
            'query'      => $meta['query'] ?? null,
            'status'     => $status,
            'user_agent' => $request->headers->get('User-Agent'),
        ]);
    }

    /**
     * Inscrit l'IP sur la blocklist, sauf exemption de chemin.
     */
    private function autoBlock(string $ip, string $path, string $reason, ?string $detail): ?BlockedIp
    {
        foreach (self::NEVER_AUTOBLOCK_PREFIXES as $prefix) {
            if (str_starts_with($path, $prefix)) {
                $this->logger->info('Blocage automatique ecarte : chemin exempte', ['ip' => $ip, 'path' => $path]);

                return null;
            }
        }

        return $this->blocklist->block($ip, $detail !== null ? $reason . ' — ' . $detail : $reason);
    }

    /**
     * Incremente un compteur a fenetre glissante et renvoie sa valeur.
     * Approximatif par nature (pas d'atomicite) : suffisant pour un seuil.
     */
    private function bump(string $key, int $ttl): int
    {
        try {
            $item = $this->cache->getItem('sev_' . preg_replace('/[^a-z0-9_]/i', '_', $key));
            $count = ($item->isHit() ? (int) $item->get() : 0) + 1;
            $item->set($count)->expiresAfter($ttl);
            $this->cache->save($item);

            return $count;
        } catch (\Throwable) {
            return 0;
        }
    }

    /**
     * Anti-spam de l'alerte : au plus un mail par IP et par heure.
     */
    private function acquireAlertSlot(string $ip): bool
    {
        try {
            $item = $this->cache->getItem('sev_alert_' . preg_replace('/[^a-z0-9_]/i', '_', $ip));
            if ($item->isHit()) {
                return false;
            }
            $item->set(1)->expiresAfter($this->repitAlerte);
            $this->cache->save($item);

            return true;
        } catch (\Throwable) {
            return false;
        }
    }
}
