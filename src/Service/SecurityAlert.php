<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Service;

use Acencyril\SentinelleBundle\Entity\BlockedIp;
use Psr\Log\LoggerInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * L'alerte par courrier.
 *
 * ⚠ EXTRAITE D'UNE CLASSE QUI FAISAIT AUTRE CHOSE. Dans l'application
 * d'origine, l'alerte de sécurité vivait dans un service de notifications
 * généraliste, aux côtés des messages d'inscription — lesquels dépendaient des
 * entités métier du projet. Un bundle qui embarquait ça aurait exigé ces
 * entités de toute application l'installant.
 *
 * ⚠ ET LE MESSAGE DISAIT UNE CHOSE FAUSSE. Il se terminait par :
 *   « Pour bloquer cette IP : ajouter une regle deny dans la configuration
 *     du serveur web, puis recharger. »
 * C'était vrai avant le blocage automatique. Depuis, l'IP EST DÉJÀ BLOQUÉE quand
 * le message part — `autoBlock()` s'exécute juste avant l'envoi. On demandait
 * donc à un humain réveillé la nuit d'aller éditer une configuration nginx pour
 * refaire ce qui venait de se faire tout seul.
 *
 * *Une alerte doit dire l'état du monde au moment où elle part, pas celui qu'il
 * avait quand on l'a écrite.*
 */
class SecurityAlert
{
    public function __construct(
        private MailerInterface $mailer,
        private LoggerInterface $logger,
        private UrlGeneratorInterface $routeur,
        private string $recipient,
        private string $sender,
        private string $senderName,
        private string $siteName,
    ) {
    }

    /**
     * @param array{reason:string,detail:?string,ip:string,path:string,method:string,query:?string,status:int,user_agent:?string} $context
     */
    public function notify(array $context, ?BlockedIp $blocked = null): void
    {
        $e = static fn (?string $v): string => htmlspecialchars((string) ($v ?? '—'), \ENT_QUOTES, 'UTF-8');

        $lignes = [
            'Pattern' => $e($context['detail'] ?? null),
            'IP' => $e($context['ip']),
            'Request' => $e($context['method'].' '.$context['path']),
            'Query' => $e($context['query'] ?? null),
            'Response' => $e((string) $context['status']),
            'User agent' => $e($context['user_agent'] ?? null),
            'Date' => $e((new \DateTimeImmutable())->format('d/m/Y H:i:s')),
        ];

        $corpsLignes = '';
        foreach ($lignes as $etiquette => $valeur) {
            $corpsLignes .= '<tr>'
                .'<td style="padding:6px 12px 6px 0;color:#64748b;white-space:nowrap;vertical-align:top">'.$etiquette.'</td>'
                .'<td style="padding:6px 0;font-family:monospace;word-break:break-all">'.$valeur.'</td>'
                .'</tr>';
        }

        // L'état réel du blocage, pas une consigne périmée.
        if (null === $blocked) {
            $footer = "This IP was <strong>not</strong> blocked automatically "
                .'(allowlisted, protected provider, or exempt path).';
        } elseif ($blocked->isPermanent()) {
            $footer = 'This IP is blocked <strong>permanently</strong>.';
        } else {
            $footer = 'This IP is blocked until <strong>'
                .$blocked->getExpiresAt()->format('d/m/Y à H:i').'</strong>.';
        }

        try {
            $link = $this->router->generate('sentinelle_activity', [],
                UrlGeneratorInterface::ABSOLUTE_URL);
            $footer .= ' <a href="'.$link.'">See the log and unblock it</a>.';
        } catch (\Throwable) {
            // ⚠ SANS DOMAINE CONFIGURÉ, `ABSOLUTE_URL` ÉCHOUE. Une alerte sans
            // lien reste une alerte utile ; une alerte qui ne part pas parce que
            // le routeur ignore le nom d'hôte ne protège personne.
        }

        $sujet = sprintf('🚨 Security alert %s — %s (%s)',
            $this->siteName, $context['reason'], $context['ip']);

        $this->send($sujet, <<<HTML
            <div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:16px">
              <div style="background:#b91c1c;color:#fff;padding:16px;border-radius:8px 8px 0 0;text-align:center">
                <strong style="font-size:18px">🚨 {$e($context['reason'])}</strong>
              </div>
              <div style="background:#fff;padding:16px;border:1px solid #e5e7eb;border-top:none;border-radius:0 0 8px 8px">
                <table style="width:100%;font-size:13px">{$corpsLignes}</table>
                <p style="font-size:12px;color:#64748b;margin:16px 0 0">{$footer}<br>
                At most one alert per IP per hour.</p>
              </div>
            </div>
            HTML);
    }

    private function send(string $sujet, string $html): void
    {
        try {
            $this->mailer->send((new Email())
                ->from(new Address($this->sender, $this->senderName))
                ->to($this->recipient)
                ->subject($sujet)
                ->html($html));
        } catch (\Throwable $e) {
            // ⚠ UNE ALARME QUI CASSE LE SITE PROTÈGE MOINS QU'ELLE NE DÉTRUIT.
            $this->logger->warning('Security alert not sent', [
                'sujet' => $sujet, 'error' => $e->getMessage(),
            ]);
        }
    }
}
