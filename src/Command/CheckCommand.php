<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Command;

use Acencyril\SentinelleBundle\Service\IpBlocklist;
use Doctrine\DBAL\Connection;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Verifie que Sentinelle peut faire son travail.
 *
 * ⚠ CETTE COMMANDE EXISTE À CAUSE D'UNE SOIRÉE PERDUE. Le bundle s'installait,
 * se chargeait, listait ses dix services — et n'ecrivait pas une ligne. Il a
 * fallu remonter jusqu'aux journaux applicatifs pour decouvrir qu'une
 * `ClassNotFoundError` partait a chaque requete, avalee par un `try/catch` sur
 * `kernel.terminate` ou plus personne n'ecoute.
 *
 * Chaque controle ci-dessous correspond a une facon dont le mecanisme peut
 * echouer EN SILENCE :
 *
 *   · sans cache, `bump()` rend toujours 0 et aucun seuil ne se declenche —
 *     la detection est desarmee sans que rien ne le signale ;
 *   · sans table, l'insertion echoue et l'erreur part dans un avertissement ;
 *   · sans liste blanche, un blocage automatique peut vous fermer votre
 *     propre site ;
 *   · sans mailer joignable, les alertes ne partent pas et personne ne le sait.
 *
 * *Ce qui protege doit pouvoir dire s'il est en etat de le faire.*
 */
#[AsCommand(
    name: 'sentinelle:check',
    description: 'Check that Sentinelle can do its job'
)]
class CheckCommand extends Command
{
    public function __construct(
        private Connection $connection,
        private CacheItemPoolInterface $cache,
        private IpBlocklist $blocklist,
        private ?string $allowlist,
        private bool $dryRun,
        private string $recipient,
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $io->title('Sentinelle');
        $problems = [];

        // --- le cache. Sans lui, aucun seuil ne se declenche jamais.
        try {
            $item = $this->cache->getItem('sentinelle_probe_'.bin2hex(random_bytes(4)));
            $item->set(1)->expiresAfter(10);
            $this->cache->save($item);
            $io->text('<info>ok</info>   cache responds');
        } catch (\Throwable $e) {
            $problems[] = 'Cache is unreachable: counters will always return zero, '
                .'no threshold will ever fire, and detection is disarmed SILENTLY. '
                .'('.$e->getMessage().')';
        }

        // --- les deux tables
        foreach (['sentinelle_visit', 'sentinelle_blocked_ip'] as $table) {
            try {
                $this->connection->fetchOne("SELECT COUNT(*) FROM $table");
                $io->text("<info>ok</info>   table <comment>$table</comment> exists");
            } catch (\Throwable) {
                $problems[] = "Table $table is missing. Run "
                    .'doctrine:migrations:diff then doctrine:migrations:migrate.';
            }
        }

        // --- la liste blanche. Celle qui evite de se fermer la porte.
        $declared = array_filter(array_map('trim', explode(',', $this->allowlist ?? '')));
        if ([] === $declared) {
            $problems[] = 'Allowlist is empty. Private ranges are protected by default, '
                .'but not your own outbound address: an automatic block '
                .'could lock you out of your own site. Set '
                .'sentinelle.jamais_bloquer.ips avant la mise en production.';
        } else {
            $io->text(sprintf('<info>ok</info>   %d address(es) allowlisted', \count($declared)));
        }

        // --- le destinataire des alertes
        if (false === filter_var($this->recipient, \FILTER_VALIDATE_EMAIL)) {
            $problems[] = sprintf('"%s" is not a valid address: alerts '
                .'will not be sent.', $this->recipient);
        } else {
            $io->text('<info>ok</info>   alerts will go to <comment>'.$this->recipient.'</comment>');
        }

        // --- l'etat courant
        /* ⚠ CE COMPTAGE N'ÉTAIT PAS PROTÉGÉ, alors qu'il interroge une table
    dont on vient peut-être de constater l'absence. La commande s'arrêtait
    donc net au milieu de son rapport : les trois contrôles suivants ne
    s'exécutaient jamais, et l'on ignorait que la liste blanche était vide.

    *Un outil de diagnostic qui plante sur ce qu'il diagnostique ne
    diagnostique rien.* */
        try {
            $active = \count($this->blocklist->activeEntries());
        } catch (\Throwable) {
            $active = 0;
        }
        $io->newLine();
        if ($this->dryRun) {
            $io->warning("Dry-run active: Sentinelle detects, logs and alerts, "
                ."but blocks NOTHING. Simulated blocks appear in the application "
                ."logs. Set sentinelle.dry_run to false once you have seen what it "
                ."would have shut out.");
        } else {
            $io->text(sprintf('Blocking <info>active</info> — %d address(es) currently blocked.', $active));
        }

        if ([] !== $problems) {
            $io->newLine();
            $io->error('Sentinelle cannot do its job:');
            $io->listing($problems);

            return Command::FAILURE;
        }

        $io->newLine();
        $io->success('Everything is in place.');

        return Command::SUCCESS;
    }
}
