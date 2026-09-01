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
 * Checks that Sentinelle can do its job.
 *
 * This command exists because of an evening spent chasing nothing. The bundle
 * installed, loaded, listed its ten services — and wrote not a single row. It
 * took reading the application logs to find a `ClassNotFoundError` thrown on
 * every request and swallowed by a `try/catch` on `kernel.terminate`, where
 * nobody is listening any more.
 *
 * Each check below matches a way the mechanism can fail silently:
 *
 *   - with no cache, `bump()` always returns 0, no threshold ever fires, and
 *     detection is disarmed without anything saying so;
 *   - with no table, the insert fails and the error goes to a warning;
 *   - with an empty allowlist, an automatic block can lock you out of your own
 *     site;
 *   - with an unreachable mailer, alerts never leave and nobody knows.
 *
 * Whatever protects you should be able to say whether it is in a position to.
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

        // The cache. Without it no threshold ever fires.
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

        // The two tables.
        foreach (['sentinelle_visit', 'sentinelle_blocked_ip'] as $table) {
            try {
                $this->connection->fetchOne("SELECT COUNT(*) FROM $table");
                $io->text("<info>ok</info>   table <comment>$table</comment> exists");
            } catch (\Throwable) {
                $problems[] = "Table $table is missing. Run "
                    .'doctrine:migrations:diff then doctrine:migrations:migrate.';
            }
        }

        // The allowlist — the one thing that keeps you from locking yourself out.
        $declared = array_filter(array_map('trim', explode(',', $this->allowlist ?? '')));
        if ([] === $declared) {
            $problems[] = 'Allowlist is empty. Private ranges are protected by default, '
                .'but not your own outbound address: an automatic block '
                .'could lock you out of your own site. Set '
                .'sentinelle.never_block.ips before going live.';
        } else {
            $io->text(sprintf('<info>ok</info>   %d address(es) allowlisted', \count($declared)));
        }

        // Where alerts are sent.
        if (false === filter_var($this->recipient, \FILTER_VALIDATE_EMAIL)) {
            $problems[] = sprintf('"%s" is not a valid address: alerts '
                .'will not be sent.', $this->recipient);
        } else {
            $io->text('<info>ok</info>   alerts will go to <comment>'.$this->recipient.'</comment>');
        }

        /* Current state. This count is guarded because it queries a table whose
           absence may have just been reported: without the guard the command
           stopped dead in the middle of its report, the remaining checks never
           ran, and you never learned that the allowlist was empty. A diagnostic
           tool that crashes on what it diagnoses diagnoses nothing. */
        try {
            $active = \count($this->blocklist->activeEntries());
        } catch (\Throwable) {
            $active = 0;
        }

        $io->newLine();
        if ($this->dryRun) {
            $io->warning('Dry-run active: Sentinelle detects, logs and alerts, '
                .'but blocks NOTHING. Simulated blocks appear in the application '
                .'logs. Set sentinelle.dry_run to false once you have seen what it '
                .'would have shut out.');
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