<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Command;

use Acencyril\SentinelleBundle\Service\IpBlocklist;
use Doctrine\DBAL\Connection;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Deletes expired blocks and old visits.
 *
 * This command did not exist. The repository provided `purgeExpired()`, and its
 * comment explained why it mattered — but nothing ever called it. Without it,
 * two things degrade quietly: the visits table grows forever, and, more
 * importantly, strike counters never reset. An address blocked six months ago
 * comes back straight at strike two on its first scan, earning seven days where
 * it deserved twenty-four hours.
 *
 * A method that is written but never called is an intention, not a mechanism.
 */
#[AsCommand(
    name: 'sentinelle:purge',
    description: 'Purge expired blocks and old visits'
)]
class PurgeCommand extends Command
{
    public function __construct(
        private IpBlocklist $blocklist,
        private Connection $connection,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption('days', null, InputOption::VALUE_REQUIRED,
                'Age in days of visits to delete', '30')
            ->addOption('dry-run', null, InputOption::VALUE_NONE,
                'Count without deleting anything');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $days = max(1, (int) $input->getOption('days'));
        $before = new \DateTimeImmutable(sprintf('-%d days', $days));
        $dryRun = (bool) $input->getOption('dry-run');

        $visits = (int) $this->connection->fetchOne(
            'SELECT COUNT(*) FROM sentinelle_visit WHERE created_at < :before',
            ['before' => $before->format('Y-m-d H:i:s')]
        );

        if ($dryRun) {
            $io->text(sprintf('%d visit(s) older than %d days would be deleted.', $visits, $days));
            $io->text('Expired blocks: not counted in dry-run mode.');

            return Command::SUCCESS;
        }

        $blocks = $this->blocklist->purgeExpired(new \DateTimeImmutable());

        $this->connection->executeStatement(
            'DELETE FROM sentinelle_visit WHERE created_at < :before',
            ['before' => $before->format('Y-m-d H:i:s')]
        );

        $io->success(sprintf(
            '%d expired block(s) and %d visit(s) older than %d days deleted.',
            $blocks, $visits, $days
        ));

        return Command::SUCCESS;
    }
}