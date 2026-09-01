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
 * Efface les blocages expires et les vieilles visites.
 *
 * ⚠ CETTE COMMANDE N'EXISTAIT PAS. Le depot prevoyait `purgeExpired()` et son
 * commentaire expliquait pourquoi elle etait indispensable — mais rien ne
 * l'appelait. Sans elle, deux choses se degradent en silence :
 *
 *   · la table des visites grossit sans fin ;
 *   · et surtout LES RECIDIVES NE SE REINITIALISENT JAMAIS. Une adresse bloquee
 *     il y a six mois repasse directement en deuxieme recidive au premier scan,
 *     et ecope de sept jours la ou elle meritait vingt-quatre heures.
 *
 * *Une methode ecrite mais jamais appelee est une intention, pas un mecanisme.*
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
            ->addOption('jours', null, InputOption::VALUE_REQUIRED,
                'Age in days of visits to delete', '30')
            ->addOption('a-blanc', null, InputOption::VALUE_NONE,
                'Count without deleting anything');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $jours = max(1, (int) $input->getOption('jours'));
        $avant = new \DateTimeImmutable(sprintf('-%d days', $jours));
        $blanc = (bool) $input->getOption('a-blanc');

        $visits = (int) $this->connection->fetchOne(
            'SELECT COUNT(*) FROM sentinelle_visit WHERE created_at < :avant',
            ['avant' => $avant->format('Y-m-d H:i:s')]
        );

        if ($blanc) {
            $io->text(sprintf('%d visit(s) older than %d days would be deleted.', $visits, $jours));
            $io->text('Expired blocks: not counted in dry-run mode.');

            return Command::SUCCESS;
        }

        $bloquages = $this->blocklist->purgeExpired(new \DateTimeImmutable());

        $this->connection->executeStatement(
            'DELETE FROM sentinelle_visit WHERE created_at < :avant',
            ['avant' => $avant->format('Y-m-d H:i:s')]
        );

        $io->success(sprintf(
            '%d expired block(s) and %d visit(s) older than %d days deleted.',
            $bloquages, $visits, $jours
        ));

        return Command::SUCCESS;
    }
}
