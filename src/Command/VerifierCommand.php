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
    name: 'sentinelle:verifier',
    description: 'Verifie que Sentinelle est en etat de fonctionner'
)]
class VerifierCommand extends Command
{
    public function __construct(
        private Connection $connection,
        private CacheItemPoolInterface $cache,
        private IpBlocklist $blocklist,
        private ?string $allowlist,
        private bool $essai,
        private string $destinataire,
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $io->title('Sentinelle');
        $soucis = [];

        // --- le cache. Sans lui, aucun seuil ne se declenche jamais.
        try {
            $item = $this->cache->getItem('sentinelle_essai_'.bin2hex(random_bytes(4)));
            $item->set(1)->expiresAfter(10);
            $this->cache->save($item);
            $io->text('<info>ok</info>   le cache repond');
        } catch (\Throwable $e) {
            $soucis[] = 'Le cache ne repond pas : les compteurs rendront toujours zero, '
                .'aucun seuil ne se declenchera, et la detection sera desarmee EN SILENCE. '
                .'('.$e->getMessage().')';
        }

        // --- les deux tables
        foreach (['sentinelle_visite', 'sentinelle_ip_bloquee'] as $table) {
            try {
                $this->connection->fetchOne("SELECT COUNT(*) FROM $table");
                $io->text("<info>ok</info>   la table <comment>$table</comment> existe");
            } catch (\Throwable) {
                $soucis[] = "La table $table est absente. Lance "
                    .'doctrine:migrations:diff puis doctrine:migrations:migrate.';
            }
        }

        // --- la liste blanche. Celle qui evite de se fermer la porte.
        $declarees = array_filter(array_map('trim', explode(',', $this->allowlist ?? '')));
        if ([] === $declarees) {
            $soucis[] = 'Aucune IP en liste blanche. Les plages privees sont protegees '
                .'d\'office, mais pas ton adresse de sortie : un blocage automatique '
                .'peut te fermer ton propre site. Renseigne '
                .'sentinelle.jamais_bloquer.ips avant la mise en production.';
        } else {
            $io->text(sprintf('<info>ok</info>   %d adresse(s) en liste blanche', \count($declarees)));
        }

        // --- le destinataire des alertes
        if (false === filter_var($this->destinataire, \FILTER_VALIDATE_EMAIL)) {
            $soucis[] = sprintf('« %s » n\'est pas une adresse valide : les alertes '
                .'ne partiront pas.', $this->destinataire);
        } else {
            $io->text('<info>ok</info>   les alertes iront a <comment>'.$this->destinataire.'</comment>');
        }

        // --- l'etat courant
        $actifs = \count($this->blocklist->activeEntries());
        $io->newLine();
        if ($this->essai) {
            $io->warning("Mode d'essai actif : Sentinelle detecte, journalise et alerte, "
                ."mais ne bloque RIEN. Les blocages simules apparaissent dans les journaux "
                ."applicatifs. Bascule sentinelle.essai a false quand tu auras vu ce qu'il "
                ."aurait ferme.");
        } else {
            $io->text(sprintf('Blocage <info>actif</info> — %d adresse(s) bloquee(s) en ce moment.', $actifs));
        }

        if ([] !== $soucis) {
            $io->newLine();
            $io->error('Sentinelle n\'est pas en etat de faire son travail :');
            $io->listing($soucis);

            return Command::FAILURE;
        }

        $io->newLine();
        $io->success('Tout est en place.');

        return Command::SUCCESS;
    }
}
