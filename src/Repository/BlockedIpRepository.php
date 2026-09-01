<?php

namespace Acencyril\SentinelleBundle\Repository;

use Acencyril\SentinelleBundle\Entity\BlockedIp;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @extends ServiceEntityRepository<BlockedIp>
 */
class BlockedIpRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, BlockedIp::class);
    }

    public function findOneByIp(string $ip): ?BlockedIp
    {
        return $this->findOneBy(['ip' => $ip]);
    }

    /**
     * Blocages encore actifs, les plus recents d'abord.
     *
     * @return BlockedIp[]
     */
    public function findActive(): array
    {
        return $this->createQueryBuilder('b')
            ->andWhere('b.expiresAt IS NULL OR b.expiresAt > :now')
            ->setParameter('now', new \DateTimeImmutable())
            ->orderBy('b.createdAt', 'DESC')
            ->getQuery()
            ->getResult();
    }

    /**
     * Les seules IP que le listener doit refuser, sous forme de simple tableau.
     * Volontairement minimal : ce resultat est mis en cache et relu a chaque
     * requete, inutile d'hydrater des entites completes pour un in_array.
     *
     * @return string[]
     */
    public function findActiveIps(): array
    {
        $rows = $this->createQueryBuilder('b')
            ->select('b.ip')
            ->andWhere('b.expiresAt IS NULL OR b.expiresAt > :now')
            ->setParameter('now', new \DateTimeImmutable())
            ->getQuery()
            ->getScalarResult();

        return array_column($rows, 'ip');
    }

    /**
     * Supprime les blocages expires. Sans ca la table grossit indefiniment et
     * l'historique des strikes devient faux : une IP bloquee il y a six mois
     * repasserait en recidive au premier scan.
     */
    public function purgeExpired(\DateTimeImmutable $before): int
    {
        return $this->createQueryBuilder('b')
            ->delete()
            ->andWhere('b.expiresAt IS NOT NULL AND b.expiresAt < :before')
            ->setParameter('before', $before)
            ->getQuery()
            ->execute();
    }
}
