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
     * Blocks still in force, most recent first.
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
     * The addresses the listener must turn away, as a plain array.
     *
     * Deliberately minimal: this result is cached and read back on every
     * request, so there is no point hydrating full entities for an in_array.
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
     * Removes expired blocks.
     *
     * Without this the table grows forever and the strike history becomes
     * wrong: an address blocked six months ago would come back as a repeat
     * offender on its first scan.
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