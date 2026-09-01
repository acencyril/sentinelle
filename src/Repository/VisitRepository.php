<?php

namespace Acencyril\SentinelleBundle\Repository;

use Acencyril\SentinelleBundle\Entity\Visit;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @extends ServiceEntityRepository<Visit>
 */
class VisitRepository extends ServiceEntityRepository
{
    /** Types treated as anomalies, produced by SiteEventLogger. */
    public const SUSPICIOUS_TYPES = ['attack_attempt', 'scan_probe', 'access_denied', 'server_error'];

    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, Visit::class);
    }

    public function save(Visit $visit, bool $flush = false): void
    {
        $this->getEntityManager()->persist($visit);
        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }

    public function remove(Visit $visit, bool $flush = false): void
    {
        $this->getEntityManager()->remove($visit);
        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }

    /**
     * @return Visit[]
     */
    public function findLatest(string $filter = 'all', int $limit = 200): array
    {
        $qb = $this->createQueryBuilder('e')
            ->orderBy('e.createdAt', 'DESC')
            ->setMaxResults($limit);

        /* "tout" and "all" meant the same thing without knowing it. The
           controller and the template had been translated, this repository had
           not: with `filter=tout` the query looked for visits whose type was
           literally "tout" and found none, while the summary — which does not
           go through this filter — still showed thirteen rows. Both spellings
           are accepted, since renaming would break URLs already shared. A
           partial translation is worse than none: it produces a silent
           disagreement between two halves of the same code. */
        if ('suspicious' === $filter || 'anomalies' === $filter) {
            $qb->andWhere('e.eventType IN (:types)')->setParameter('types', self::SUSPICIOUS_TYPES);
        } elseif ('all' !== $filter && 'tout' !== $filter) {
            $qb->andWhere('e.eventType = :type')->setParameter('type', $filter);
        }

        return $qb->getQuery()->getResult();
    }

    /**
     * Count per event type over a period.
     *
     * @return array<string,int>
     */
    public function summarySince(\DateTimeInterface $since): array
    {
        $rows = $this->createQueryBuilder('e')
            ->select('e.eventType AS type, COUNT(e.id) AS total')
            ->andWhere('e.createdAt >= :since')
            ->setParameter('since', $since)
            ->groupBy('e.eventType')
            ->orderBy('total', 'DESC')
            ->getQuery()
            ->getArrayResult();

        return array_column($rows, 'total', 'type');
    }

    /**
     * Addresses most active on anomalous events.
     *
     * @return array<int,array{ip:string,total:int,last:\DateTimeInterface}>
     */
    public function topSuspiciousIps(\DateTimeInterface $since, int $limit = 10): array
    {
        return $this->createQueryBuilder('e')
            ->select('e.ip AS ip, COUNT(e.id) AS total, MAX(e.createdAt) AS last')
            ->andWhere('e.createdAt >= :since')
            ->andWhere('e.eventType IN (:types)')
            ->andWhere('e.ip IS NOT NULL')
            ->setParameter('since', $since)
            ->setParameter('types', self::SUSPICIOUS_TYPES)
            ->groupBy('e.ip')
            ->orderBy('total', 'DESC')
            ->setMaxResults($limit)
            ->getQuery()
            ->getArrayResult();
    }
}