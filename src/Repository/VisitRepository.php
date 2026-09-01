<?php

namespace Acencyril\SentinelleBundle\Repository;

use Acencyril\SentinelleBundle\Entity\Visit;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @extends ServiceEntityRepository<BlockedIp>
 */
class VisitRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, Visit::class);
    }

    public function save(Visit $siteEvent, bool $flush = false): void
    {
        $this->getEntityManager()->persist($siteEvent);
        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }

    public function remove(Visit $siteEvent, bool $flush = false): void
    {
        $this->getEntityManager()->remove($siteEvent);
        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }

    /** Types consideres comme anormaux, produits par SiteEventLogger. */
    public const SUSPICIOUS_TYPES = ['attack_attempt', 'scan_probe', 'access_denied', 'server_error'];

    public function findLatest(string $filter = 'tout', int $limit = 200): array
    {
        $qb = $this->createQueryBuilder('e')
            ->orderBy('e.createdAt', 'DESC')
            ->setMaxResults($limit);

        /* ⚠ « tout » ET « all » DÉSIGNAIENT LA MÊME CHOSE SANS SE CONNAÎTRE. Le
           contrôleur et le gabarit ont été traduits en français, pas ce dépôt :
           avec `filter=tout`, la requête cherchait les visites dont le TYPE vaut
           littéralement « tout », et n'en trouvait aucune. Le résumé, qui ne
           passe pas par ce filter, affichait pourtant treize lignes.
           On accepte les deux, faute de pouvoir renommer sans casser les URL
           déjà partagées. *Une traduction partielle est pire qu'aucune : elle
           produit un désaccord silencieux entre deux moitiés du même code.* */
        if ('suspicious' === $filter || 'anomalies' === $filter) {
            $qb->andWhere('e.eventType IN (:types)')->setParameter('types', self::SUSPICIOUS_TYPES);
        } elseif ('all' !== $filter && 'tout' !== $filter) {
            $qb->andWhere('e.eventType = :type')->setParameter('type', $filter);
        }

        return $qb->getQuery()->getResult();
    }

    /**
     * Compteur par type d'evenement sur une periode.
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
     * IP les plus actives sur les events anormaux.
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
