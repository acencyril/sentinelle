<?php

namespace Acencyril\SentinelleBundle\Entity;

use Acencyril\SentinelleBundle\Repository\IpBloqueeRepository;
use Doctrine\ORM\Mapping as ORM;

/**
 * Une IP interdite d'acces au site.
 *
 * Avant cette table, bloquer une IP voulait dire ajouter une ligne dans la
 * configuration du serveur web puis la recharger. Fiable mais lent, et il
 * fallait y penser. La même décision vit ici : applicable sans redéploiement,
 * révocable d'un clic.
 *
 * Le blocage reste volontairement temporaire par defaut : la quasi-totalite des
 * IP scannees sont des machines compromises ou des adresses cloud recyclees,
 * les bannir a vie finirait par fermer la porte a de vrais visiteurs.
 */
#[ORM\Entity(repositoryClass: IpBloqueeRepository::class)]
#[ORM\Table(name: 'sentinelle_ip_bloquee')]
#[ORM\Index(name: 'idx_sentinelle_ip_expires', columns: ['expires_at'])]
class IpBloquee
{
    public const SOURCE_AUTO = 'auto';
    public const SOURCE_MANUAL = 'manual';

    #[ORM\Id, ORM\GeneratedValue, ORM\Column(type: 'integer')]
    private ?int $id = null;

    #[ORM\Column(type: 'string', length: 45, unique: true)]
    private string $ip;

    /** Motif lisible, affiche tel quel dans le dashboard. */
    #[ORM\Column(type: 'string', length: 255)]
    private string $reason;

    #[ORM\Column(type: 'string', length: 10)]
    private string $source = self::SOURCE_AUTO;

    /**
     * Nombre de blocages successifs de cette IP. Sert a allonger la peine :
     * une IP qui revient apres expiration n'est pas un faux positif.
     */
    #[ORM\Column(type: 'smallint')]
    private int $strikes = 1;

    /** Null = blocage permanent (3e récidive, ou blocage manuel sans durée). */
    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $expiresAt = null;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $createdAt;

    /** Derniere requete refusee : montre si l'IP insiste encore. */
    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $lastHitAt = null;

    #[ORM\Column(type: 'integer')]
    private int $hitCount = 0;

    public function __construct(string $ip, string $reason, string $source = self::SOURCE_AUTO)
    {
        $this->ip = $ip;
        $this->reason = $reason;
        $this->source = $source;
        $this->createdAt = new \DateTimeImmutable();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getIp(): string
    {
        return $this->ip;
    }

    public function getReason(): string
    {
        return $this->reason;
    }

    public function setReason(string $reason): self
    {
        $this->reason = $reason;

        return $this;
    }

    public function getSource(): string
    {
        return $this->source;
    }

    public function setSource(string $source): self
    {
        $this->source = $source;

        return $this;
    }

    public function getStrikes(): int
    {
        return $this->strikes;
    }

    public function setStrikes(int $strikes): self
    {
        $this->strikes = $strikes;

        return $this;
    }

    public function getExpiresAt(): ?\DateTimeImmutable
    {
        return $this->expiresAt;
    }

    public function setExpiresAt(?\DateTimeImmutable $expiresAt): self
    {
        $this->expiresAt = $expiresAt;

        return $this;
    }

    public function isPermanent(): bool
    {
        return $this->expiresAt === null;
    }

    public function isExpired(?\DateTimeImmutable $now = null): bool
    {
        return $this->expiresAt !== null && $this->expiresAt <= ($now ?? new \DateTimeImmutable());
    }

    public function getCreatedAt(): \DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function getLastHitAt(): ?\DateTimeImmutable
    {
        return $this->lastHitAt;
    }

    public function getHitCount(): int
    {
        return $this->hitCount;
    }

    public function registerHit(): self
    {
        $this->hitCount++;
        $this->lastHitAt = new \DateTimeImmutable();

        return $this;
    }
}
