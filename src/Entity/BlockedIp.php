<?php

namespace Acencyril\SentinelleBundle\Entity;

use Acencyril\SentinelleBundle\Repository\BlockedIpRepository;
use Doctrine\ORM\Mapping as ORM;

/**
 * An address barred from the site.
 *
 * Before this table, blocking an IP meant adding a line to the web server
 * configuration and reloading it. Reliable but slow, and you had to remember to
 * do it. The same decision lives here: applied without a deployment, revoked
 * with one click.
 *
 * Blocks stay deliberately temporary by default. Almost every scanning address
 * is a compromised machine or a recycled cloud address, and banning them for
 * life would eventually shut the door on real visitors.
 */
#[ORM\Entity(repositoryClass: BlockedIpRepository::class)]
#[ORM\Table(name: 'sentinelle_blocked_ip')]
#[ORM\Index(name: 'idx_sentinelle_blocked_ip_expires', columns: ['expires_at'])]
class BlockedIp
{
    public const SOURCE_AUTO = 'auto';
    public const SOURCE_MANUAL = 'manual';

    #[ORM\Id, ORM\GeneratedValue, ORM\Column(type: 'integer')]
    private ?int $id = null;

    #[ORM\Column(type: 'string', length: 45, unique: true)]
    private string $ip;

    /** Readable reason, shown as-is on the dashboard. */
    #[ORM\Column(type: 'string', length: 255)]
    private string $reason;

    #[ORM\Column(type: 'string', length: 10)]
    private string $source = self::SOURCE_AUTO;

    /**
     * How many times this address has been blocked. Used to lengthen the
     * sentence: an address that comes back after expiry is not a false
     * positive.
     */
    #[ORM\Column(type: 'smallint')]
    private int $strikes = 1;

    /** Null means permanent: third strike, or a manual block with no duration. */
    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $expiresAt = null;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $createdAt;

    /** Last refused request: shows whether the address is still insisting. */
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