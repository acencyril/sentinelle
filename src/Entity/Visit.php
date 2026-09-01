<?php

namespace Acencyril\SentinelleBundle\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
#[ORM\Table(name: "sentinelle_visit")]
#[ORM\Index(name: "idx_sentinelle_visit_created", columns: ["created_at"])]
#[ORM\Index(name: "idx_sentinelle_visit_ip_created", columns: ["ip", "created_at"])]
#[ORM\Index(name: "idx_sentinelle_visit_type_created", columns: ["event_type", "created_at"])]
class Visit
{
    #[ORM\Id, ORM\GeneratedValue, ORM\Column(type: "integer")]
    private ?int $id = null;

    #[ORM\Column(type: "string", length: 255)]
    private string $eventType;

    #[ORM\Column(type: "string", length: 255, nullable: true)]
    private ?string $url = null;

    /** Code HTTP de la reponse. Null pour les lignes anterieures a juillet 2026. */
    #[ORM\Column(type: "smallint", nullable: true)]
    private ?int $statusCode = null;

    #[ORM\Column(type: "string", length: 255, nullable: true)]
    private ?string $userAgent = null;

    #[ORM\Column(type: "string", length: 45, nullable: true)]
    private ?string $ip = null;

    #[ORM\Column(type: "json", nullable: true)]
    private array $meta = [];

    #[ORM\Column(type: "datetime")]
    private \DateTimeInterface $createdAt;

    public function __construct()
    {
        $this->createdAt = new \DateTimeImmutable();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function setId(?int $id): void
    {
        $this->id = $id;
    }

    public function getEventType(): string
    {
        return $this->eventType;
    }

    public function setEventType(string $eventType): void
    {
        $this->eventType = $eventType;
    }

    public function getUrl(): ?string
    {
        return $this->url;
    }

    public function setUrl(?string $url): void
    {
        $this->url = $url;
    }

    public function getStatusCode(): ?int
    {
        return $this->statusCode;
    }

    public function setStatusCode(?int $statusCode): void
    {
        $this->statusCode = $statusCode;
    }

    public function getUserAgent(): ?string
    {
        return $this->userAgent;
    }

    public function setUserAgent(?string $userAgent): void
    {
        $this->userAgent = $userAgent;
    }

    public function getIp(): ?string
    {
        return $this->ip;
    }

    public function setIp(?string $ip): void
    {
        $this->ip = $ip;
    }

    public function getMeta(): array
    {
        return $this->meta;
    }

    public function setMeta(array $meta): void
    {
        $this->meta = $meta;
    }

    public function getCreatedAt(): \DateTimeInterface
    {
        return $this->createdAt;
    }

    public function setCreatedAt(\DateTimeInterface $createdAt): void
    {
        $this->createdAt = $createdAt;
    }

}
