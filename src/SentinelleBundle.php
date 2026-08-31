<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle;

use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 * Sentinelle — journalise les visites, reconnaît les attaques, ferme la porte.
 *
 * Extrait d'une application en production. Rien n'est réinventé : les motifs de
 * détection, les seuils et la progressivité des peines viennent d'incidents
 * réels, et les commentaires qui les expliquent sont conservés tels quels — ils
 * valent plus que le code.
 */
class SentinelleBundle extends Bundle
{
    public function getPath(): string
    {
        return \dirname(__DIR__);
    }
}