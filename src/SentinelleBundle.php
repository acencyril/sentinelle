<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle;

use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 * Sentinelle — logs traffic, recognises attacks, closes the door.
 *
 * Extracted from an application running in production. Nothing here is
 * reinvented: the detection patterns, the thresholds and the escalating
 * penalties all come from real incidents, and the comments explaining them are
 * kept as they were.
 *
 * Extracting it meant removing seven assumptions the original made about its
 * host: the admin address, the sender, the domain in links, the site name in
 * subjects, the access role, the parent template and the back-link route. All
 * of them are configuration now.
 *
 * Note `Bundle` rather than `AbstractBundle`: the latter carries its own
 * configuration and ignores an extension class written alongside it, which
 * leaves the bundle loading fine with an empty configuration tree.
 */
class SentinelleBundle extends Bundle
{
    public function getPath(): string
    {
        return \dirname(__DIR__);
    }
}