#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * corswhy — why the browser blocked your cross-origin request.
 * One file, zero Composer dependencies. PHP 8.1+.
 *
 * Follows the Fetch standard (CORS-preflight fetch + CORS check):
 * https://fetch.spec.whatwg.org/#http-cors-protocol
 */

namespace CorsWhy;

final class Finding
{
    /** @param array<string, string> $params */
    public function __construct(
        public readonly string $id,
        public readonly string $level,
        public readonly array $params = [],
    ) {
    }
}

final class Hop
{
    /** @param array<string, list<string>> $headers */
    public function __construct(
        public readonly int $status,
        public readonly array $headers,
        public readonly string $url = '',
    ) {
    }

    /** @param array<string, string|list<string>> $headers */
    public static function of(int $status, array $headers, string $url = ''): self
    {
        $norm = [];
        foreach ($headers as $name => $value) {
            $key = strtolower((string) $name);
            $norm[$key] = is_array($value) ? array_values(array_map('strval', $value)) : [(string) $value];
        }
        return new self($status, $norm, $url);
    }
}

final class RequestProfile
{
    /**
     * @param list<array{0: string, 1: string}> $headers
     */
    public function __construct(
        public readonly string $url,
        public readonly string $origin,
        public readonly string $method,
        public readonly array $headers,
        public readonly bool $credentials,
        public readonly bool $cookiePromoted = false,
    ) {
    }

    public function isSameOrigin(): bool
    {
        if ($this->origin === 'null') {
            return false;
        }
        $target = self::serializeUrlOrigin($this->url);
        return $target !== null && $target === $this->origin;
    }

    /** @return list<array{code: string, value: string}> */
    public function preflightReasons(): array
    {
        $reasons = [];
        if (!in_array($this->method, ['GET', 'HEAD', 'POST'], true)) {
            $reasons[] = ['code' => 'method', 'value' => $this->method];
        }
        foreach ($this->unsafeHeaderNames() as $name) {
            $reasons[] = ['code' => 'header', 'value' => $name];
        }
        return $reasons;
    }

    public function needsPreflight(): bool
    {
        return $this->preflightReasons() !== [];
    }

    /** @return list<string> */
    public function unsafeHeaderNames(): array
    {
        $unsafe = [];
        $safeNames = [];
        $safeBytes = 0;
        foreach ($this->headers as [$name, $value]) {
            $lower = strtolower($name);
            if (self::isSafelisted($lower, $value)) {
                $safeNames[] = $lower;
                $safeBytes += strlen($value);
                continue;
            }
            $unsafe[] = $lower;
        }
        if ($safeBytes > 1024) {
            foreach ($safeNames as $name) {
                $unsafe[] = $name;
            }
        }
        $unsafe = array_values(array_unique($unsafe));
        sort($unsafe);
        return $unsafe;
    }

    public static function isSafelisted(string $lowerName, string $value): bool
    {
        if (strlen($value) > 128) {
            return false;
        }
        return match ($lowerName) {
            'accept' => !self::hasUnsafeByte($value),
            'accept-language', 'content-language' => (bool) preg_match('/^[0-9A-Za-z *,\-.;=]*$/', $value),
            'content-type' => self::isSafelistedContentType($value),
            'range' => self::isSafelistedRange($value),
            default => false,
        };
    }

    public static function normalizeMethod(string $method): string
    {
        $trimmed = trim($method);
        if ($trimmed === '') {
            throw new \InvalidArgumentException('Missing HTTP method.');
        }
        $upper = strtoupper($trimmed);
        if (in_array($upper, ['CONNECT', 'TRACE', 'TRACK'], true)) {
            throw new \InvalidArgumentException("Method {$upper} is a forbidden method and cannot be used in a CORS request.");
        }
        if (in_array($upper, ['DELETE', 'GET', 'HEAD', 'OPTIONS', 'POST', 'PUT'], true)) {
            return $upper;
        }
        if (!preg_match('/^[!#$%&\'*+.^_`|~0-9A-Za-z-]+$/', $trimmed)) {
            throw new \InvalidArgumentException('Invalid HTTP method.');
        }
        return $trimmed;
    }

    public static function normalizeOrigin(string $origin): string
    {
        if ($origin === 'null') {
            return 'null';
        }
        $parts = parse_url($origin);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            throw new \InvalidArgumentException('Origin must look like https://app.example.com (or the opaque origin "null").');
        }
        if (!empty($parts['user']) || isset($parts['query']) || isset($parts['fragment'])) {
            throw new \InvalidArgumentException('Origin cannot contain credentials, a query, or a fragment.');
        }
        if (isset($parts['path']) && $parts['path'] !== '' && $parts['path'] !== '/') {
            throw new \InvalidArgumentException('An Origin has no path. Drop everything after the host.');
        }
        $scheme = strtolower((string) $parts['scheme']);
        if (!in_array($scheme, ['http', 'https'], true)) {
            throw new \InvalidArgumentException('Origin scheme must be http or https.');
        }
        $host = strtolower((string) $parts['host']);
        $default = $scheme === 'https' ? 443 : 80;
        $port = isset($parts['port']) ? (int) $parts['port'] : $default;
        $serialized = $scheme . '://' . $host;
        if ($port !== $default) {
            $serialized .= ':' . $port;
        }
        return $serialized;
    }

    public static function assertUrl(string $url): void
    {
        $parts = parse_url($url);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            throw new \InvalidArgumentException('URL must look like https://api.example.com/users.');
        }
        $scheme = strtolower((string) $parts['scheme']);
        if (!in_array($scheme, ['http', 'https'], true)) {
            throw new \InvalidArgumentException('Only http and https URLs are supported.');
        }
        if (!empty($parts['user'])) {
            throw new \InvalidArgumentException('URLs with embedded usernames or passwords are refused.');
        }
    }

    private static function serializeUrlOrigin(string $url): ?string
    {
        $parts = parse_url($url);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            return null;
        }
        $scheme = strtolower((string) $parts['scheme']);
        if (!in_array($scheme, ['http', 'https'], true)) {
            return null;
        }
        $host = strtolower((string) $parts['host']);
        $default = $scheme === 'https' ? 443 : 80;
        $port = isset($parts['port']) ? (int) $parts['port'] : $default;
        $serialized = $scheme . '://' . $host;
        if ($port !== $default) {
            $serialized .= ':' . $port;
        }
        return $serialized;
    }

    private static function isSafelistedContentType(string $value): bool
    {
        if (self::hasUnsafeByte($value)) {
            return false;
        }
        $essence = strtolower(trim(explode(';', $value, 2)[0]));
        return in_array($essence, [
            'application/x-www-form-urlencoded',
            'multipart/form-data',
            'text/plain',
        ], true);
    }

    private static function isSafelistedRange(string $value): bool
    {
        return (bool) preg_match('/^bytes=\d+-\d*$/i', $value);
    }

    private static function hasUnsafeByte(string $value): bool
    {
        $len = strlen($value);
        for ($i = 0; $i < $len; $i++) {
            $byte = ord($value[$i]);
            if (($byte < 0x20 && $byte !== 0x09) || $byte === 0x7F) {
                return true;
            }
            if (in_array($value[$i], ['"', '(', ')', ':', '<', '>', '?', '@', '[', '\\', ']', '{', '}'], true)) {
                return true;
            }
        }
        return false;
    }
}

final class Report
{
    /**
     * @param list<Finding> $findings
     * @param list<array{code: string, value: string}> $reasons
     */
    public function __construct(
        public readonly string $verdict,
        public readonly array $findings,
        public readonly array $reasons,
        public readonly bool $preflightRequired,
    ) {
    }

    public function has(string $id): bool
    {
        foreach ($this->findings as $finding) {
            if ($finding->id === $id) {
                return true;
            }
        }
        return false;
    }

    /** @return list<string> */
    public function ids(): array
    {
        return array_map(static fn (Finding $finding): string => $finding->id, $this->findings);
    }
}

final class Engine
{
    public static function diagnose(RequestProfile $profile, ?Hop $preflight, ?array $actualHops): Report
    {
        $findings = [];
        $reasons = $profile->preflightReasons();

        if ($profile->cookiePromoted) {
            $findings[] = new Finding('cookie_as_credentials', 'info');
        }

        if ($profile->isSameOrigin()) {
            $findings[] = new Finding('same_origin', 'ok');
            return new Report('allowed', $findings, [], false);
        }

        $preflightFailed = false;
        if ($profile->needsPreflight()) {
            if ($preflight === null) {
                $findings[] = new Finding('preflight_missing', 'fatal');
                $preflightFailed = true;
            } else {
                $before = count($findings);
                self::inspectPreflight($profile, $preflight, $findings);
                for ($i = $before; $i < count($findings); $i++) {
                    if ($findings[$i]->level === 'fatal') {
                        $preflightFailed = true;
                        break;
                    }
                }
            }
        }

        if ($actualHops === null || $actualHops === []) {
            $findings[] = new Finding($preflightFailed ? 'actual_skipped' : 'response_missing', $preflightFailed ? 'info' : 'fatal');
        } else {
            $last = count($actualHops) - 1;
            foreach ($actualHops as $index => $hop) {
                if (!$hop instanceof Hop) {
                    throw new \InvalidArgumentException('Actual hops must be Hop instances.');
                }
                $where = $index === $last ? 'response' : 'redirect:' . ($index + 1);
                self::corsCheck($hop, $profile, $where, $findings);
                if ($index === $last && $hop->status >= 300 && $hop->status < 400) {
                    $findings[] = new Finding('ended_on_redirect', 'fatal', [
                        'status' => (string) $hop->status,
                        'location' => $hop->headers['location'][0] ?? '(none)',
                    ]);
                } elseif ($index === $last && $hop->status >= 400) {
                    $findings[] = new Finding('http_status', 'info', [
                        'status' => (string) $hop->status,
                    ]);
                }
                if ($index === $last && self::corsFailure($findings, 'response') === null) {
                    self::varyAndExpose($hop, $findings);
                }
            }
        }

        $verdict = 'allowed';
        foreach ($findings as $finding) {
            if ($finding->level === 'fatal') {
                $verdict = 'blocked';
                break;
            }
        }

        return new Report($verdict, $findings, $reasons, $profile->needsPreflight());
    }

    /** @param list<Finding> $findings */
    private static function inspectPreflight(RequestProfile $profile, Hop $hop, array &$findings): void
    {
        if ($hop->status >= 300 && $hop->status < 400) {
            $findings[] = new Finding('preflight_redirect', 'fatal', [
                'status' => (string) $hop->status,
                'location' => $hop->headers['location'][0] ?? '(none)',
            ]);
        } elseif ($hop->status < 200 || $hop->status > 299) {
            $findings[] = new Finding('preflight_status', 'fatal', [
                'status' => (string) $hop->status,
            ]);
        }

        self::corsCheck($hop, $profile, 'preflight', $findings);
        $corsFailed = self::corsFailure($findings, 'preflight') !== null;
        $methodFailed = self::checkMethod($profile, $hop, $findings);
        $headerFailed = self::checkHeaders($profile, $hop, $findings);

        if (!$corsFailed && !$methodFailed && $headerFailed === false && $hop->status >= 200 && $hop->status <= 299) {
            $maxAge = $hop->headers['access-control-max-age'][0] ?? null;
            if ($maxAge === null || trim($maxAge) === '') {
                $findings[] = new Finding('max_age_default', 'info');
            }
            if (in_array($profile->method, ['GET', 'HEAD', 'POST'], true)) {
                $methods = self::listHeader($hop, 'access-control-allow-methods');
                $listed = $methods !== null && self::listHas($methods, $profile->method);
                $wildcard = $methods !== null && self::listHas($methods, '*');
                if (!$listed && !$wildcard) {
                    $findings[] = new Finding('method_safelisted_ok', 'info', [
                        'method' => $profile->method,
                    ]);
                }
            }
        }
    }

    /** @param list<Finding> $findings */
    private static function checkMethod(RequestProfile $profile, Hop $hop, array &$findings): bool
    {
        $methods = self::listHeader($hop, 'access-control-allow-methods');
        $method = $profile->method;
        if ($methods !== null && self::listHas($methods, $method)) {
            return false;
        }
        if ($methods !== null) {
            foreach ($methods as $candidate) {
                if (strcasecmp($candidate, $method) === 0 && $candidate !== $method) {
                    $findings[] = new Finding('method_case', 'fatal', [
                        'method' => $method,
                        'found' => $candidate,
                    ]);
                    return true;
                }
            }
        }
        if (in_array($method, ['GET', 'HEAD', 'POST'], true)) {
            return false;
        }
        $wildcard = $methods !== null && self::listHas($methods, '*');
        if ($wildcard && !$profile->credentials) {
            return false;
        }
        if ($wildcard && $profile->credentials) {
            $findings[] = new Finding('method_wildcard_credentials', 'fatal', [
                'method' => $method,
            ]);
            return true;
        }
        $findings[] = new Finding('method_missing', 'fatal', [
            'method' => $method,
        ]);
        return true;
    }

    /** @param list<Finding> $findings */
    private static function checkHeaders(RequestProfile $profile, Hop $hop, array &$findings): bool
    {
        $allow = self::listHeader($hop, 'access-control-allow-headers');
        $allowLower = $allow === null ? [] : array_map('strtolower', $allow);
        $wildcard = $allow !== null && self::listHas($allow, '*');
        $failed = false;
        $names = [];
        foreach ($profile->headers as [$name]) {
            $names[] = strtolower($name);
        }
        if (in_array('authorization', $names, true) && !in_array('authorization', $allowLower, true)) {
            $findings[] = new Finding('header_authorization', 'fatal');
            $failed = true;
        }
        foreach ($profile->unsafeHeaderNames() as $name) {
            if ($name === 'authorization') {
                continue;
            }
            if (in_array($name, $allowLower, true)) {
                continue;
            }
            if ($profile->credentials || !$wildcard) {
                $findings[] = new Finding(
                    $wildcard ? 'header_wildcard_credentials' : 'header_missing',
                    'fatal',
                    ['name' => $name],
                );
                $failed = true;
            }
        }
        return $failed;
    }

    /** @param list<Finding> $findings */
    private static function corsCheck(Hop $hop, RequestProfile $profile, string $where, array &$findings): void
    {
        $values = $hop->headers['access-control-allow-origin'] ?? null;
        if ($values === null || $values === []) {
            $findings[] = new Finding('cors_missing', 'fatal', ['where' => $where]);
            return;
        }
        if (count($values) > 1) {
            $findings[] = new Finding('cors_duplicate', 'fatal', ['where' => $where]);
            return;
        }
        $acao = $values[0];
        if (!$profile->credentials && $acao === '*') {
            return;
        }
        if ($acao !== $profile->origin) {
            if ($acao === '*') {
                $findings[] = new Finding('cors_wildcard_credentials', 'fatal', [
                    'where' => $where,
                    'origin' => $profile->origin,
                ]);
                return;
            }
            if (str_contains($acao, ',')) {
                $findings[] = new Finding('cors_list', 'fatal', [
                    'where' => $where,
                    'acao' => $acao,
                ]);
                return;
            }
            if (rtrim($acao, '/') === $profile->origin && $acao !== $profile->origin) {
                $findings[] = new Finding('cors_mismatch_slash', 'fatal', [
                    'where' => $where,
                    'origin' => $profile->origin,
                    'acao' => $acao,
                ]);
                return;
            }
            $findings[] = new Finding('cors_mismatch', 'fatal', [
                'where' => $where,
                'origin' => $profile->origin,
                'acao' => $acao,
            ]);
            return;
        }
        if (!$profile->credentials) {
            return;
        }
        $credential = $hop->headers['access-control-allow-credentials'][0] ?? '';
        if ($credential !== 'true') {
            $findings[] = new Finding('cors_credentials_missing', 'fatal', [
                'where' => $where,
                'value' => $credential === '' ? '(absent)' : $credential,
            ]);
        }
    }

    /** @param list<Finding> $findings */
    private static function corsFailure(array $findings, string $wherePrefix): ?Finding
    {
        foreach ($findings as $finding) {
            if (!str_starts_with($finding->id, 'cors_')) {
                continue;
            }
            $where = $finding->params['where'] ?? '';
            if ($where === $wherePrefix || str_starts_with($where, $wherePrefix)) {
                return $finding;
            }
        }
        return null;
    }

    /** @param list<Finding> $findings */
    private static function varyAndExpose(Hop $hop, array &$findings): void
    {
        $acao = $hop->headers['access-control-allow-origin'][0] ?? '';
        if ($acao !== '' && $acao !== '*') {
            $vary = strtolower(implode(', ', $hop->headers['vary'] ?? []));
            $tokens = array_map('trim', explode(',', $vary));
            if (!in_array('origin', $tokens, true)) {
                $findings[] = new Finding('vary_origin', 'warn');
            }
        }
        $hidden = [];
        $exposed = array_map('strtolower', self::listHeader($hop, 'access-control-expose-headers') ?? []);
        $visible = [
            'cache-control', 'content-language', 'content-length', 'content-type',
            'expires', 'last-modified', 'pragma',
        ];
        $ignore = [
            'date', 'server', 'connection', 'keep-alive', 'transfer-encoding', 'content-encoding',
            'etag', 'age', 'via', 'alt-svc', 'nel', 'report-to', 'vary',
        ];
        foreach ($hop->headers as $name => $_values) {
            if (str_starts_with($name, 'access-control-') || str_starts_with($name, 'cf-') || str_starts_with($name, 'x-cache')) {
                continue;
            }
            if (in_array($name, $visible, true) || in_array($name, $ignore, true)) {
                continue;
            }
            if (in_array($name, $exposed, true) || in_array('*', $exposed, true)) {
                continue;
            }
            $hidden[] = $name;
        }
        if ($hidden !== []) {
            $findings[] = new Finding('expose_headers', 'info', [
                'names' => implode(', ', $hidden),
            ]);
        }
    }

    /** @return list<string>|null */
    private static function listHeader(Hop $hop, string $name): ?array
    {
        if (!isset($hop->headers[$name])) {
            return null;
        }
        $items = [];
        foreach ($hop->headers[$name] as $value) {
            foreach (explode(',', $value) as $part) {
                $part = trim($part);
                if ($part !== '') {
                    $items[] = $part;
                }
            }
        }
        return $items;
    }

    /** @param list<string> $items */
    private static function listHas(array $items, string $needle): bool
    {
        return in_array($needle, $items, true);
    }
}

final class Text
{
    /** @var array<string, array{level: string, en: array{title: string, detail: string}, fr: array{title: string, detail: string}}> */
    private const CATALOG = [
        'same_origin' => [
            'en' => ['title' => 'Same origin', 'detail' => 'This URL and the page origin are the same. The browser does not apply CORS, so there is nothing to allow.'],
            'fr' => ['title' => 'Même origine', 'detail' => 'Cette URL et l\'origine de la page sont identiques. Le navigateur n\'applique pas CORS : il n\'y a rien à autoriser.'],
        ],
        'cookie_as_credentials' => [
            'en' => ['title' => 'Cookie header', 'detail' => 'JavaScript cannot set the Cookie header. corswhy treated it as credentials: "include" and sends it only on the real request, never on the preflight.'],
            'fr' => ['title' => 'En-tête Cookie', 'detail' => 'JavaScript ne peut pas poser l\'en-tête Cookie. corswhy l\'a traité comme credentials: "include" et ne l\'envoie que sur la vraie requête, jamais sur le préflight.'],
        ],
        'preflight_missing' => [
            'en' => ['title' => 'Preflight not checked', 'detail' => 'This request needs an OPTIONS preflight, but no preflight response was provided.'],
            'fr' => ['title' => 'Préflight non vérifié', 'detail' => 'Cette requête exige un préflight OPTIONS, mais aucune réponse de préflight n\'a été fournie.'],
        ],
        'preflight_redirect' => [
            'en' => ['title' => 'Preflight redirected', 'detail' => 'OPTIONS returned {status} to {location}. A redirected preflight fails in browsers. Call the final URL directly.'],
            'fr' => ['title' => 'Préflight redirigé', 'detail' => 'OPTIONS a répondu {status} vers {location}. Un préflight redirigé échoue dans les navigateurs. Appelle directement l\'URL finale.'],
        ],
        'preflight_status' => [
            'en' => ['title' => 'Preflight status', 'detail' => 'OPTIONS returned {status}. The Fetch standard requires an ok status (200–299). CORS headers on any other status are ignored.'],
            'fr' => ['title' => 'Statut du préflight', 'detail' => 'OPTIONS a répondu {status}. Le standard Fetch exige un statut ok (200–299). Des en-têtes CORS sur un autre statut sont ignorés.'],
        ],
        'cors_missing' => [
            'en' => ['title' => 'No Allow-Origin', 'detail' => 'The {where} has no Access-Control-Allow-Origin header. The browser hides the response from JavaScript.'],
            'fr' => ['title' => 'Pas de Allow-Origin', 'detail' => 'La {where} n\'a pas d\'en-tête Access-Control-Allow-Origin. Le navigateur cache la réponse à JavaScript.'],
        ],
        'cors_duplicate' => [
            'en' => ['title' => 'Duplicated Allow-Origin', 'detail' => 'The {where} sends Access-Control-Allow-Origin more than once. Browsers reject that. Send the header exactly once.'],
            'fr' => ['title' => 'Allow-Origin en double', 'detail' => 'La {where} envoie Access-Control-Allow-Origin plus d\'une fois. Les navigateurs rejettent ça. Envoie l\'en-tête une seule fois.'],
        ],
        'cors_wildcard_credentials' => [
            'en' => ['title' => 'Wildcard with credentials', 'detail' => 'The {where} says Access-Control-Allow-Origin: *. A credentialed request (cookies, credentials: "include") cannot use *. Echo {origin} instead, and add Access-Control-Allow-Credentials: true.'],
            'fr' => ['title' => 'Joker avec identifiants', 'detail' => 'La {where} dit Access-Control-Allow-Origin: *. Une requête avec identifiants (cookies, credentials: "include") ne peut pas utiliser *. Renvoie {origin}, et ajoute Access-Control-Allow-Credentials: true.'],
        ],
        'cors_mismatch' => [
            'en' => ['title' => 'Origin mismatch', 'detail' => 'The browser sent origin {origin}, but the {where} allows {acao}. The match is byte-for-byte: scheme, host, and port. A list of origins in this header does not work.'],
            'fr' => ['title' => 'Origine différente', 'detail' => 'Le navigateur a envoyé l\'origine {origin}, mais la {where} autorise {acao}. La comparaison est octet par octet : schéma, hôte et port. Une liste d\'origines dans cet en-tête ne fonctionne pas.'],
        ],
        'cors_mismatch_slash' => [
            'en' => ['title' => 'Trailing slash', 'detail' => 'The browser sent {origin}, the {where} sent {acao}. An origin has no trailing slash. That single character is a mismatch.'],
            'fr' => ['title' => 'Slash final', 'detail' => 'Le navigateur a envoyé {origin}, la {where} a envoyé {acao}. Une origine n\'a pas de slash final. Ce seul caractère suffit à bloquer.'],
        ],
        'cors_list' => [
            'en' => ['title' => 'Origin list', 'detail' => 'The {where} sent Access-Control-Allow-Origin: {acao}. This header takes one origin or *, never a comma-separated list. Reflect one allowlisted origin.'],
            'fr' => ['title' => 'Liste d\'origines', 'detail' => 'La {where} a envoyé Access-Control-Allow-Origin: {acao}. Cet en-tête prend une origine ou *, jamais une liste séparée par des virgules. Renvoie une seule origine autorisée.'],
        ],
        'cors_credentials_missing' => [
            'en' => ['title' => 'Credentials not allowed', 'detail' => 'The origin matches, but Access-Control-Allow-Credentials on the {where} must be the exact lowercase token true. Got: {value}.'],
            'fr' => ['title' => 'Identifiants refusés', 'detail' => 'L\'origine correspond, mais Access-Control-Allow-Credentials sur la {where} doit être exactement le jeton true en minuscules. Reçu : {value}.'],
        ],
        'method_case' => [
            'en' => ['title' => 'Method casing', 'detail' => 'The browser asks to send {method}, but Access-Control-Allow-Methods contains {found}. After normalization the comparison is case-sensitive.'],
            'fr' => ['title' => 'Casse de la méthode', 'detail' => 'Le navigateur demande {method}, mais Access-Control-Allow-Methods contient {found}. Après normalisation, la comparaison est sensible à la casse.'],
        ],
        'method_wildcard_credentials' => [
            'en' => ['title' => 'Method wildcard', 'detail' => 'Access-Control-Allow-Methods is *. On a credentialed request, * is the literal method name, not "any method". List {method} explicitly.'],
            'fr' => ['title' => 'Joker de méthode', 'detail' => 'Access-Control-Allow-Methods vaut *. Avec des identifiants, * est le nom littéral de la méthode, pas « n\'importe laquelle ». Liste {method} explicitement.'],
        ],
        'method_missing' => [
            'en' => ['title' => 'Method not allowed', 'detail' => '{method} is not a safelisted method (GET, HEAD, POST) and it is not in Access-Control-Allow-Methods. The preflight fails, so the real request is never sent.'],
            'fr' => ['title' => 'Méthode non autorisée', 'detail' => '{method} n\'est pas une méthode simple (GET, HEAD, POST) et elle n\'est pas dans Access-Control-Allow-Methods. Le préflight échoue : la vraie requête n\'est jamais envoyée.'],
        ],
        'method_safelisted_ok' => [
            'en' => ['title' => 'Safelisted method', 'detail' => '{method} is not listed in Access-Control-Allow-Methods, and it does not have to be. GET, HEAD, and POST are safelisted and still allowed.'],
            'fr' => ['title' => 'Méthode simple', 'detail' => '{method} n\'est pas listée dans Access-Control-Allow-Methods, et ce n\'est pas nécessaire. GET, HEAD et POST sont des méthodes simples : elles restent autorisées.'],
        ],
        'header_authorization' => [
            'en' => ['title' => 'Authorization is special', 'detail' => 'Authorization is a CORS non-wildcard request-header. Access-Control-Allow-Headers must list it explicitly. * does not cover it, with or without cookies.'],
            'fr' => ['title' => 'Authorization est spécial', 'detail' => 'Authorization est un en-tête CORS « non-wildcard ». Access-Control-Allow-Headers doit le citer explicitement. * ne le couvre pas, avec ou sans cookies.'],
        ],
        'header_wildcard_credentials' => [
            'en' => ['title' => 'Header wildcard', 'detail' => 'Access-Control-Allow-Headers is *. On a credentialed request, * does not cover {name}. List the header by name.'],
            'fr' => ['title' => 'Joker d\'en-tête', 'detail' => 'Access-Control-Allow-Headers vaut *. Avec des identifiants, cela ne couvre pas {name}. Liste l\'en-tête par son nom.'],
        ],
        'header_missing' => [
            'en' => ['title' => 'Header not allowed', 'detail' => 'The browser will ask to send {name}, and Access-Control-Allow-Headers does not include it. The preflight fails before the real request.'],
            'fr' => ['title' => 'En-tête non autorisé', 'detail' => 'Le navigateur demandera à envoyer {name}, et Access-Control-Allow-Headers ne le contient pas. Le préflight échoue avant la vraie requête.'],
        ],
        'vary_origin' => [
            'en' => ['title' => 'Missing Vary: Origin', 'detail' => 'Access-Control-Allow-Origin is a specific origin, but Vary does not include Origin. A shared cache can reuse this response for a different site. Add Vary: Origin.'],
            'fr' => ['title' => 'Vary: Origin manquant', 'detail' => 'Access-Control-Allow-Origin est une origine précise, mais Vary ne contient pas Origin. Un cache partagé peut resservir cette réponse à un autre site. Ajoute Vary: Origin.'],
        ],
        'max_age_default' => [
            'en' => ['title' => 'Preflight cache', 'detail' => 'Access-Control-Max-Age is missing. Browsers then cache this preflight for only 5 seconds, so OPTIONS fires on almost every call.'],
            'fr' => ['title' => 'Cache du préflight', 'detail' => 'Access-Control-Max-Age est absent. Les navigateurs ne mettent alors ce préflight en cache que 5 secondes, donc OPTIONS repart presque à chaque appel.'],
        ],
        'expose_headers' => [
            'en' => ['title' => 'Headers hidden from JS', 'detail' => 'JavaScript can only read safelisted response headers plus Access-Control-Expose-Headers. Still hidden: {names}.'],
            'fr' => ['title' => 'En-têtes cachés à JS', 'detail' => 'JavaScript ne peut lire que les en-têtes de réponse simples, plus Access-Control-Expose-Headers. Toujours cachés : {names}.'],
        ],
        'actual_skipped' => [
            'en' => ['title' => 'Real request not sent', 'detail' => 'The preflight is already a failure. The browser never sends the real request, so corswhy did not either.'],
            'fr' => ['title' => 'Vraie requête non envoyée', 'detail' => 'Le préflight est déjà un échec. Le navigateur n\'envoie jamais la vraie requête, corswhy non plus.'],
        ],
        'response_missing' => [
            'en' => ['title' => 'Response not checked', 'detail' => 'No actual response was provided. A passing preflight is not enough: the real response needs its own CORS headers.'],
            'fr' => ['title' => 'Réponse non vérifiée', 'detail' => 'Aucune vraie réponse n\'a été fournie. Un préflight réussi ne suffit pas : la vraie réponse a besoin de ses propres en-têtes CORS.'],
        ],
        'http_status' => [
            'en' => ['title' => 'HTTP {status}', 'detail' => 'The API returned {status}. That is not a CORS failure. If the CORS check passes, JavaScript can read this error body.'],
            'fr' => ['title' => 'HTTP {status}', 'detail' => 'L\'API a répondu {status}. Ce n\'est pas un échec CORS. Si le contrôle CORS passe, JavaScript peut lire ce corps d\'erreur.'],
        ],
        'ended_on_redirect' => [
            'en' => ['title' => 'Stopped on a redirect', 'detail' => 'The response is still a {status} to {location}. Cross-origin JavaScript does not follow that for you here. Request the final URL, and remember every hop needs its own CORS headers.'],
            'fr' => ['title' => 'Arrêté sur une redirection', 'detail' => 'La réponse est encore un {status} vers {location}. Le JavaScript cross-origin ne suit pas ça tout seul ici. Interroge l\'URL finale : chaque saut a besoin de ses propres en-têtes CORS.'],
        ],
    ];

    /** @return list<string> */
    public static function ids(): array
    {
        return array_keys(self::CATALOG);
    }

    /** @return array{title: string, detail: string, level: string} */
    public static function finding(string $lang, Finding $finding): array
    {
        if (!isset(self::CATALOG[$finding->id][$lang])) {
            throw new \RuntimeException('Missing translation for ' . $finding->id . ' [' . $lang . '].');
        }
        $row = self::CATALOG[$finding->id][$lang];
        $params = $finding->params;
        if (isset($params['where'])) {
            $params['where'] = self::where($lang, $params['where']);
        }
        return [
            'level' => $finding->level,
            'title' => self::fill($row['title'], $params),
            'detail' => self::fill($row['detail'], $params),
        ];
    }

    public static function banner(string $lang, string $verdict): string
    {
        if ($verdict === 'allowed') {
            return $lang === 'fr'
                ? 'AUTORISÉ   JavaScript peut lire cette réponse.'
                : 'ALLOWED    JavaScript can read this response.';
        }
        return $lang === 'fr'
            ? 'BLOQUÉ     Le navigateur n\'expose pas cette réponse à JavaScript.'
            : 'BLOCKED    The browser will not let JavaScript read this response.';
    }

    /** @param list<array{code: string, value: string}> $reasons */
    public static function because(string $lang, array $reasons): string
    {
        if ($reasons === []) {
            return $lang === 'fr' ? 'non — requête simple' : 'no — simple request';
        }
        $parts = [];
        foreach ($reasons as $reason) {
            if ($reason['code'] === 'method') {
                $parts[] = $lang === 'fr'
                    ? 'méthode ' . $reason['value']
                    : 'method ' . $reason['value'];
            } else {
                $parts[] = $reason['value'];
            }
        }
        $prefix = $lang === 'fr' ? 'oui — ' : 'yes — ';
        return $prefix . implode(', ', $parts);
    }

    public static function phpFix(RequestProfile $profile): string
    {
        $headers = $profile->unsafeHeaderNames();
        $methods = [$profile->method];
        if (!in_array('OPTIONS', $methods, true)) {
            $methods[] = 'OPTIONS';
        }
        $origin = $profile->origin;
        $allowMethods = implode(', ', $methods);
        $credentials = $profile->credentials
            ? "    header('Access-Control-Allow-Credentials: true');\n"
            : '';
        $allowHeaders = $headers === []
            ? ''
            : "header('Access-Control-Allow-Headers: " . implode(', ', $headers) . "');\n";
        return <<<PHP
            <?php
            declare(strict_types=1);

            // Reflect ONE allowlisted origin. Never echo an arbitrary Origin
            // if cookies or credentials are involved, and never send "*".
            \$allowed = ['{$origin}'];
            \$origin = \$_SERVER['HTTP_ORIGIN'] ?? '';

            if (in_array(\$origin, \$allowed, true)) {
                header('Access-Control-Allow-Origin: ' . \$origin);
                header('Vary: Origin');
            {$credentials}}

            header('Access-Control-Allow-Methods: {$allowMethods}');
            {$allowHeaders}header('Access-Control-Max-Age: 600');

            if ((\$_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
                http_response_code(204);
                exit;
            }
            PHP;
    }

    public static function nginxFix(RequestProfile $profile): string
    {
        $headers = $profile->unsafeHeaderNames();
        $methods = [$profile->method];
        if (!in_array('OPTIONS', $methods, true)) {
            $methods[] = 'OPTIONS';
        }
        $lines = [
            'add_header Access-Control-Allow-Origin "' . $profile->origin . '" always;',
            'add_header Vary "Origin" always;',
            'add_header Access-Control-Allow-Methods "' . implode(', ', $methods) . '" always;',
        ];
        if ($headers !== []) {
            $lines[] = 'add_header Access-Control-Allow-Headers "' . implode(', ', $headers) . '" always;';
        }
        $lines[] = 'add_header Access-Control-Max-Age "600" always;';
        if ($profile->credentials) {
            $lines[] = 'add_header Access-Control-Allow-Credentials "true" always;';
        }
        $lines[] = '';
        $lines[] = 'if ($request_method = OPTIONS) {';
        $lines[] = '    return 204;';
        $lines[] = '}';
        return implode("\n", $lines);
    }

    /** @param array<string, string> $params */
    private static function fill(string $template, array $params): string
    {
        $rendered = preg_replace_callback('/\{([a-z0-9_]+)\}/', static function (array $match) use ($params): string {
            $key = $match[1];
            return array_key_exists($key, $params) ? $params[$key] : $match[0];
        }, $template);
        return is_string($rendered) ? $rendered : $template;
    }

    private static function where(string $lang, string $code): string
    {
        if ($code === 'preflight') {
            return $lang === 'fr' ? 'réponse du préflight' : 'preflight response';
        }
        if ($code === 'response') {
            return $lang === 'fr' ? 'réponse' : 'response';
        }
        if (str_starts_with($code, 'redirect:')) {
            $hop = substr($code, strlen('redirect:'));
            return $lang === 'fr' ? 'redirection ' . $hop : 'redirect ' . $hop;
        }
        return $code;
    }
}

final class HttpClient
{
    public function exchange(
        string $method,
        string $url,
        array $headers,
        int $timeout,
        bool $insecure,
        bool $follow,
    ): array {
        if (function_exists('curl_init')) {
            return $this->viaCurl($method, $url, $headers, $timeout, $insecure, $follow);
        }
        return $this->viaStreams($method, $url, $headers, $timeout, $insecure, $follow);
    }

    /**
     * @param list<array{0: string, 1: string}> $headers
     * @return list<Hop>
     */
    private function viaCurl(string $method, string $url, array $headers, int $timeout, bool $insecure, bool $follow): array
    {
        $handle = curl_init();
        if ($handle === false) {
            throw new \RuntimeException('Unable to initialize curl.');
        }
        $blocks = [];
        $current = '';
        $options = [
            CURLOPT_URL => $url,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_FOLLOWLOCATION => $follow,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => min(8, $timeout),
            CURLOPT_USERAGENT => 'corswhy/1.0',
            CURLOPT_SSL_VERIFYPEER => !$insecure,
            CURLOPT_SSL_VERIFYHOST => $insecure ? 0 : 2,
            CURLOPT_HTTPHEADER => self::wireHeaders($headers),
            CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use (&$current, &$blocks): int {
                $current .= $line;
                if (rtrim($line, "\r\n") === '' && preg_match('/^HTTP\//', ltrim($current)) === 1) {
                    $blocks[] = $current;
                    $current = '';
                }
                return strlen($line);
            },
        ];
        if (defined('CURLOPT_PROTOCOLS_STR')) {
            $options[CURLOPT_PROTOCOLS_STR] = 'http,https';
            $options[CURLOPT_REDIR_PROTOCOLS_STR] = 'http,https';
        } elseif (defined('CURLOPT_PROTOCOLS')) {
            $options[CURLOPT_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS;
            $options[CURLOPT_REDIR_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS;
        }
        curl_setopt_array($handle, $options);
        $downloaded = 0;
        curl_setopt($handle, CURLOPT_WRITEFUNCTION, static function ($ch, string $data) use (&$downloaded): int {
            $downloaded += strlen($data);
            if ($downloaded > 262144) {
                return 0;
            }
            return strlen($data);
        });
        curl_exec($handle);
        $errno = curl_errno($handle);
        if ($current !== '' && preg_match('/^HTTP\//', ltrim($current)) === 1) {
            $blocks[] = $current;
        }
        $error = curl_error($handle);
        curl_close($handle);
        if ($errno !== 0 && $errno !== 23) {
            throw new \RuntimeException($error !== '' ? $error : 'Network error (' . $errno . ').');
        }
        return self::hopsFromBlocks($blocks);
    }

    /**
     * @param list<array{0: string, 1: string}> $headers
     * @return list<Hop>
     */
    private function viaStreams(string $method, string $url, array $headers, int $timeout, bool $insecure, bool $follow): array
    {
        $context = stream_context_create([
            'http' => [
                'method' => $method,
                'header' => implode("\r\n", self::wireHeaders($headers)),
                'timeout' => $timeout,
                'follow_location' => $follow ? 1 : 0,
                'max_redirects' => $follow ? 5 : 0,
                'ignore_errors' => true,
                'protocol_version' => 1.1,
            ],
            'ssl' => [
                'verify_peer' => !$insecure,
                'verify_peer_name' => !$insecure,
            ],
        ]);
        $stream = @fopen($url, 'rb', false, $context);
        if ($stream === false) {
            $last = error_get_last();
            throw new \RuntimeException($last['message'] ?? 'Request failed.');
        }
        $meta = stream_get_meta_data($stream);
        fread($stream, 1);
        fclose($stream);
        $wrapper = $meta['wrapper_data'] ?? [];
        if (!is_array($wrapper) || $wrapper === []) {
            throw new \RuntimeException('Response had no HTTP headers.');
        }
        $flat = [];
        $walker = function ($value) use (&$flat, &$walker): void {
            if (is_array($value)) {
                foreach ($value as $item) {
                    $walker($item);
                }
                return;
            }
            $flat[] = (string) $value;
        };
        $walker($wrapper);
        return self::hopsFromBlocks([implode("\r\n", $flat) . "\r\n\r\n"]);
    }

    /** @param list<string> $blocks
     *  @return list<Hop>
     */
    public static function hopsFromBlocks(array $blocks): array
    {
        $hops = [];
        foreach ($blocks as $block) {
            foreach (self::splitStatusBlocks($block) as $chunk) {
                $hop = self::parseBlock($chunk);
                if ($hop === null || ($hop->status >= 100 && $hop->status < 200)) {
                    continue;
                }
                $hops[] = $hop;
            }
        }
        if ($hops === []) {
            throw new \RuntimeException('Could not read an HTTP status line from the response.');
        }
        return $hops;
    }

    /** @return list<string> */
    public static function splitStatusBlocks(string $raw): array
    {
        $lines = preg_split("/\r\n|\n|\r/", $raw);
        if ($lines === false) {
            return [];
        }
        $blocks = [];
        $current = [];
        foreach ($lines as $line) {
            if (preg_match('/^HTTP\/\d/', $line) === 1 && $current !== []) {
                $blocks[] = implode("\n", $current);
                $current = [];
            }
            $current[] = $line;
        }
        if ($current !== []) {
            $blocks[] = implode("\n", $current);
        }
        return $blocks;
    }

    public static function parseBlock(string $raw): ?Hop
    {
        $lines = preg_split("/\r\n|\n|\r/", trim($raw));
        if ($lines === false || $lines === [] || preg_match('/^HTTP\/\d+(?:\.\d+)?\s+(\d{3})/', $lines[0], $match) !== 1) {
            return null;
        }
        $headers = [];
        $count = count($lines);
        for ($i = 1; $i < $count; $i++) {
            if ($lines[$i] === '' || !str_contains($lines[$i], ':')) {
                continue;
            }
            [$name, $value] = explode(':', $lines[$i], 2);
            $headers[strtolower(trim($name))][] = trim($value);
        }
        return new Hop((int) $match[1], $headers);
    }

    /**
     * @param list<array{0: string, 1: string}> $headers
     * @return list<string>
     */
    private static function wireHeaders(array $headers): array
    {
        $wire = [];
        foreach ($headers as [$name, $value]) {
            if (preg_match('/[\r\n]/', $name . $value) === 1) {
                throw new \InvalidArgumentException('Header values cannot contain newlines.');
            }
            $wire[] = $name . ': ' . $value;
        }
        return $wire;
    }
}

final class Cli
{
    /** @param list<string> $argv */
    public static function main(array $argv): int
    {
        try {
            $opts = self::parse($argv);
        } catch (\InvalidArgumentException $error) {
            fwrite(STDERR, $error->getMessage() . "\n");
            return 2;
        }
        $lang = $opts['lang'];
        if ($opts['help']) {
            fwrite(STDOUT, self::help($lang));
            return 0;
        }
        if ($opts['demo']) {
            return self::demo($lang, $opts['no_color']);
        }
        try {
            $profile = self::profileFromOpts($opts);
        } catch (\InvalidArgumentException $error) {
            fwrite(STDERR, $error->getMessage() . "\n");
            return 2;
        }
        if ($opts['insecure']) {
            fwrite(STDERR, ($lang === 'fr'
                ? "Attention : vérification TLS désactivée.\n"
                : "Warning: TLS verification is disabled.\n"));
        }
        try {
            $report = self::probe(new HttpClient(), $profile, $opts['timeout'], $opts['insecure']);
        } catch (\RuntimeException $error) {
            fwrite(STDERR, ($lang === 'fr' ? 'Réseau : ' : 'Network: ') . $error->getMessage() . "\n");
            return 2;
        }
        if (!empty($opts['json'])) {
            fwrite(STDOUT, self::toJson($lang, $profile, $report));
        } else {
            fwrite(STDOUT, self::render($lang, $profile, $report, self::color($opts['no_color'])));
        }
        return $report->verdict === 'allowed' ? 0 : 1;
    }

    public static function probe(HttpClient $client, RequestProfile $profile, int $timeout, bool $insecure): Report
    {
        if ($profile->isSameOrigin()) {
            return Engine::diagnose($profile, null, null);
        }
        $preflight = null;
        $preflightFailed = false;
        if ($profile->needsPreflight()) {
            $unsafe = $profile->unsafeHeaderNames();
            $headers = [
                ['Origin', $profile->origin],
                ['Access-Control-Request-Method', $profile->method],
                ['Accept', '*/*'],
            ];
            if ($unsafe !== []) {
                $headers[] = ['Access-Control-Request-Headers', implode(',', $unsafe)];
            }
            $hops = $client->exchange('OPTIONS', $profile->url, $headers, $timeout, $insecure, false);
            $preflight = $hops[0];
            $preview = Engine::diagnose($profile, $preflight, null);
            // A null actual response always adds response_missing. Any other fatal means the
            // preflight itself failed, and the browser would stop before the real request.
            $preflightFailed = !self::onlyResponseMissing($preview);
        }
        $actual = null;
        if (!$preflightFailed) {
            $headers = [['Origin', $profile->origin]];
            foreach ($profile->headers as $pair) {
                $headers[] = $pair;
            }
            $actual = $client->exchange($profile->method, $profile->url, $headers, $timeout, $insecure, false);
        }
        return Engine::diagnose($profile, $preflight, $actual);
    }

    private static function onlyResponseMissing(Report $report): bool
    {
        foreach ($report->findings as $finding) {
            if ($finding->level === 'fatal' && $finding->id !== 'response_missing') {
                return false;
            }
        }
        return true;
    }

    private static function toJson(string $lang, RequestProfile $profile, Report $report): string
    {
        $findings = [];
        foreach ($report->findings as $finding) {
            $text = Text::finding($lang, $finding);
            $findings[] = [
                'id' => $finding->id,
                'level' => $finding->level,
                'title' => $text['title'],
                'detail' => $text['detail'],
            ];
        }
        $payload = [
            'verdict' => $report->verdict,
            'url' => $profile->url,
            'origin' => $profile->origin,
            'method' => $profile->method,
            'credentials' => $profile->credentials,
            'preflight_required' => $report->preflightRequired,
            'preflight_because' => Text::because($lang, $report->reasons),
            'findings' => $findings,
        ];
        if ($report->verdict === 'blocked' && !$profile->isSameOrigin()) {
            $payload['fix'] = [
                'php' => Text::phpFix($profile),
                'nginx' => Text::nginxFix($profile),
            ];
        }
        $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            throw new \RuntimeException('Could not encode JSON.');
        }
        return $json . "\n";
    }

    /** @param array<string, mixed> $opts */
    private static function profileFromOpts(array $opts): RequestProfile
    {
        if (!is_string($opts['url']) || $opts['url'] === '') {
            throw new \InvalidArgumentException('Missing URL. Try: php corswhy.php --origin https://app.example.com https://api.example.com/users');
        }
        if (!is_string($opts['origin']) || $opts['origin'] === '') {
            throw new \InvalidArgumentException('Missing --origin. It is the page the browser is on, for example https://app.example.com.');
        }
        RequestProfile::assertUrl($opts['url']);
        $origin = RequestProfile::normalizeOrigin($opts['origin']);
        $method = RequestProfile::normalizeMethod(is_string($opts['method']) ? $opts['method'] : 'GET');
        $credentials = (bool) $opts['credentials'];
        $cookiePromoted = false;
        $headers = [];
        foreach ($opts['headers'] as $pair) {
            if (strtolower($pair[0]) === 'cookie') {
                $credentials = true;
                $cookiePromoted = true;
            }
            if (strtolower($pair[0]) === 'origin') {
                throw new \InvalidArgumentException('Do not pass Origin via --header. Use --origin.');
            }
            $headers[] = $pair;
        }
        return new RequestProfile($opts['url'], $origin, $method, $headers, $credentials, $cookiePromoted);
    }

    /**
     * @param list<string> $argv
     * @return array<string, mixed>
     */
    private static function parse(array $argv): array
    {
        $opts = [
            'help' => false,
            'demo' => false,
            'lang' => 'en',
            'origin' => '',
            'method' => 'GET',
            'headers' => [],
            'credentials' => false,
            'timeout' => 12,
            'insecure' => false,
            'no_color' => false,
            'json' => false,
            'url' => '',
        ];
        $args = array_slice($argv, 1);
        $count = count($args);
        for ($i = 0; $i < $count; $i++) {
            $arg = $args[$i];
            switch ($arg) {
                case '-h':
                case '--help':
                    $opts['help'] = true;
                    break;
                case '--demo':
                    $opts['demo'] = true;
                    break;
                case '--credentials':
                    $opts['credentials'] = true;
                    break;
                case '--insecure':
                    $opts['insecure'] = true;
                    break;
                case '--no-color':
                    $opts['no_color'] = true;
                    break;
                case '--json':
                    $opts['json'] = true;
                    break;
                case '--lang':
                case '--origin':
                case '--method':
                case '--timeout':
                case '--header':
                    $value = self::needValue($args, $i, $arg);
                    $i++;
                    if ($arg === '--lang') {
                        if (!in_array($value, ['en', 'fr'], true)) {
                            throw new \InvalidArgumentException('Supported languages: en, fr.');
                        }
                        $opts['lang'] = $value;
                    } elseif ($arg === '--origin') {
                        $opts['origin'] = $value;
                    } elseif ($arg === '--method') {
                        $opts['method'] = $value;
                    } elseif ($arg === '--timeout') {
                        if (!preg_match('/^\d+$/', $value) || (int) $value < 1 || (int) $value > 60) {
                            throw new \InvalidArgumentException('--timeout must be between 1 and 60 seconds.');
                        }
                        $opts['timeout'] = (int) $value;
                    } else {
                        $opts['headers'][] = self::splitHeader($value);
                    }
                    break;
                default:
                    if (str_starts_with($arg, '--header=')) {
                        $opts['headers'][] = self::splitHeader(substr($arg, 9));
                        break;
                    }
                    if (str_starts_with($arg, '--origin=')) {
                        $opts['origin'] = substr($arg, 9);
                        break;
                    }
                    if (str_starts_with($arg, '--method=')) {
                        $opts['method'] = substr($arg, 9);
                        break;
                    }
                    if (str_starts_with($arg, '--lang=')) {
                        $value = substr($arg, 7);
                        if (!in_array($value, ['en', 'fr'], true)) {
                            throw new \InvalidArgumentException('Supported languages: en, fr.');
                        }
                        $opts['lang'] = $value;
                        break;
                    }
                    if (str_starts_with($arg, '-')) {
                        throw new \InvalidArgumentException('Unknown option: ' . $arg);
                    }
                    if ($opts['url'] !== '') {
                        throw new \InvalidArgumentException('Only one URL is accepted.');
                    }
                    $opts['url'] = $arg;
            }
        }
        return $opts;
    }

    /** @param list<string> $args */
    private static function needValue(array $args, int $index, string $flag): string
    {
        if (!isset($args[$index + 1]) || str_starts_with($args[$index + 1], '--')) {
            throw new \InvalidArgumentException("Missing value for {$flag}.");
        }
        return $args[$index + 1];
    }

    /** @return array{0: string, 1: string} */
    private static function splitHeader(string $raw): array
    {
        if (!str_contains($raw, ':')) {
            throw new \InvalidArgumentException('Headers look like --header "Content-Type: application/json".');
        }
        [$name, $value] = explode(':', $raw, 2);
        $name = trim($name);
        $value = trim($value);
        if ($name === '' || preg_match('/^[!#$%&\'*+.^_`|~0-9A-Za-z-]+$/', $name) !== 1) {
            throw new \InvalidArgumentException('Invalid header name.');
        }
        return [$name, $value];
    }

    private static function color(bool $noColor): bool
    {
        if ($noColor || getenv('NO_COLOR') !== false) {
            return false;
        }
        return function_exists('posix_isatty') && posix_isatty(STDOUT);
    }

    private static function paint(bool $color, string $code, string $text): string
    {
        if (!$color) {
            return $text;
        }
        return "\033[" . $code . 'm' . $text . "\033[0m";
    }

    private static function render(string $lang, RequestProfile $profile, Report $report, bool $color): string
    {
        $lines = [];
        $lines[] = self::paint($color, '1', 'corswhy') . '  ' . $profile->method . ' ' . $profile->url;
        $lines[] = ($lang === 'fr' ? 'origine  ' : 'origin   ') . $profile->origin;
        $lines[] = ($lang === 'fr' ? 'cookies  ' : 'cookies  ') . ($profile->credentials ? 'include' : 'omit');
        $lines[] = ($lang === 'fr' ? 'préflight ' : 'preflight ') . Text::because($lang, $report->reasons);
        $lines[] = '';
        $bannerCode = $report->verdict === 'allowed' ? '32' : '31';
        $lines[] = self::paint($color, '1;' . $bannerCode, Text::banner($lang, $report->verdict));
        $lines[] = '';
        if ($report->findings === []) {
            $lines[] = $lang === 'fr' ? 'Aucun avertissement.' : 'No warnings.';
        }
        foreach ($report->findings as $finding) {
            if ($finding->id === 'same_origin') {
                $text = Text::finding($lang, $finding);
                $lines[] = self::paint($color, '32', '  ok     ' . $text['title']);
                $lines[] = '         ' . $text['detail'];
                $lines[] = '';
                continue;
            }
            $text = Text::finding($lang, $finding);
            $label = str_pad($text['level'], 5);
            $tone = match ($finding->level) {
                'fatal' => '31',
                'warn' => '33',
                'ok' => '32',
                default => '36',
            };
            $lines[] = '  ' . self::paint($color, $tone, $label) . '  ' . $text['title'];
            $lines[] = self::wrap($text['detail']);
            $lines[] = '';
        }
        if ($report->verdict === 'blocked' && !$profile->isSameOrigin()) {
            $heading = $lang === 'fr' ? 'Correctif PHP' : 'PHP fix';
            $nginx = $lang === 'fr' ? 'Correctif Nginx' : 'Nginx fix';
            $note = $lang === 'fr'
                ? 'L\'origine est volontairement écrite en dur. Avec des cookies, ne recopie pas n\'importe quel en-tête Origin.'
                : 'On purpose this origin is hardcoded. Do not copy an arbitrary Origin header when cookies are involved.';
            $lines[] = self::paint($color, '1', $heading);
            $lines[] = Text::phpFix($profile);
            $lines[] = '';
            $lines[] = self::paint($color, '1', $nginx);
            $lines[] = Text::nginxFix($profile);
            $lines[] = '';
            $lines[] = $note;
            $lines[] = '';
        }
        return implode("\n", $lines) . "\n";
    }

    private static function wrap(string $text): string
    {
        $wrapped = wordwrap($text, 76, "\n");
        $lines = explode("\n", $wrapped);
        return '         ' . implode("\n         ", $lines);
    }

    private static function demo(string $lang, bool $noColor): int
    {
        $color = self::color($noColor);
        $blockedProfile = new RequestProfile(
            'https://api.example.com/users',
            'https://app.example.com',
            'PATCH',
            [
                ['Content-Type', 'application/json'],
                ['Authorization', 'Bearer secret'],
            ],
            true,
        );
        $blocked = Engine::diagnose(
            $blockedProfile,
            Hop::of(204, [
                'Access-Control-Allow-Origin' => '*',
                'Access-Control-Allow-Credentials' => 'true',
                'Access-Control-Allow-Methods' => '*',
                'Access-Control-Allow-Headers' => '*',
            ]),
            null,
        );
        $allowedProfile = new RequestProfile(
            'https://api.example.com/health',
            'https://app.example.com',
            'GET',
            [],
            false,
        );
        $allowed = Engine::diagnose(
            $allowedProfile,
            null,
            [Hop::of(200, [
                'Access-Control-Allow-Origin' => 'https://app.example.com',
                'Vary' => 'Origin',
                'Content-Type' => 'application/json',
            ])],
        );
        fwrite(STDOUT, self::render($lang, $blockedProfile, $blocked, $color));
        fwrite(STDOUT, "---\n\n");
        fwrite(STDOUT, self::render($lang, $allowedProfile, $allowed, $color));
        $ok = $blocked->verdict === 'blocked'
            && $blocked->has('cors_wildcard_credentials')
            && $blocked->has('header_authorization')
            && $blocked->has('method_wildcard_credentials')
            && $allowed->verdict === 'allowed'
            && !$allowed->has('vary_origin');
        if (!$ok) {
            fwrite(STDERR, "demo assertions failed\n");
            return 1;
        }
        return 0;
    }

    private static function help(string $lang): string
    {
        if ($lang === 'fr') {
            return <<<TXT
                corswhy — pourquoi le navigateur a bloqué la requête

                Usage
                  php corswhy.php --origin https://app.example.com https://api.example.com/users
                  php corswhy.php --origin https://app.example.com --method POST \\
                      --header "Content-Type: application/json" \\
                      --header "Authorization: Bearer …" \\
                      --credentials https://api.example.com/users
                  php corswhy.php --demo
                  php corswhy.php --lang fr --demo

                Options
                  --origin URL       Origine de la page (en-tête Origin)
                  --method VERB      Méthode de la vraie requête (défaut GET)
                  --header "N: V"    En-tête que JavaScript enverrait (répétable)
                  --credentials      cookies / credentials: "include"
                  --timeout SEC      1 à 60 (défaut 12)
                  --lang en|fr       Langue du diagnostic (défaut en)
                  --json             sortie JSON
                  --insecure         ne pas vérifier TLS
                  --no-color
                  --demo             deux scénarios hors ligne
                  -h, --help

                Codes de sortie
                  0  le navigateur laisserait JavaScript lire la réponse
                  1  le navigateur bloquerait
                  2  usage ou erreur réseau

                N'interroge que des API que tu as le droit de tester.
                  Une requête OPTIONS et, si le préflight passe, une vraie requête.

                TXT;
        }
        return <<<TXT
            corswhy — why the browser blocked the request

            Usage
              php corswhy.php --origin https://app.example.com https://api.example.com/users
              php corswhy.php --origin https://app.example.com --method POST \\
                  --header "Content-Type: application/json" \\
                  --header "Authorization: Bearer …" \\
                  --credentials https://api.example.com/users
              php corswhy.php --demo
              php corswhy.php --lang fr --demo

            Options
              --origin URL       Page origin (the Origin header)
              --method VERB      Real request method (default GET)
              --header "N: V"    Header JavaScript would send (repeatable)
              --credentials      cookies / credentials: "include"
              --timeout SEC      1 to 60 (default 12)
              --lang en|fr       Diagnosis language (default en)
              --insecure         skip TLS verification
              --json             print JSON instead of text
              --no-color
              --demo             two offline scenarios
              -h, --help

            Exit codes
              0  JavaScript would be allowed to read the response
              1  the browser would block it
              2  usage or network error

            Only probe APIs you are allowed to test.
              One OPTIONS, then the real request if the preflight would pass.

            TXT;
    }
}

if (PHP_SAPI === 'cli' && isset($_SERVER['argv'][0]) && realpath($_SERVER['argv'][0]) === __FILE__) {
    exit(Cli::main($_SERVER['argv']));
}
