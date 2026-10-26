<?php
declare(strict_types=1);

require dirname(__DIR__) . '/corswhy.php';

use CorsWhy\Cli;
use CorsWhy\Engine;
use CorsWhy\Finding;
use CorsWhy\Hop;
use CorsWhy\HttpClient;
use CorsWhy\RequestProfile;
use CorsWhy\Text;

final class Test
{
    public int $ok = 0;
    public int $bad = 0;

    public function same(mixed $actual, mixed $expected, string $message): void
    {
        if ($actual !== $expected) {
            $this->bad++;
            fwrite(STDERR, "FAIL {$message}\n  expected: " . var_export($expected, true) . "\n  actual:   " . var_export($actual, true) . "\n");
            return;
        }
        $this->ok++;
    }

    public function truth(bool $condition, string $message): void
    {
        $this->same($condition, true, $message);
    }

    public function has(\CorsWhy\Report $report, string $id): void
    {
        $this->truth($report->has($id), $id . ' present, got [' . implode(', ', $report->ids()) . ']');
    }

    public function lacks(\CorsWhy\Report $report, string $id): void
    {
        $this->truth(!$report->has($id), $id . ' absent');
    }
}

$test = new Test();

function profile(
    string $method,
    array $headers,
    bool $credentials = false,
    string $url = 'https://api.example.com/users',
    string $origin = 'https://app.example.com',
): RequestProfile {
    return new RequestProfile($url, $origin, $method, $headers, $credentials);
}

function renderBoth(\CorsWhy\Report $report): void
{
    global $test;
    foreach ($report->findings as $finding) {
        foreach (['en', 'fr'] as $lang) {
            $text = Text::finding($lang, $finding);
            $blob = $text['title'] . $text['detail'];
            $test->truth(!str_contains($blob, '{'), "unfilled placeholder in {$finding->id} [{$lang}]");
            $test->truth($text['title'] !== '' && $text['detail'] !== '', "empty copy for {$finding->id} [{$lang}]");
        }
    }
}

foreach (Text::ids() as $id) {
    $finding = new Finding($id, 'info', [
        'where' => 'preflight',
        'origin' => 'https://app.example.com',
        'acao' => 'https://other.example.com',
        'status' => '204',
        'location' => 'https://api.example.com/next',
        'method' => 'PATCH',
        'found' => 'patch',
        'name' => 'content-type',
        'names' => 'x-request-id',
        'value' => 'TRUE',
    ]);
    foreach (['en', 'fr'] as $lang) {
        $text = Text::finding($lang, $finding);
        $test->truth(!str_contains($text['title'] . $text['detail'], '{'), "catalog {$id} {$lang}");
    }
    $redirect = new Finding($id, 'info', [
        'where' => 'redirect:2',
        'origin' => 'https://app.example.com',
        'acao' => '*',
        'status' => '302',
        'location' => 'https://api.example.com/next',
        'method' => 'DELETE',
        'found' => 'delete',
        'name' => 'x-csrf',
        'names' => 'x-request-id',
        'value' => '(absent)',
    ]);
    $french = Text::finding('fr', $redirect);
    $test->truth(!str_contains($french['detail'], '{'), "catalog redirect {$id}");
}

$test->truth(RequestProfile::isSafelisted('content-type', 'text/plain'), 'text/plain is safelisted');
$test->truth(RequestProfile::isSafelisted('content-type', 'text/plain; charset=UTF-8'), 'charset is ignored for the essence');
$test->truth(!RequestProfile::isSafelisted('content-type', 'application/json'), 'json is not safelisted');
$test->truth(!RequestProfile::isSafelisted('content-type', 'application/json; charset=utf-8'), 'json with charset is not safelisted');
$test->truth(RequestProfile::isSafelisted('content-type', 'multipart/form-data; boundary=abc'), 'multipart is safelisted');
$test->truth(!RequestProfile::isSafelisted('content-type', 'text/plain; charset="utf-8"'), 'quote is an unsafe byte');
$test->truth(!RequestProfile::isSafelisted('accept', str_repeat('a', 129)), 'value longer than 128 is unsafe');
$test->truth(RequestProfile::isSafelisted('range', 'bytes=0-'), 'open range is safelisted');
$test->truth(RequestProfile::isSafelisted('range', 'bytes=0-10'), 'closed range is safelisted');
$test->truth(!RequestProfile::isSafelisted('range', 'bytes=-10'), 'suffix range is not safelisted');
$test->truth(!RequestProfile::isSafelisted('x-custom', '1'), 'custom header is unsafe');

$big = profile('GET', [['Accept', str_repeat('a', 120)], ['Accept', str_repeat('b', 120)], ['Accept', str_repeat('c', 120)], ['Accept', str_repeat('d', 120)], ['Accept', str_repeat('e', 120)], ['Accept', str_repeat('f', 120)], ['Accept', str_repeat('g', 120)], ['Accept', str_repeat('h', 120)], ['Accept', str_repeat('i', 120)]]);
$test->same($big->needsPreflight(), true, 'safelisted headers over 1024 bytes force a preflight');
$test->truth(in_array('accept', $big->unsafeHeaderNames(), true), 'accept becomes unsafe past 1024 bytes');

$simple = profile('GET', [['Accept', 'text/html']]);
$test->same($simple->needsPreflight(), false, 'simple GET does not preflight');

$json = profile('POST', [['Content-Type', 'application/json']]);
$test->same($json->needsPreflight(), true, 'JSON content-type preflights');
$test->same($json->unsafeHeaderNames(), ['content-type'], 'unsafe name is content-type');

$test->same(RequestProfile::normalizeOrigin('https://App.Example.com:443'), 'https://app.example.com', 'default port is stripped');
$test->same(RequestProfile::normalizeOrigin('http://app.example.com:80/'), 'http://app.example.com', 'http default port and slash');
$test->same(RequestProfile::normalizeOrigin('https://app.example.com:8443'), 'https://app.example.com:8443', 'non-default port stays');
$test->same(RequestProfile::normalizeMethod('post'), 'POST', 'post is normalized');
$test->same(RequestProfile::normalizeMethod('Patch'), 'Patch', 'custom methods keep their case');

$threw = false;
try {
    RequestProfile::normalizeMethod('TRACE');
} catch (InvalidArgumentException) {
    $threw = true;
}
$test->truth($threw, 'TRACE is rejected');

$threw = false;
try {
    RequestProfile::normalizeOrigin('https://app.example.com/dashboard');
} catch (InvalidArgumentException) {
    $threw = true;
}
$test->truth($threw, 'origin path is rejected');

$threw = false;
try {
    RequestProfile::assertUrl('http://user:secret@api.example.com/');
} catch (InvalidArgumentException) {
    $threw = true;
}
$test->truth($threw, 'userinfo URL is rejected');

$same = profile('GET', [], false, 'https://app.example.com/dashboard', 'https://app.example.com');
$sameReport = Engine::diagnose($same, null, null);
$test->same($sameReport->verdict, 'allowed', 'same origin is allowed');
$test->has($sameReport, 'same_origin');
renderBoth($sameReport);

$missing = Engine::diagnose(
    profile('GET', []),
    null,
    [Hop::of(200, ['Content-Type' => 'text/html'])],
);
$test->same($missing->verdict, 'blocked', 'missing ACAO blocks a simple GET');
$test->has($missing, 'cors_missing');
$test->lacks($missing, 'preflight_missing');
renderBoth($missing);

$star = Engine::diagnose(
    profile('GET', []),
    null,
    [Hop::of(200, ['Access-Control-Allow-Origin' => '*'])],
);
$test->same($star->verdict, 'allowed', 'wildcard allows a non-credentialed GET');
$test->lacks($star, 'vary_origin');

$starCookies = Engine::diagnose(
    profile('GET', [], true),
    null,
    [Hop::of(200, [
        'Access-Control-Allow-Origin' => '*',
        'Access-Control-Allow-Credentials' => 'true',
    ])],
);
$test->same($starCookies->verdict, 'blocked', 'wildcard plus cookies is blocked');
$test->has($starCookies, 'cors_wildcard_credentials');
renderBoth($starCookies);

$exactNoCredsHeader = Engine::diagnose(
    profile('GET', [], true),
    null,
    [Hop::of(200, [
        'Access-Control-Allow-Origin' => 'https://app.example.com',
        'Vary' => 'Origin',
    ])],
);
$test->has($exactNoCredsHeader, 'cors_credentials_missing');
$test->same($exactNoCredsHeader->verdict, 'blocked', 'matching origin still needs Allow-Credentials');

$wrongCase = Engine::diagnose(
    profile('GET', [], true),
    null,
    [Hop::of(200, [
        'Access-Control-Allow-Origin' => 'https://app.example.com',
        'Access-Control-Allow-Credentials' => 'TRUE',
        'Vary' => 'Origin',
    ])],
);
$test->has($wrongCase, 'cors_credentials_missing');

$goodCookies = Engine::diagnose(
    profile('GET', [], true),
    null,
    [Hop::of(200, [
        'Access-Control-Allow-Origin' => 'https://app.example.com',
        'Access-Control-Allow-Credentials' => 'true',
        'Vary' => 'Accept, Origin',
    ])],
);
$test->same($goodCookies->verdict, 'allowed', 'explicit origin plus credentials is allowed');
$test->lacks($goodCookies, 'vary_origin');

$slash = Engine::diagnose(
    profile('GET', []),
    null,
    [Hop::of(200, ['Access-Control-Allow-Origin' => 'https://app.example.com/'])],
);
$test->has($slash, 'cors_mismatch_slash');

$list = Engine::diagnose(
    profile('GET', []),
    null,
    [Hop::of(200, ['Access-Control-Allow-Origin' => 'https://app.example.com, https://other.example.com'])],
);
$test->has($list, 'cors_list');

$dup = Engine::diagnose(
    profile('GET', []),
    null,
    [Hop::of(200, ['Access-Control-Allow-Origin' => ['https://app.example.com', 'https://app.example.com']])],
);
$test->has($dup, 'cors_duplicate');

$mismatch = Engine::diagnose(
    profile('GET', []),
    null,
    [Hop::of(200, ['Access-Control-Allow-Origin' => 'https://other.example.com'])],
);
$test->has($mismatch, 'cors_mismatch');
renderBoth($mismatch);

$myth = Engine::diagnose(
    profile('POST', [['Content-Type', 'application/json']]),
    Hop::of(204, [
        'Access-Control-Allow-Origin' => 'https://app.example.com',
        'Access-Control-Allow-Headers' => 'Content-Type',
        'Vary' => 'Origin',
    ]),
    [Hop::of(200, [
        'Access-Control-Allow-Origin' => 'https://app.example.com',
        'Vary' => 'Origin',
        'Content-Type' => 'application/json',
    ])],
);
$test->same($myth->verdict, 'allowed', 'POST does not need to be listed in Allow-Methods');
$test->has($myth, 'method_safelisted_ok');
$test->lacks($myth, 'method_missing');
$test->has($myth, 'max_age_default');
renderBoth($myth);

$put = Engine::diagnose(
    profile('PUT', []),
    Hop::of(200, [
        'Access-Control-Allow-Origin' => '*',
    ]),
    null,
);
$test->same($put->verdict, 'blocked', 'PUT without Allow-Methods is blocked');
$test->has($put, 'method_missing');
$test->has($put, 'actual_skipped');
renderBoth($put);

$putStar = Engine::diagnose(
    profile('PUT', []),
    Hop::of(200, [
        'Access-Control-Allow-Origin' => '*',
        'Access-Control-Allow-Methods' => '*',
        'Access-Control-Max-Age' => '600',
    ]),
    [Hop::of(200, ['Access-Control-Allow-Origin' => '*'])],
);
$test->same($putStar->verdict, 'allowed', 'PUT is allowed by a non-credentialed wildcard');
$test->lacks($putStar, 'method_missing');

$putStarCookies = Engine::diagnose(
    profile('PATCH', [], true),
    Hop::of(204, [
        'Access-Control-Allow-Origin' => 'https://app.example.com',
        'Access-Control-Allow-Credentials' => 'true',
        'Access-Control-Allow-Methods' => '*',
        'Vary' => 'Origin',
    ]),
    null,
);
$test->has($putStarCookies, 'method_wildcard_credentials');
$test->same($putStarCookies->verdict, 'blocked', 'credentialed wildcard method is blocked');

$case = Engine::diagnose(
    profile('DELETE', []),
    Hop::of(200, [
        'Access-Control-Allow-Origin' => '*',
        'Access-Control-Allow-Methods' => 'delete',
    ]),
    null,
);
$test->has($case, 'method_case');

$authStar = Engine::diagnose(
    profile('GET', [['Authorization', 'Bearer secret']]),
    Hop::of(204, [
        'Access-Control-Allow-Origin' => '*',
        'Access-Control-Allow-Headers' => '*',
        'Access-Control-Max-Age' => '60',
    ]),
    null,
);
$test->has($authStar, 'header_authorization');
$test->lacks($authStar, 'header_missing');
$test->same($authStar->verdict, 'blocked', 'star does not cover Authorization');
renderBoth($authStar);

$authOk = Engine::diagnose(
    profile('GET', [['Authorization', 'Bearer secret'], ['Content-Type', 'application/json']]),
    Hop::of(204, [
        'Access-Control-Allow-Origin' => '*',
        'Access-Control-Allow-Headers' => 'Authorization, Content-Type',
        'Access-Control-Max-Age' => '60',
    ]),
    [Hop::of(401, [
        'Access-Control-Allow-Origin' => '*',
        'Content-Type' => 'application/json',
    ])],
);
$test->same($authOk->verdict, 'allowed', 'explicit Authorization header is allowed');
$test->has($authOk, 'http_status');
$test->lacks($authOk, 'header_authorization');

$headerCreds = Engine::diagnose(
    profile('POST', [['Content-Type', 'application/json'], ['X-CSRF', '1']], true),
    Hop::of(204, [
        'Access-Control-Allow-Origin' => 'https://app.example.com',
        'Access-Control-Allow-Credentials' => 'true',
        'Access-Control-Allow-Headers' => '*',
        'Vary' => 'Origin',
    ]),
    null,
);
$test->has($headerCreds, 'header_wildcard_credentials');
$test->same($headerCreds->verdict, 'blocked', 'credentialed star does not cover custom headers');

$noAllowHeaders = Engine::diagnose(
    profile('POST', [['Content-Type', 'application/json']]),
    Hop::of(204, [
        'Access-Control-Allow-Origin' => '*',
    ]),
    null,
);
$test->has($noAllowHeaders, 'header_missing');

$status = Engine::diagnose(
    profile('PUT', []),
    Hop::of(404, [
        'Access-Control-Allow-Origin' => '*',
        'Access-Control-Allow-Methods' => 'PUT',
    ]),
    null,
);
$test->has($status, 'preflight_status');
$test->same($status->verdict, 'blocked', '404 preflight is blocked even with CORS headers');

$redirect = Engine::diagnose(
    profile('PUT', []),
    Hop::of(301, [
        'Location' => 'https://api.example.com/v2',
        'Access-Control-Allow-Origin' => '*',
    ]),
    null,
);
$test->has($redirect, 'preflight_redirect');
$test->lacks($redirect, 'preflight_status');

$chain = Engine::diagnose(
    profile('GET', []),
    null,
    [
        Hop::of(302, ['Location' => 'https://api.example.com/v2']),
        Hop::of(200, [
            'Access-Control-Allow-Origin' => 'https://app.example.com',
            'Vary' => 'Origin',
        ]),
    ],
);
$test->has($chain, 'cors_missing');
$test->same($chain->verdict, 'blocked', 'a redirect hop without ACAO blocks');
renderBoth($chain);

$ended = Engine::diagnose(
    profile('GET', []),
    null,
    [Hop::of(302, [
        'Location' => 'https://api.example.com/v2',
        'Access-Control-Allow-Origin' => '*',
    ])],
);
$test->has($ended, 'ended_on_redirect');
$test->same($ended->verdict, 'blocked', 'stopping on a redirect is blocked');

$vary = Engine::diagnose(
    profile('GET', []),
    null,
    [Hop::of(200, [
        'Access-Control-Allow-Origin' => 'https://app.example.com',
        'X-Request-Id' => 'abc',
    ])],
);
$test->same($vary->verdict, 'allowed', 'missing Vary is a warning, not a block');
$test->has($vary, 'vary_origin');
$test->has($vary, 'expose_headers');
renderBoth($vary);

$preflightPassesActualFails = Engine::diagnose(
    profile('POST', [['Content-Type', 'application/json']]),
    Hop::of(204, [
        'Access-Control-Allow-Origin' => '*',
        'Access-Control-Allow-Headers' => 'content-type',
        'Access-Control-Max-Age' => '10',
    ]),
    [Hop::of(200, ['Content-Type' => 'application/json'])],
);
$test->has($preflightPassesActualFails, 'cors_missing');
$test->same($preflightPassesActualFails->verdict, 'blocked', 'preflight success does not excuse the real response');
$test->lacks($preflightPassesActualFails, 'actual_skipped');

$notRun = Engine::diagnose(profile('PUT', []), null, null);
$test->has($notRun, 'preflight_missing');
$test->has($notRun, 'actual_skipped');

$parsed = HttpClient::parseBlock("HTTP/2 204\nAccess-Control-Allow-Origin: *\nX-Empty:\n\n");
$test->truth($parsed !== null && $parsed->status === 204, 'HTTP/2 status parses');
$test->same($parsed?->headers['access-control-allow-origin'][0] ?? '', '*', 'header name is normalized');

$split = HttpClient::hopsFromBlocks(["HTTP/1.1 100 Continue\n\nHTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *\n\n"]);
$test->same(count($split), 1, '100 Continue is ignored');
$test->same($split[0]->status, 200, 'the real status remains');

$multi = HttpClient::splitStatusBlocks("HTTP/1.1 302 Found\nLocation: /b\n\nHTTP/1.1 200 OK\nContent-Type: text/plain\n");
$test->same(count($multi), 2, 'redirect blocks split');

$php = Text::phpFix(profile('PATCH', [['Content-Type', 'application/json'], ['Authorization', 'Bearer x']], true));
$test->truth(str_contains($php, 'https://app.example.com'), 'fix names the origin');
$test->truth(str_contains($php, 'Access-Control-Allow-Credentials: true'), 'credentialed fix sets credentials');
$test->truth(str_contains($php, 'authorization'), 'fix lists authorization');
$test->truth(str_contains($php, 'PATCH, OPTIONS'), 'fix lists the method and OPTIONS');
$test->truth(!str_contains($php, 'Allow-Origin: *'), 'fix does not suggest a wildcard origin');
$lint = shell_exec(escapeshellarg(PHP_BINARY) . ' -l ' . escapeshellarg(dirname(__DIR__) . '/corswhy.php') . ' 2>&1');
$test->truth(is_string($lint) && str_contains($lint, 'No syntax errors'), 'generated project file still lints');
$snippet = tempnam(sys_get_temp_dir(), 'corswhy');
file_put_contents((string) $snippet, $php);
$snippetLint = shell_exec(escapeshellarg(PHP_BINARY) . ' -l ' . escapeshellarg((string) $snippet) . ' 2>&1');
$test->truth(is_string($snippetLint) && str_contains($snippetLint, 'No syntax errors'), "PHP fix lints\n{$php}\n{$snippetLint}");
unlink((string) $snippet);

$nginx = Text::nginxFix(profile('GET', []));
$test->truth(str_contains($nginx, 'Access-Control-Allow-Origin'), 'nginx fix has ACAO');

$bin = PHP_BINARY;
$script = dirname(__DIR__) . '/corswhy.php';
$run = static function (array $args) use ($bin, $script): array {
    $cmd = array_merge([$bin, $script], $args);
    $spec = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = proc_open($cmd, $spec, $pipes, dirname(__DIR__));
    if (!is_resource($proc)) {
        return [127, '', 'proc_open failed'];
    }
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    return [proc_close($proc), is_string($stdout) ? $stdout : '', is_string($stderr) ? $stderr : ''];
};

[$code, $out] = $run(['--help']);
$test->same($code, 0, 'help exits 0');
$test->truth(str_contains($out, '--origin'), 'help shows --origin');

[$code, $out] = $run(['--demo', '--no-color']);
$test->same($code, 0, 'demo exits 0');
$test->truth(str_contains($out, 'BLOCKED') && str_contains($out, 'ALLOWED'), 'demo prints both verdicts');
$test->truth(str_contains($out, 'Authorization is special'), 'demo explains Authorization');

[$code, $out] = $run(['--lang', 'fr', '--demo', '--no-color']);
$test->same($code, 0, 'french demo exits 0');
$test->truth(str_contains($out, 'BLOQUÉ') && str_contains($out, 'AUTORISÉ'), 'french demo is translated');
$test->truth(str_contains($out, 'Authorization est spécial'), 'french demo names Authorization');

[$code, $out] = $run(['--json', '--no-color', '--origin', 'https://example.com', 'https://example.com/health']);
$test->same($code, 0, 'same-origin JSON exits 0 without a network call');
$decoded = json_decode($out, true);
$test->truth(is_array($decoded) && ($decoded['verdict'] ?? '') === 'allowed', 'same-origin JSON verdict');
$test->same($decoded['findings'][0]['id'] ?? '', 'same_origin', 'same-origin JSON finding');

[$code] = $run(['--origin', 'https://app.example.com/app', 'https://api.example.com']);
$test->same($code, 2, 'bad origin exits 2');

[$code] = $run(['https://api.example.com']);
$test->same($code, 2, 'missing origin exits 2');

[$code] = $run(['--origin', 'https://app.example.com', '--method', 'TRACE', 'https://api.example.com']);
$test->same($code, 2, 'TRACE exits 2');

[$code] = $run(['--not-a-flag']);
$test->same($code, 2, 'unknown flag exits 2');

$liveUrl = 'https://example.com/';
$client = new HttpClient();
try {
    $hops = $client->exchange('GET', $liveUrl, [
        ['Origin', 'https://app.example.com'],
        ['Accept', 'text/html'],
    ], 12, false, false);
    $live = Engine::diagnose(
        profile('GET', [['Accept', 'text/html']], false, $liveUrl, 'https://app.example.com'),
        null,
        $hops,
    );
    $test->same($live->verdict, 'blocked', 'example.com does not opt into a foreign origin');
    $test->has($live, 'cors_missing');
    $test->truth($hops[0]->status >= 200 && $hops[0]->status < 400, 'example.com returned a usable status');
    fwrite(STDOUT, "live example.com status {$hops[0]->status}\n");
} catch (RuntimeException $error) {
    fwrite(STDERR, "SKIP live network: {$error->getMessage()}\n");
}

fwrite(STDOUT, "\n{$test->ok} passed, {$test->bad} failed\n");
exit($test->bad > 0 ? 1 : 0);
