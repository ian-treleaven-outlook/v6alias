<?php
declare(strict_types=1);

namespace V6Alias;

require_once __DIR__ . '/../pfsense/platform.php';

set_error_handler(static function (int $severity, string $message): bool {
    if (!(error_reporting() & $severity)) {
        return false;
    }
    throw new \RuntimeException($message);
});

$count = 0;
function test(string $name, callable $body): void {
    global $count;
    try {
        $body();
        $count++;
        echo "ok $count - $name\n";
    } catch (\Throwable $error) {
        fwrite(STDERR, "FAIL $name: " . $error->getMessage() . "\n" . $error->getTraceAsString() . "\n");
        exit(1);
    }
}

function check(bool $value): void {
    if (!$value) {
        throw new \RuntimeException('assertion failed');
    }
}

function refused(callable $body, ?string $code = null): void {
    try {
        $body();
    } catch (Refusal $error) {
        if ($code !== null && $error->getMessage() !== $code) {
            throw new \RuntimeException(
                'Expected refusal ' . $code . ', received ' . $error->getMessage()
            );
        }
        return;
    }
    throw new \RuntimeException('expected refusal');
}

function fixtureDnsReply(string $packet, string $records): string {
    $at = 12;
    $labels = [];
    while (ord($packet[$at]) !== 0) {
        $length = ord($packet[$at++]);
        $labels[] = substr($packet, $at, $length);
        $at += $length;
    }
    $name = implode('.', $labels) . '.';
    $type = unpack('n', substr($packet, $at + 1, 2))[1];
    $answers = [];
    foreach (explode("\n", $records) as $line) {
        if (!preg_match('/^(\S+) ([0-9]+) IN (A|AAAA|PTR) (.+)$/D', $line, $m) ||
            dns($m[1]) !== $name || DnsWire::TYPES[$m[3]] !== $type) { continue; }
        $rdata = $type === 12 ? DnsWire::name($m[4]) : inet_pton($m[4]);
        $answers[] = "\xc0\x0c" . pack('nnNn', $type, 1, (int)$m[2], strlen($rdata)) . $rdata;
    }
    return substr($packet, 0, 2) . pack('nnnnn', 0x8400, 1, count($answers), 0, 0) .
        substr($packet, 12) . implode('', $answers);
}

final class FixtureEnvironment implements Environment {
    public bool $valid = true;
    public bool $dirty = false;
    public int $clock = 100;
    public string $records;
    public ?\Closure $onDns = null;
    public string $boot = 'boot-before';
    public bool $healthy = true;
    public bool $servedHealthy = true;
    public ?string $servedRecords = null;
    public string $protected = 'protected';
    public ?\Closure $onHealth = null;
    public function __construct() {
        $address = 'fd12:3456:789a:a::35';
        $this->records = implode("\n", [
            "foreign.demo.home.arpa. 3600 IN AAAA $address",
            "printer.demo.home.arpa. 3600 IN AAAA $address",
            reverseName($address) . ' 3600 IN PTR foreign.demo.home.arpa.',
            'foreign.demo.home.arpa. 3600 IN A 192.0.2.53',
            'printer.demo.home.arpa. 3600 IN A 192.0.2.53',
            '53.2.0.192.in-addr.arpa. 3600 IN PTR foreign.demo.home.arpa.',
            'outside.example. 3600 IN A 192.0.2.77',
            'localhost. 3600 IN AAAA ::1',
            'localhost.example.test. 3600 IN AAAA ::1',
            'synthetic-router.example.test. 3600 IN A 192.0.2.1',
        ]);
    }
    public function gate(Policy $policy): void { need($this->valid, 'source_gate'); }
    public function clean(): void { need(!$this->dirty, 'dirty'); }
    public function now(): int { return $this->clock; }
    public function bootIdentity(): string {
        return (new RuntimeHealth(fn() => '', fn($name) => $name === 'boot-id' ? hash('md5', $this->boot, true) : ''))->bootIdentity();
    }
    public function prepareRuntime(string $raw, Policy $policy): string {
        (new NativeXml($raw))->projectedConfig($policy);
        return hash('sha256', $this->protected);
    }
    public function verifyRuntime(string $raw, Policy $policy, array $external, string $protectedHash): \stdClass {
        if ($this->onHealth !== null) { ($this->onHealth)(); }
        need($this->healthy, 'fixture_runtime_unhealthy');
        $projection = projection($raw, $policy, $this->clock, $this->records);
        need(Json::hash($projection->external_dns) === Json::hash($external), 'external_dns_runtime_changed');
        $served = ServedDns::verify($this->records, $projection->config, (new NativeXml($raw))->systemNames(), $policy,
            function ($target, $packet, $deadline) {
                need($this->servedHealthy, 'fixture_dns_listener_unavailable');
                return fixtureDnsReply($packet, $this->servedRecords ?? $this->records);
            });
        return obj([
            'contract' => RuntimeHealth::CONTRACT, 'boot_sha256' => $this->bootIdentity(),
            'config_revision_sha256' => hash('sha256', $raw), 'dhcp_config_sha256' => hash('sha256', 'dhcp'),
            'dns_data_sha256' => hash('sha256', $this->records), 'processes_sha256' => hash('sha256', 'processes'),
            'protected_sha256' => $protectedHash, 'dhcp_mapping_count' => 2, 'dns_native_host_count' => count($projection->config->unbound->hosts),
            'verified_at_unix_secs' => $this->clock,
            'served_query_count' => $served->served_query_count, 'served_answers_sha256' => $served->served_answers_sha256,
        ]);
    }
    public function dnsData(): string {
        if ($this->onDns !== null) { ($this->onDns)(); }
        return $this->records;
    }
}

/* Only the metadata adapter differs: real open/flock/fsync/rename/XML/journals
 * are exercised; production stat checks are independently tested below.
 * There is no production fixture-root switch. */
final class FixtureFiles extends Files {
    public ?\Closure $fault = null;
    public bool $failWrite = false;
    public bool $failSync = false;
    public bool $failRename = false;
    public bool $failCache = false;
    public bool $shortChunks = false;
    public function __construct(private string $root) { parent::__construct(posix_geteuid()); }
    protected function standardLockPath(): string { return $this->root . '/config.lock'; }
    public function parents(string $path, bool $stickyParent = false): void {
        need(str_starts_with($path, $this->root . '/') && !str_contains($path, '/../'), 'fixture_path');
        for ($parent = dirname($path); strlen($parent) >= strlen($this->root); $parent = dirname($parent)) {
            $this->checked($parent, false, true);
        }
    }
    public function checked(string $path, bool $private = false, bool $directory = false, bool $stockLock = false): array {
        clearstatcache(true, $path);
        $s = @lstat($path);
        need($s !== false, 'file_missing');
        need(($s['mode'] & 0170000) === ($directory ? 0040000 : 0100000) && ($directory || $s['nlink'] === 1), 'fixture_unsafe_type');
        return $s;
    }
    protected function writeChunk($file, string $bytes): int|false {
        if ($this->failWrite) { return 0; }
        return parent::writeChunk($file, $this->shortChunks ? substr($bytes, 0, 7) : $bytes);
    }
    protected function syncFile($file): bool {
        return !$this->failSync && parent::syncFile($file);
    }
    protected function renameFile(string $from, string $to): bool {
        return !$this->failRename && parent::renameFile($from, $to);
    }
    public function point(string $stage): void {
        if ($this->fault !== null) { ($this->fault)($stage); }
    }
    public function removeCache(string $path): void {
        need(!$this->failCache, 'cache_invalidation');
        parent::removeCache($path);
    }
}

final class Fixture {
    public string $root;
    public string $raw;
    public Policy $policy;
    public FixtureFiles $files;
    public FixtureEnvironment $env;
    public Transactions $tx;
    public \stdClass $baseline;
    public \stdClass $request;
    public function __construct() {
        // Native temporary storage avoids DrvFS's inconsistent post-rename metadata.
        $this->root = sys_get_temp_dir() . '/v6alias-php-helper-test-' . bin2hex(random_bytes(8));
        mkdir($this->root, 0700);
        $this->raw = file_get_contents(__DIR__ . '/fixtures/pfsense-config.xml');
        $this->policy = new Policy(Json::decode(file_get_contents(__DIR__ . '/fixtures/pfsense-policy.json')));
        $this->files = new FixtureFiles($this->root);
        $this->env = new FixtureEnvironment();
        $this->files->create($this->root . '/config.xml', $this->raw);
        $this->files->create($this->root . '/config.lock', '');
        $this->files->create($this->root . '/config.cache', 'synthetic cached secrets');
        $this->tx = new Transactions($this->files, $this->env, $this->root . '/config.xml', $this->root . '/private', $this->root . '/config.lock', [$this->root . '/config.cache']);
        $this->baseline = (new Collector($this->files, $this->env, $this->root . '/config.xml'))->capture($this->policy);
        $map = obj(['duid' => '00:01:00:01:01:02:03:04:02:00:00:00:00:42', 'ipaddrv6' => 'fd12:3456:789a:a::2', 'hostname' => 'workstation', 'descr' => 'v6alias:asset-1', 'earlydnsregpolicy' => 'disable', 'filename' => '', 'rootpath' => '']);
        $host = obj(['host' => 'workstation', 'domain' => 'demo.home.arpa', 'ip' => 'fd12:3456:789a:a::2', 'descr' => 'v6alias:asset-1', 'aliases' => obj(['item' => []])]);
        $this->request = obj([
            'schema_version' => 1, 'mode' => 'native_plan', 'mutation_scope' => 'managed_dhcpv6_staticmaps_and_unbound_host_overrides',
            'network_writes' => false, 'approval_required' => true, 'source_contract' => CONTRACT,
            'expected_revision_sha256' => $this->baseline->config_revision_sha256, 'baseline_projection_sha256' => Json::hash($this->baseline),
            'authority_sha256' => str_repeat('a', 64), 'candidate_projection_sha256' => '',
            'allowed_paths' => $this->policy->paths(), 'activation_requirements' => ['operator_approval_and_maintenance_window'],
            'changes' => [
                obj(['path' => obj(['kind' => 'dhcpv6_staticmap', 'interface' => 'lan']), 'before' => $this->baseline->config->dhcpdv6->lan->staticmap, 'after' => [...$this->baseline->config->dhcpdv6->lan->staticmap, $map]]),
                obj(['path' => obj(['kind' => 'unbound_hosts']), 'before' => $this->baseline->config->unbound->hosts, 'after' => [...$this->baseline->config->unbound->hosts, $host]]),
            ],
        ]);
        $this->rehash();
    }
    public function rehash(): void {
        $candidate = Json::copy($this->baseline);
        foreach ($this->request->changes as $c) {
            if ($c->path->kind === 'unbound_hosts') { $candidate->config->unbound->hosts = $c->after; }
            else { $candidate->config->dhcpdv6->{$c->path->interface}->staticmap = $c->after; }
        }
        $candidate->offline_generation = count($this->request->changes) ? 1 : 0;
        $this->request->candidate_projection_sha256 = Json::hash($candidate);
    }
    public function addUnmanagedScope(): void {
        $data = Json::copy($this->policy->data);
        $data->scopes->opt1 = obj([
            'router_address' => 'fd12:3456:789a:b::1',
            'external_static_addresses' => [],
            'approved_reservation_addresses' => [],
        ]);
        $this->policy = new Policy($data);
        $this->raw = str_replace('</interfaces>',
            '<opt1><if>vtnet2</if><ipaddrv6>fd12:3456:789a:b::1</ipaddrv6><subnetv6>64</subnetv6></opt1></interfaces>', $this->raw);
        $this->raw = str_replace('</dhcpdv6>',
            '<opt1><enable/><range><from>fd12:3456:789a:b::1000</from><to>fd12:3456:789a:b::ffff</to></range></opt1></dhcpdv6>', $this->raw);
        file_put_contents($this->root . '/config.xml', $this->raw);
        $this->baseline = projection($this->raw, $this->policy, $this->env->clock, $this->env->records);
        $this->request->expected_revision_sha256 = $this->baseline->config_revision_sha256;
        $this->request->baseline_projection_sha256 = Json::hash($this->baseline);
        $this->rehash();
    }
    public function persist(?string $approval = null): \stdClass {
        return $this->tx->persist($this->policy, $this->baseline, $this->request, $approval ?? Json::hash($this->request), hash('sha256', Json::canonical($this->request) . "\n"), true);
    }
    public function current(): string { return file_get_contents($this->root . '/config.xml'); }
    public function bootCandidate(): void {
        $this->env->boot = 'boot-after';
        $this->env->records .= "\nworkstation.demo.home.arpa. 3600 IN AAAA fd12:3456:789a:a::2\n" .
            reverseName('fd12:3456:789a:a::2') . ' 3600 IN PTR workstation.demo.home.arpa.';
    }
    public function close(): void {
        $remove = function (string $path) use (&$remove): void {
            if (is_dir($path) && !is_link($path)) {
                foreach (scandir($path) as $name) {
                    if ($name !== '.' && $name !== '..') { $remove($path . '/' . $name); }
                }
                rmdir($path);
            } else { unlink($path); }
        };
        $remove($this->root);
    }
}

function fixture(callable $test): void {
    $f = new Fixture();
    try { $test($f); } finally { $f->close(); }
}

test('canonical JSON preserves Unicode, slash, object/array distinction and order', function () {
    $value = Json::decode('{"z":[],"é":"雪/\u2028","a":{},"b":[2,1]}');
    check(Json::canonical($value) === '{"a":{},"b":[2,1],"z":[],"é":"雪/' . "\u{2028}" . '"}');
    check(Json::hash(obj()) !== Json::hash([]));
});
foreach (['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"z":{"x":1,"x":2}}', '0.5', '1e2', '18446744073709551615', '-9223372036854775809', '-0', '{"a":1,}', '[1,]', '01', '"\\ud800"', 'true false'] as $raw) {
    test('strict JSON refuses ' . $raw, fn() => refused(fn() => Json::decode($raw)));
}
test('integer signed boundaries', function () {
    check(Json::decode('9223372036854775807') === PHP_INT_MAX);
    check(Json::decode('-9223372036854775808') === PHP_INT_MIN);
});
test('XML secret-free complete projection', fn() => fixture(function (Fixture $f) {
    $json = Json::canonical($f->baseline);
    check(!str_contains($json, 'SECRET') && !str_contains($json, 'bcrypt'));
    check(count($f->baseline->external_dns) === 4);
    check($f->baseline->config_revision_sha256 === hash('sha256', $f->raw));
}));
test('root backend defaults to pinned ISC but explicit Kea or unknown values refuse', fn() => fixture(function (Fixture $f) {
    foreach (['', '<dhcpbackend/>', '<dhcpbackend>isc</dhcpbackend>'] as $replacement) {
        $raw = str_replace('<dhcpbackend>isc</dhcpbackend>', $replacement, $f->raw);
        check(projection($raw, $f->policy, 100, $f->env->records)->dhcp_backend === 'isc');
    }
    foreach (['kea', 'unrecognized'] as $backend) {
        $raw = str_replace('<dhcpbackend>isc</dhcpbackend>', "<dhcpbackend>$backend</dhcpbackend>", $f->raw);
        refused(fn() => projection($raw, $f->policy, 100, $f->env->records), 'isc_backend_required');
    }
}));
test('system DNS identity ignores repeated private group data but not duplicate names', fn() => fixture(function (Fixture $f) {
    $raw = str_replace('</system>', '<group><name>SECRET-GROUP-ONE</name></group><group><name>SECRET-GROUP-TWO</name></group></system>', $f->raw);
    $p = projection($raw, $f->policy, 100, $f->env->records);
    check(!str_contains(Json::canonical($p), 'SECRET-GROUP'));
    refused(fn() => projection(str_replace('</system>', '<hostname>duplicate</hostname></system>', $raw), $f->policy, 100, $f->env->records), 'xml_duplicate_element');
}));
test('managed RA metadata is preserved without changing RA settings', fn() => fixture(function (Fixture $f) {
    $raw = str_replace('<range>', '<ramode>managed</ramode><rapriority>medium</rapriority><range>', $f->raw);
    $p = projection($raw, $f->policy, 100, $f->env->records);
    check($p->config->dhcpdv6->lan->ramode === 'managed' && $p->config->dhcpdv6->lan->rapriority === 'medium');
    refused(fn() => projection(str_replace('<ramode>managed</ramode>', '<ramode>invalid</ramode>', $raw), $f->policy, 100, $f->env->records), 'unsupported_ra_mode');
}));
test('fixed interface retains dormant tracking preferences but active track6 refuses', fn() => fixture(function (Fixture $f) {
    $raw = str_replace('<if>vtnet1</if>', '<if>vtnet1</if><track6-interface>wan</track6-interface><track6-prefix-id>0</track6-prefix-id>', $f->raw);
    $p = projection($raw, $f->policy, 100, $f->env->records);
    check($p->config->interfaces->lan->ipaddrv6 === 'fd12:3456:789a:a::1');
    $xml = new NativeXml($raw);
    $after = $xml->patch($f->request->changes);
    check(str_contains($after, '<track6-interface>wan</track6-interface>'));
    refused(fn() => projection(str_replace('<ipaddrv6>fd12:3456:789a:a::1</ipaddrv6>', '<ipaddrv6>track6</ipaddrv6>', $raw), $f->policy, 100, $f->env->records));
}));
foreach ([
    '<!DOCTYPE pfsense [<!ENTITY x SYSTEM "file:///never-read">]><pfsense>&x;</pfsense>',
    '<pfsense><unbound/><unbound/></pfsense>',
    '<pfsense><system xmlns="urn:unsafe"/></pfsense>',
    '<pfsense><?unsafe x?></pfsense>',
    '<pfsense>' . str_repeat('<x>', 65) . str_repeat('</x>', 65) . '</pfsense>',
] as $i => $raw) {
    test("XML rejects unsafe structure $i", fn() => refused(fn() => new NativeXml($raw)));
}
foreach (['<password>never-export</password>', '<iaid>3</iaid>', '<ttl>60</ttl>'] as $field) {
    test('record extensions refuse rather than silently project', fn() => fixture(function (Fixture $f) use ($field) {
        $raw = str_replace('<filename>', $field . '<filename>', $f->raw);
        refused(fn() => projection($raw, $f->policy, 100, $f->env->records), 'unsupported_native_record_field');
    }));
}
foreach (['<regdhcp/>', '<regdhcpstatic/>', '<python/>', '<domainoverrides/>', '<custom_options>anything</custom_options>'] as $field) {
    test('unsupported resolver feature refuses', fn() => fixture(function (Fixture $f) use ($field) {
        refused(fn() => projection(str_replace('<unbound>', '<unbound>' . $field, $f->raw), $f->policy, 100, $f->env->records));
    }));
}
test('DNS runtime exact TTL target and missing native data', fn() => fixture(function (Fixture $f) {
    foreach ([
        str_replace('3600 IN AAAA', '300 IN AAAA', $f->env->records),
        str_replace('IN PTR foreign.', 'IN PTR changed.', $f->env->records),
        '',
        $f->env->records . "\nforeign.demo.home.arpa. 3600 IN AAAA fd12:3456:789a:a::99",
    ] as $data) {
        refused(fn() => DnsRecords::external($data, $f->baseline->config));
    }
}));
test('DNS CNAME and arbitrary RR owners stay conflict evidence', fn() => fixture(function (Fixture $f) {
    $extra = "\nalias.example. 600 IN CNAME foreign.demo.home.arpa.\nmail.example. 600 IN MX 10 mx.example.";
    $out = DnsRecords::external($f->env->records . $extra, $f->baseline->config);
    check(count($out) === 6 && $out[0]->name === 'alias.example.' && $out[0]->addresses === []);
}));
test('source and runtime version pins', function () {
    $policy = new Policy(Json::decode(file_get_contents(__DIR__ . '/fixtures/pfsense-policy.json')));
    $pins = [...SourceGate::PINS, 'globals.inc' => $policy->data->globals_sha256];
    SourceGate::verify('2.8.1-RELEASE', $pins, "isc-dhcpd-4.4.3-P1\n", "Version 1.24.2\n", $policy);
    refused(fn() => SourceGate::verify('2.8.2-RELEASE', $pins, 'isc-dhcpd-4.4.3-P1', 'Version 1.24.2', $policy), 'pfsense_version_pin');
    refused(fn() => SourceGate::verify('2.8.1-RELEASE', [], 'isc-dhcpd-4.4.3-P1', 'Version 1.24.2', $policy), 'native_source_pin');
    refused(fn() => SourceGate::verify('2.8.1-RELEASE', $pins, 'isc-dhcpd-4.4.3-P2', 'Version 1.24.2', $policy), 'isc_version_pin');
    refused(fn() => SourceGate::verify('2.8.1-RELEASE', $pins, 'isc-dhcpd-4.4.3-P1', 'Version 1.25.0', $policy), 'unbound_version_pin');
});
test('real durable persist private preimage foreign DOM and exact rollback', fn() => fixture(function (Fixture $f) {
    $r = $f->persist();
    check($r->status === 'committed' && $r->network_writes && $r->activation === 'not_activated');
    check($f->current() !== $f->raw && !file_exists($f->root . '/config.cache'));
    check(str_contains($f->current(), '<![CDATA[operator-owned; preserve & punctuation]]>'));
    check(str_contains($f->current(), '<!-- preserve this foreign comment -->'));
    check(str_contains($f->current(), 'SECRET-FIXTURE-NOT-A-CREDENTIAL'));
    check(!str_contains(Json::canonical($r), 'SECRET'));
    check(file_get_contents($f->root . '/private/' . $r->transaction_id . '/before.xml') === $f->raw);
    check($r->request_sha256 !== $r->request_file_sha256);
    refused(fn() => $f->persist(), 'prior_transaction_requires_recovery_or_activation');
    $back = $f->tx->rollback($f->policy, $r->transaction_id, $r->current_revision_sha256, true);
    check($back->status === 'rolled_back' && $back->network_writes && $f->current() === $f->raw);
    refused(fn() => $f->tx->rollback($f->policy, $r->transaction_id, $r->current_revision_sha256, true), 'rollback_journal_state');
}));
test('candidate XML roundtrip empty aliases normalized', fn() => fixture(function (Fixture $f) {
    $f->persist();
    $config = (new NativeXml($f->current()))->projectedConfig($f->policy);
    check(Json::hash($config->unbound->hosts) === Json::hash($f->request->changes[1]->after));
    check($config->unbound->hosts[1]->aliases->item === []);
}));
foreach (['approval', 'candidate', 'baseline', 'revision', 'foreign', 'path', 'duplicate-path', 'future', 'stale', 'dirty', 'source', 'unapproved', 'unpaired'] as $case) {
    test("persist refusal $case leaves config unchanged", fn() => fixture(function (Fixture $f) use ($case) {
        $approval = null;
        switch ($case) {
            case 'approval': $approval = str_repeat('0', 64); break;
            case 'candidate': $f->request->candidate_projection_sha256 = str_repeat('0', 64); break;
            case 'baseline': $f->baseline->source = 'changed'; break;
            case 'revision': file_put_contents($f->root . '/config.xml', $f->raw . "\n"); break;
            case 'foreign': $f->request->changes[0]->after[0]->filename = 'changed'; break;
            case 'path': $f->request->changes[0]->path->interface = '../../filter'; break;
            case 'duplicate-path': $f->request->changes[] = $f->request->changes[0]; break;
            case 'future': $f->baseline->captured_at_unix_secs = 101; break;
            case 'stale': $f->env->clock = 401; break;
            case 'dirty': $f->env->dirty = true; break;
            case 'source': $f->env->valid = false; break;
            case 'unapproved': $f->request->changes[0]->after[1]->ipaddrv6 = 'fd12:3456:789a:a::3'; break;
            case 'unpaired': $f->request->changes[1]->after = $f->request->changes[1]->before; break;
        }
        $before = $f->current();
        refused(fn() => $f->persist($approval));
        check($before === $f->current());
    }));
}
test('capture revision race refuses', fn() => fixture(function (Fixture $f) {
    $f->env->onDns = fn() => file_put_contents($f->root . '/config.xml', $f->raw . "\n");
    refused(fn() => (new Collector($f->files, $f->env, $f->root . '/config.xml'))->capture($f->policy), 'config_capture_race');
}));
test('capture runtime race refuses', fn() => fixture(function (Fixture $f) {
    $n = 0;
    $f->env->onDns = function () use ($f, &$n) {
        if (++$n === 2) { $f->env->records .= "\nrace.example. 3600 IN A 192.0.2.100"; }
    };
    refused(fn() => (new Collector($f->files, $f->env, $f->root . '/config.xml'))->capture($f->policy), 'runtime_capture_race');
}));
test('missing automatic system owner cannot masquerade as complete DNS', fn() => fixture(function (Fixture $f) {
    $f->env->records = preg_replace('/^synthetic-router[^\n]*$/m', '', $f->env->records);
    refused(fn() => projection($f->raw, $f->policy, 100, $f->env->records), 'system_dns_runtime_missing_or_shadowed');
}));
test('complete capture includes unmanaged scope without granting mutation paths', fn() => fixture(function (Fixture $f) {
    $f->addUnmanagedScope();
    check(isset($f->baseline->scopes->opt1) && isset($f->baseline->config->dhcpdv6->opt1));
    check($f->policy->paths() === ['dhcpdv6/lan/staticmap', 'unbound/hosts']);
    $old = Json::canonical($f->baseline->config->dhcpdv6->opt1);
    $r = $f->persist();
    check(Json::canonical((new NativeXml($f->current()))->projectedConfig($f->policy)->dhcpdv6->opt1) === $old);
    $f->tx->rollback($f->policy, $r->transaction_id, $r->current_revision_sha256, true);
    check($f->current() === $f->raw);
}));
test('captured but unmanaged interface cannot be added to approved request paths', fn() => fixture(function (Fixture $f) {
    $f->addUnmanagedScope();
    $f->request->allowed_paths = ['dhcpdv6/lan/staticmap', 'dhcpdv6/opt1/staticmap', 'unbound/hosts'];
    refused(fn() => $f->persist(), 'request_paths');
    $f->request->allowed_paths = $f->policy->paths();
    $f->request->changes[0]->path->interface = 'opt1';
    refused(fn() => $f->persist(), 'request_path');
    check($f->current() === $f->raw);
}));
test('policy requires an explicit valid unique managed interface subset', fn() => fixture(function (Fixture $f) {
    foreach ([[], ['opt2'], ['lan', 'lan'], [1]] as $managed) {
        $data = Json::copy($f->policy->data);
        $data->managed_interfaces = $managed;
        refused(fn() => new Policy($data));
    }
}));
foreach (['preparation_directory', 'preparation_backup', 'preparation_evidence', 'preparation_journal'] as $stage) {
    test("interrupted unpublished preparation at $stage does not block next persist", fn() => fixture(function (Fixture $f) use ($stage) {
        $f->files->fault = function ($at) use ($stage) { need($at !== $stage, 'injected_crash'); };
        refused(fn() => $f->persist(), 'injected_crash');
        check($f->current() === $f->raw && $f->tx->transactionId === null);
        $entries = scandir($f->root . '/private');
        check(count(array_filter($entries, fn($name) => preg_match('/^[a-f0-9]{32}$/D', $name))) === 0);
        check(count(array_filter($entries, fn($name) => str_starts_with($name, '.prepare-'))) === 1);
        $f->files->fault = null;
        $r = $f->persist();
        check($r->status === 'committed');
        check(count(array_filter(scandir($f->root . '/private'), fn($name) => str_starts_with($name, '.prepare-'))) === 0);
        $f->tx->rollback($f->policy, $r->transaction_id, $r->current_revision_sha256, true);
        check($f->current() === $f->raw);
    }));
}
test('failed transaction publication leaves only safe discardable preparation', fn() => fixture(function (Fixture $f) {
    $f->files->failRename = true;
    refused(fn() => $f->persist(), 'journal_publish');
    check($f->current() === $f->raw);
    $f->files->failRename = false;
    check($f->persist()->status === 'committed');
}));
test('unpublished preparation with foreign content refuses cleanup', fn() => fixture(function (Fixture $f) {
    $f->files->fault = function ($at) { need($at !== 'preparation_directory', 'injected_crash'); };
    refused(fn() => $f->persist(), 'injected_crash');
    $name = array_values(array_filter(scandir($f->root . '/private'), fn($name) => str_starts_with($name, '.prepare-')))[0];
    $foreign = $f->root . '/private/' . $name . '/unexpected.txt';
    file_put_contents($foreign, 'preserve unknown file');
    $f->files->fault = null;
    refused(fn() => $f->persist(), 'preparation_contents');
    check(file_get_contents($foreign) === 'preserve unknown file' && $f->current() === $f->raw);
}));
foreach (['prepared', 'config_committed'] as $stage) {
    test("crash recovery at $stage", fn() => fixture(function (Fixture $f) use ($stage) {
        $f->files->fault = function ($at) use ($stage) { need($at !== $stage, 'injected_crash'); };
        refused(fn() => $f->persist(), 'injected_crash');
        $id = $f->tx->transactionId;
        $f->files->fault = null;
        $r = $f->tx->recover($f->policy, $id, true);
        check($r->status === ($stage === 'prepared' ? 'aborted' : 'committed'));
        if ($r->status === 'committed') {
            $f->tx->rollback($f->policy, $id, $r->current_revision_sha256, true);
        }
        check($f->current() === $f->raw);
    }));
}
foreach (['rollback_prepared', 'rollback_committed'] as $stage) {
    test("rollback crash recovery at $stage", fn() => fixture(function (Fixture $f) use ($stage) {
        $r = $f->persist();
        $f->files->fault = function ($at) use ($stage) { need($at !== $stage, 'injected_crash'); };
        refused(fn() => $f->tx->rollback($f->policy, $r->transaction_id, $r->current_revision_sha256, true), 'injected_crash');
        $f->files->fault = null;
        $recovered = $f->tx->recover($f->policy, $r->transaction_id, true);
        check($recovered->status === ($stage === 'rollback_prepared' ? 'committed' : 'rolled_back'));
    }));
}
test('foreign edits never overwritten by recovery or rollback', fn() => fixture(function (Fixture $f) {
    $r = $f->persist();
    $foreign = $f->current() . "\n<!-- concurrent foreign write -->\n";
    file_put_contents($f->root . '/config.xml', $foreign);
    refused(fn() => $f->tx->rollback($f->policy, $r->transaction_id, $r->current_revision_sha256, true), 'rollback_foreign_revision');
    refused(fn() => $f->tx->recover($f->policy, $r->transaction_id, true), 'recovery_foreign_revision');
    check($f->current() === $foreign);
}));
test('last moment stale UI CAS refuses rather than overwrites', fn() => fixture(function (Fixture $f) {
    $f->files->fault = function ($at) use ($f) {
        if ($at === 'before_rename') { file_put_contents($f->root . '/config.xml', $f->raw . "\n"); }
    };
    refused(fn() => $f->persist(), 'revision_cas');
    check($f->current() === $f->raw . "\n");
}));
foreach (['failWrite', 'failSync', 'failRename'] as $failure) {
    test("filesystem failure $failure never commits", fn() => fixture(function (Fixture $f) use ($failure) {
        $f->files->$failure = true;
        refused(fn() => $f->persist());
        check($f->current() === $f->raw);
    }));
}
test('partial writes handled and verified', fn() => fixture(function (Fixture $f) {
    $f->files->shortChunks = true;
    check($f->persist()->status === 'committed');
}));
test('cache failure returns failure with recoverable prepared journal', fn() => fixture(function (Fixture $f) {
    $f->files->failCache = true;
    refused(fn() => $f->persist(), 'cache_invalidation');
    check($f->current() !== $f->raw);
    $f->files->failCache = false;
    check($f->tx->recover($f->policy, $f->tx->transactionId, true)->status === 'committed');
}));
test('missing cache is safe idempotent invalidation', fn() => fixture(function (Fixture $f) {
    unlink($f->root . '/config.cache');
    check($f->persist()->status === 'committed');
}));
test('locks are bounded and never unlinked', fn() => fixture(function (Fixture $f) {
    $file = $f->files->lock($f->root . '/config.lock', true);
    try { refused(fn() => $f->files->lock($f->root . '/config.lock', true, 0.03), 'lock_timeout'); }
    finally { fclose($file); }
    check(file_exists($f->root . '/config.lock'));
}));
test('root ownership type link count and private permissions', function () {
    $s = ['mode' => 0100600, 'uid' => 0, 'nlink' => 1];
    Files::verifyStat($s, 0, false, true);
    foreach ([['uid' => 1], ['mode' => 0120600], ['nlink' => 2], ['mode' => 0100644]] as $change) {
        refused(fn() => Files::verifyStat(array_replace($s, $change), 0, false, true));
    }
    Files::verifyStat(['mode' => 0100666, 'uid' => 0, 'nlink' => 1], 0, false, false, true);
    refused(fn() => Files::verifyStat(['mode' => 0100666, 'uid' => 0, 'nlink' => 1], 0, false, false));
});
test('symlink input and symlink parent refuse', fn() => fixture(function (Fixture $f) {
    symlink($f->root . '/config.xml', $f->root . '/link');
    refused(fn() => $f->files->read($f->root . '/link'), 'fixture_unsafe_type');
    symlink($f->root, $f->root . '/parent');
    refused(fn() => $f->files->read($f->root . '/parent/config.xml'), 'fixture_unsafe_type');
}));
test('hardlink input refuses', fn() => fixture(function (Fixture $f) {
    link($f->root . '/config.xml', $f->root . '/linked');
    refused(fn() => $f->files->read($f->root . '/config.xml'), 'fixture_unsafe_type');
}));
test('backup corruption blocks rollback and recovery', fn() => fixture(function (Fixture $f) {
    $r = $f->persist();
    file_put_contents($f->root . '/private/' . $r->transaction_id . '/before.xml', 'damaged');
    refused(fn() => $f->tx->rollback($f->policy, $r->transaction_id, $r->current_revision_sha256, true), 'backup_integrity');
    refused(fn() => $f->tx->recover($f->policy, $r->transaction_id, true), 'backup_integrity');
}));
test('maintenance acknowledgement is required', fn() => fixture(function (Fixture $f) {
    refused(fn() => $f->tx->persist($f->policy, $f->baseline, $f->request, Json::hash($f->request), str_repeat('a', 64), false), 'maintenance_window_required');
    check($f->current() === $f->raw);
}));
test('production environment refuses Linux including root overrides', function () {
    if (php_uname('s') !== 'FreeBSD') {
        refused(fn() => new LiveEnvironment(new Files()), 'freebsd_root_cli_required');
    }
});

test('retirement removes exact approved owned nodes only', fn() => fixture(function (Fixture $f) {
    $xml = new NativeXml($f->raw);
    $ownedRaw = $xml->patch($f->request->changes);
    $f->env->records .= "\nworkstation.demo.home.arpa. 3600 IN AAAA fd12:3456:789a:a::2\n" .
        reverseName('fd12:3456:789a:a::2') . ' 3600 IN PTR workstation.demo.home.arpa.';
    file_put_contents($f->root . '/config.xml', $ownedRaw);
    $f->baseline = projection($ownedRaw, $f->policy, 100, $f->env->records);
    foreach ($f->request->changes as $c) {
        [$c->before, $c->after] = [$c->after, $c->before];
    }
    $f->request->expected_revision_sha256 = hash('sha256', $ownedRaw);
    $f->request->baseline_projection_sha256 = Json::hash($f->baseline);
    $f->rehash();
    $r = $f->persist();
    check(!str_contains($f->current(), 'v6alias:asset-1') && str_contains($f->current(), 'operator-owned'));
    $f->tx->rollback($f->policy, $r->transaction_id, $r->current_revision_sha256, true);
    check($f->current() === $ownedRaw);
}));
test('capture no-owned maps remains complete with empty aliases', fn() => fixture(function (Fixture $f) {
    $raw = preg_replace('~<aliases>.*?</aliases>~s', '<aliases/>', $f->raw);
    $records = preg_replace('/^printer[^\n]*\n?/m', '', $f->env->records);
    $p = projection($raw, $f->policy, 100, $records);
    check($p->config->unbound->hosts[0]->aliases->item === []);
}));
test('post-rename failure recovers intended full hash, not a guessed diff', fn() => fixture(function (Fixture $f) {
    $f->files->fault = function ($at) { need($at !== 'after_rename', 'injected_crash'); };
    refused(fn() => $f->persist(), 'injected_crash');
    $f->files->fault = null;
    check($f->tx->status($f->tx->transactionId, $f->policy)->network_writes && $f->tx->status($f->tx->transactionId, $f->policy)->recovery_required);
    check($f->tx->recover($f->policy, $f->tx->transactionId, true)->status === 'committed');
}));
test('changed source refuses rollback and recovery too', fn() => fixture(function (Fixture $f) {
    $r = $f->persist();
    $f->env->valid = false;
    refused(fn() => $f->tx->rollback($f->policy, $r->transaction_id, $r->current_revision_sha256, true), 'source_gate');
    refused(fn() => $f->tx->recover($f->policy, $r->transaction_id, true), 'source_gate');
}));
test('recovery and status never claim persisted state had no writes', fn() => fixture(function (Fixture $f) {
    $r = $f->persist();
    check($f->tx->status($r->transaction_id, $f->policy)->network_writes);
    check($f->tx->recover($f->policy, $r->transaction_id, true)->network_writes);
}));

test('explicit stock lock initialization is durable idempotent and does not truncate', fn() => fixture(function (Fixture $f) {
    chmod($f->root, 01777);
    unlink($f->root . '/config.lock');
    $r = $f->tx->initializeLock($f->policy, true);
    check($r->created && $r->lock_ready && !$r->config_persisted && !$r->runtime_activation_performed);
    $before = lstat($f->root . '/config.lock');
    check(($before['mode'] & 07777) === 0666 && $before['nlink'] === 1 && $before['uid'] === posix_geteuid());
    file_put_contents($f->root . '/config.lock', 'stock inode contents must survive');
    $r = $f->tx->initializeLock($f->policy, true);
    clearstatcache(true, $f->root . '/config.lock');
    check(!$r->created && lstat($f->root . '/config.lock')['ino'] === $before['ino']);
    check(file_get_contents($f->root . '/config.lock') === 'stock inode contents must survive');
    check($f->current() === $f->raw && file_exists($f->root . '/config.cache'));
    check(count(scandir($f->root . '/private')) === 3);
}));
test('capture never initializes a missing stock lock', fn() => fixture(function (Fixture $f) {
    unlink($f->root . '/config.lock');
    $calls = 0;
    $f->env->onDns = function () use (&$calls) { ++$calls; };
    (new Collector($f->files, $f->env, $f->root . '/config.xml'))->capture($f->policy);
    check($calls === 2 && !file_exists($f->root . '/config.lock') && !file_exists($f->root . '/private'));
    refused(fn() => $f->persist(), 'file_missing');
    check($f->current() === $f->raw && !file_exists($f->root . '/config.lock'));
}));
test('stock lock initialization requires maintenance source gate sticky parent and exact path', fn() => fixture(function (Fixture $f) {
    unlink($f->root . '/config.lock');
    refused(fn() => $f->tx->initializeLock($f->policy, false), 'maintenance_window_required');
    $f->env->valid = false;
    refused(fn() => $f->tx->initializeLock($f->policy, true), 'source_gate');
    $f->env->valid = true;
    refused(fn() => $f->tx->initializeLock($f->policy, true), 'unsafe_lock_parent');
    refused(fn() => $f->files->initializeStandardLock($f->root . '/other.lock'), 'standard_lock_contract');
    refused(fn() => (new Files())->initializeStandardLock($f->root . '/config.lock'), 'standard_lock_contract');
    check(!file_exists($f->root . '/config.lock') && $f->current() === $f->raw);
}));
test('racing stock creator is adopted without replacing its inode or contents', fn() => fixture(function (Fixture $f) {
    chmod($f->root, 01777);
    unlink($f->root . '/config.lock');
    $inode = null;
    $f->files->fault = function ($stage) use ($f, &$inode) {
        if ($stage === 'lock_before_create') {
            file_put_contents($f->root . '/config.lock', 'racing stock writer');
            chmod($f->root . '/config.lock', 0666);
            $inode = lstat($f->root . '/config.lock')['ino'];
        }
    };
    $r = $f->tx->initializeLock($f->policy, true);
    check(!$r->created && lstat($f->root . '/config.lock')['ino'] === $inode);
    check(file_get_contents($f->root . '/config.lock') === 'racing stock writer');
}));
foreach (['symlink', 'hardlink', 'directory', 'foreign-owner', 'unsafe-mode'] as $case) {
    test("stock lock initialization refuses $case without replacing the node", fn() => fixture(function (Fixture $f) use ($case) {
        chmod($f->root, 01777);
        $path = $f->root . '/config.lock';
        unlink($path);
        switch ($case) {
            case 'symlink': symlink($f->root . '/config.xml', $path); break;
            case 'hardlink': link($f->root . '/config.xml', $path); break;
            case 'directory': mkdir($path, 0700); break;
            case 'foreign-owner':
                // fstat is not adapted by FixtureFiles; also works without chown privilege.
                $files = new class(posix_geteuid() + 1) extends Files {};
                $handle = fopen($f->root . '/config.xml', 'rb');
                try { refused(fn() => $files->assertLockIdentity($f->root . '/config.xml', $handle, true), 'unsafe_file_type_owner'); }
                finally { fclose($handle); }
                file_put_contents($path, '');
                if (posix_geteuid() === 0) { chown($path, 1); }
                else { return; }
                break;
            case 'unsafe-mode': file_put_contents($path, ''); chmod($path, 04777); break;
        }
        $before = lstat($path);
        refused(fn() => $f->tx->initializeLock($f->policy, true));
        clearstatcache(true, $path);
        check(lstat($path)['ino'] === $before['ino'] && $f->current() === $f->raw);
    }));
}
foreach (['lock_opened', 'lock_permissions', 'lock_initialized'] as $stage) {
    test("interrupted lock initialization at $stage leaves an adoptable same inode", fn() => fixture(function (Fixture $f) use ($stage) {
        chmod($f->root, 01777);
        unlink($f->root . '/config.lock');
        $f->files->fault = function ($at) use ($stage) { need($at !== $stage, 'injected_crash'); };
        refused(fn() => $f->tx->initializeLock($f->policy, true), 'injected_crash');
        $before = lstat($f->root . '/config.lock');
        $f->files->fault = null;
        $r = $f->tx->initializeLock($f->policy, true);
        check(!$r->created && lstat($f->root . '/config.lock')['ino'] === $before['ino']);
    }));
}
test('lock initialization detects named inode replacement and never deletes it', fn() => fixture(function (Fixture $f) {
    chmod($f->root, 01777);
    $f->files->fault = function ($at) use ($f) {
        if ($at === 'lock_opened') {
            rename($f->root . '/config.lock', $f->root . '/original.lock');
            file_put_contents($f->root . '/config.lock', 'replacement');
        }
    };
    refused(fn() => $f->tx->initializeLock($f->policy, true), 'lock_race');
    check(file_get_contents($f->root . '/config.lock') === 'replacement' && file_exists($f->root . '/original.lock'));
}));
test('lock initialization refuses reentry and bounded contention then releases descriptors', fn() => fixture(function (Fixture $f) {
    chmod($f->root, 01777);
    $f->files->fault = function ($at) use ($f) {
        if ($at === 'lock_opened') {
            refused(fn() => $f->files->initializeStandardLock($f->root . '/config.lock'), 'lock_initialization_reentrant');
        }
    };
    $held = $f->files->lock($f->root . '/config.lock', true);
    try { refused(fn() => $f->files->initializeStandardLock($f->root . '/config.lock', 0.01), 'lock_timeout'); }
    finally { fclose($held); }
    check(!$f->files->initializeStandardLock($f->root . '/config.lock', 0.01));
    $held = $f->files->lock($f->root . '/config.lock', true, 0.01);
    fclose($held);
}));
test('lock fsync failure reports failure but preserves inode for explicit retry', fn() => fixture(function (Fixture $f) {
    chmod($f->root, 01777);
    $f->files->failSync = true;
    refused(fn() => $f->files->initializeStandardLock($f->root . '/config.lock'), 'stock_lock_fsync');
    $inode = lstat($f->root . '/config.lock')['ino'];
    $f->files->failSync = false;
    check(!$f->files->initializeStandardLock($f->root . '/config.lock'));
    check(lstat($f->root . '/config.lock')['ino'] === $inode);
}));
test('immutable activation evidence binds request source baseline and candidate with no XML secrets', fn() => fixture(function (Fixture $f) {
    $r = $f->persist();
    $directory = $f->root . '/private/' . $r->transaction_id;
    $journal = Json::decode(file_get_contents($directory . '/journal.json'));
    $bytes = file_get_contents($directory . '/activation.json');
    $evidence = Json::decode($bytes);
    check($journal->schema_version === 3 && $journal->evidence_sha256 === hash('sha256', $bytes));
    check($journal->source_sha256 === SourceGate::identity($f->policy));
    check(Json::hash($evidence->request) === $r->request_sha256 && Json::hash($evidence->baseline) === Json::hash($f->baseline));
    check(($f->files->checked($directory . '/activation.json')['mode'] & 0777) === 0600);
    check(!str_contains($bytes, 'SECRET-FIXTURE'));
    $prepared = $f->tx->activate($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true);
    check($prepared->activation === 'awaiting_cold_boot' && !$prepared->runtime_health_verified && !$prepared->runtime_activation_performed);
    check(file_get_contents($directory . '/activation.json') === $bytes);
    $status = $f->tx->status($r->transaction_id, $f->policy);
    check($status->status === 'committed' && !$status->runtime_health_verified && $status->runtime_activation_supported);
    check($status->recovery_scope === 'config_cache_and_explicit_cold_boot_runtime_verification');
}));
foreach (['approval', 'revision', 'source', 'policy', 'evidence', 'legacy', 'rolled_back', 'maintenance'] as $case) {
    test("activation refuses $case without any config journal cache or service effects", fn() => fixture(function (Fixture $f) use ($case) {
        $r = $f->persist();
        $directory = $f->root . '/private/' . $r->transaction_id;
        $policy = $f->policy;
        $expected = $r->current_revision_sha256;
        $approval = $r->request_sha256;
        $maintenance = true;
        switch ($case) {
            case 'approval': $approval = str_repeat('0', 64); break;
            case 'revision': file_put_contents($f->root . '/config.xml', $f->current() . "\n"); break;
            case 'source': $f->env->valid = false; break;
            case 'policy': $data = Json::copy($policy->data); $data->audit_id .= '-changed'; $policy = new Policy($data); break;
            case 'evidence': file_put_contents($directory . '/activation.json', '{}'); break;
            case 'legacy':
                $j = Json::decode(file_get_contents($directory . '/journal.json'));
                $j->schema_version = 1;
                file_put_contents($directory . '/journal.json', Json::canonical($j));
                break;
            case 'rolled_back': $f->tx->rollback($f->policy, $r->transaction_id, $expected, true); break;
            case 'maintenance': $maintenance = false; break;
        }
        $config = $f->current();
        $journal = file_get_contents($directory . '/journal.json');
        $calls = 0;
        $f->env->onDns = function () use (&$calls) { ++$calls; };
        refused(fn() => $f->tx->activate($policy, $r->transaction_id, $expected, $approval, $maintenance));
        check($f->current() === $config && file_get_contents($directory . '/journal.json') === $journal);
        check($calls === 0 && !file_exists($f->root . '/config.cache'));
    }));
}
test('legacy journals refuse manual-only without silently migrating or reconciling', fn() => fixture(function (Fixture $f) {
    $r = $f->persist();
    $path = $f->root . '/private/' . $r->transaction_id . '/journal.json';
    $j = Json::decode(file_get_contents($path));
    $j->schema_version = 1;
    foreach (['source_sha256', 'evidence_sha256'] as $field) { unset($j->$field); }
    file_put_contents($path, Json::canonical($j));
    refused(fn() => $f->tx->status($r->transaction_id, $f->policy), 'legacy_journal_requires_manual_recovery');
    refused(fn() => $f->tx->recover($f->policy, $r->transaction_id, true), 'legacy_journal_requires_manual_recovery');
    refused(fn() => $f->tx->rollback($f->policy, $r->transaction_id, $r->current_revision_sha256, true), 'legacy_journal_requires_manual_recovery');
    check(file_get_contents($path) === Json::canonical($j));
}));
test('source identity mismatch blocks config recovery and rollback', fn() => fixture(function (Fixture $f) {
    $r = $f->persist();
    $path = $f->root . '/private/' . $r->transaction_id . '/journal.json';
    $j = Json::decode(file_get_contents($path));
    $j->source_sha256 = str_repeat('0', 64);
    file_put_contents($path, Json::canonical($j));
    refused(fn() => $f->tx->status($r->transaction_id, $f->policy), 'journal_source_mismatch');
    refused(fn() => $f->tx->recover($f->policy, $r->transaction_id, true), 'journal_source_mismatch');
    refused(fn() => $f->tx->rollback($f->policy, $r->transaction_id, $r->current_revision_sha256, true), 'journal_source_mismatch');
}));
test('delayed preparation expiry is recoverable without reapproving an expired request', fn() => fixture(function (Fixture $f) {
    $f->files->fault = function ($at) use ($f) {
        if ($at === 'preparation_backup') { $f->env->clock = 1000; }
    };
    refused(fn() => $f->persist(), 'baseline_freshness');
    check($f->current() === $f->raw);
    $f->files->fault = null;
    check($f->tx->recover($f->policy, $f->tx->transactionId, true)->status === 'aborted');
}));
test('activation evidence corruption blocks status recovery and rollback without config writes', fn() => fixture(function (Fixture $f) {
    $r = $f->persist();
    file_put_contents($f->root . '/private/' . $r->transaction_id . '/activation.json', '{}');
    $current = $f->current();
    refused(fn() => $f->tx->status($r->transaction_id, $f->policy), 'activation_evidence_integrity');
    refused(fn() => $f->tx->recover($f->policy, $r->transaction_id, true), 'activation_evidence_integrity');
    refused(fn() => $f->tx->rollback($f->policy, $r->transaction_id, $r->current_revision_sha256, true), 'activation_evidence_integrity');
    check($f->current() === $current);
}));
test('racing unsafe creator is refused without chmod unlink or truncation', fn() => fixture(function (Fixture $f) {
    chmod($f->root, 01777);
    unlink($f->root . '/config.lock');
    $mode = fileperms($f->root . '/config.xml');
    $f->files->fault = function ($at) use ($f) {
        if ($at === 'lock_before_create') { symlink($f->root . '/config.xml', $f->root . '/config.lock'); }
    };
    refused(fn() => $f->tx->initializeLock($f->policy, true), 'fixture_unsafe_type');
    check(is_link($f->root . '/config.lock') && $f->current() === $f->raw);
    check(fileperms($f->root . '/config.xml') === $mode);
}));
test('activation without an existing transaction cannot create helper state', fn() => fixture(function (Fixture $f) {
    foreach (['invalid-id', str_repeat('0', 32)] as $id) {
        refused(fn() => $f->tx->activate($f->policy, $id, str_repeat('0', 64), Json::hash($f->request), true));
    }
    check(!file_exists($f->root . '/private') && $f->current() === $f->raw);
}));

test('cold boot activation verifies fresh runtime and retains only historical proof in status', fn() => fixture(function (Fixture $f) {
    $r = $f->persist();
    $before = $f->current();
    $prepared = $f->tx->activate($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true);
    check($prepared->cold_restart_required && $prepared->recovery_required);
    refused(fn() => $f->tx->verifyActivation($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true), 'cold_boot_required');
    check($f->tx->status($r->transaction_id, $f->policy)->activation === 'activation_failed');
    $f->bootCandidate();
    $f->tx->activate($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true);
    $verified = $f->tx->verifyActivation($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true);
    check($verified->activation === 'activated' && $verified->runtime_health_verified && !$verified->recovery_required);
    check(!$verified->runtime_activation_performed && !$verified->config_persisted && $before === $f->current());
    check(!str_contains(Json::canonical($verified), 'workstation') && !str_contains(Json::canonical($verified), 'fd12'));
    $status = $f->tx->status($r->transaction_id, $f->policy);
    check(!$status->runtime_health_verified && $status->runtime_health_previously_verified);
    $f->env->healthy = false;
    check(!$f->tx->recover($f->policy, $r->transaction_id, true)->runtime_health_verified);
    refused(fn() => $f->tx->verifyActivation($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true), 'fixture_runtime_unhealthy');
    $status = $f->tx->status($r->transaction_id, $f->policy);
    check($status->activation === 'activation_failed' && !$status->runtime_health_previously_verified && $status->runtime_health_proof === null);
}));
test('changed boot alone with stale DNS cannot be accepted', fn() => fixture(function (Fixture $f) {
    $r = $f->persist();
    $f->tx->activate($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true);
    $f->env->boot = 'new-boot';
    refused(fn() => $f->tx->verifyActivation($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true), 'dns_native_missing');
    $status = $f->tx->recover($f->policy, $r->transaction_id, true);
    check($status->activation === 'activation_failed' && $status->recovery_required && !$status->runtime_health_verified);
    refused(fn() => $f->persist(), 'prior_transaction_requires_recovery_or_activation');
}));
foreach (['activation_prepared', 'activation_verifying', 'activation_health_verified', 'activation_recorded'] as $stage) {
    test("activation fault at $stage is durable and explicitly retryable", fn() => fixture(function (Fixture $f) use ($stage) {
        $r = $f->persist();
        $f->files->fault = function ($at) use ($stage) { need($at !== $stage, 'injected_crash'); };
        if ($stage === 'activation_prepared') {
            refused(fn() => $f->tx->activate($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true), 'injected_crash');
        } else {
            $f->tx->activate($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true);
            $f->bootCandidate();
            refused(fn() => $f->tx->verifyActivation($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true), 'injected_crash');
        }
        $f->files->fault = null;
        $status = $f->tx->recover($f->policy, $r->transaction_id, true);
        check(!$status->runtime_health_verified && $status->recovery_required);
        if ($stage === 'activation_prepared') { $f->bootCandidate(); }
        $retry = $f->tx->verifyActivation($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true);
        check($retry->runtime_health_verified && $retry->activation === 'activated');
    }));
}
foreach (['health', 'activation_health_verified', 'activation_recorded'] as $stage) {
    test("foreign config race at $stage fails runtime acceptance without restoring anything", fn() => fixture(function (Fixture $f) use ($stage) {
        $r = $f->persist();
        $f->tx->activate($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true);
        $f->bootCandidate();
        $foreign = $f->current() . "\n";
        if ($stage === 'health') { $f->env->onHealth = fn() => file_put_contents($f->root . '/config.xml', $foreign); }
        else { $f->files->fault = function ($at) use ($f, $stage, $foreign) { if ($at === $stage) { file_put_contents($f->root . '/config.xml', $foreign); } }; }
        refused(fn() => $f->tx->verifyActivation($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true), 'activation_foreign_revision');
        check($f->current() === $foreign);
        $j = Json::decode(file_get_contents($f->root . '/private/' . $r->transaction_id . '/journal.json'));
        check($j->activation === 'activation_failed' && $j->runtime->proof === null);
    }));
}
test('rollback after verified activation needs a second cold boot and baseline health', fn() => fixture(function (Fixture $f) {
    $dns = $f->env->records;
    $r = $f->persist();
    $f->tx->activate($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true);
    $f->bootCandidate();
    $f->tx->verifyActivation($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true);
    $back = $f->tx->rollback($f->policy, $r->transaction_id, $r->current_revision_sha256, true);
    check($f->current() === $f->raw && $back->activation === 'rollback_required' && $back->recovery_required);
    refused(fn() => $f->persist(), 'prior_transaction_requires_recovery_or_activation');
    refused(fn() => $f->tx->verifyActivation($f->policy, $r->transaction_id, $back->current_revision_sha256, $r->request_sha256, true, true), 'activation_not_prepared');
    $f->tx->activate($f->policy, $r->transaction_id, $back->current_revision_sha256, $r->request_sha256, true, true);
    refused(fn() => $f->tx->verifyActivation($f->policy, $r->transaction_id, $back->current_revision_sha256, $r->request_sha256, true, true), 'cold_boot_required');
    $f->env->boot = 'boot-rollback';
    refused(fn() => $f->tx->verifyActivation($f->policy, $r->transaction_id, $back->current_revision_sha256, $r->request_sha256, true, true), 'external_dns_runtime_changed');
    $f->env->records = $dns;
    $ok = $f->tx->verifyActivation($f->policy, $r->transaction_id, $back->current_revision_sha256, $r->request_sha256, true, true);
    check($ok->activation === 'rollback_verified' && $ok->runtime_health_verified && !$ok->recovery_required);
    check($f->persist()->status === 'committed');
}));
foreach (['rollback_prepared', 'rollback_committed'] as $stage) {
    test("verified runtime rollback crash at $stage never invents restored runtime", fn() => fixture(function (Fixture $f) use ($stage) {
        $r = $f->persist();
        $f->tx->activate($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true);
        $f->bootCandidate();
        $f->tx->verifyActivation($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true);
        $f->files->fault = function ($at) use ($stage) { need($at !== $stage, 'injected_crash'); };
        refused(fn() => $f->tx->rollback($f->policy, $r->transaction_id, $r->current_revision_sha256, true), 'injected_crash');
        $f->files->fault = null;
        $status = $f->tx->status($r->transaction_id, $f->policy);
        check(!$status->runtime_health_verified && !$status->runtime_health_previously_verified);
        $recovered = $f->tx->recover($f->policy, $r->transaction_id, true);
        check(!$recovered->runtime_health_verified);
        if ($stage === 'rollback_committed') { check($recovered->activation === 'rollback_required' && $recovered->recovery_required); }
    }));
}
test('activated transaction allows next transaction but old rollback cannot overwrite it', fn() => fixture(function (Fixture $f) {
    $r = $f->persist();
    $f->tx->activate($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true);
    $f->bootCandidate();
    $f->tx->verifyActivation($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true);
    $f->baseline = (new Collector($f->files, $f->env, $f->root . '/config.xml'))->capture($f->policy);
    $f->request->expected_revision_sha256 = $f->baseline->config_revision_sha256;
    $f->request->baseline_projection_sha256 = Json::hash($f->baseline);
    $f->request->changes[0]->before = Json::copy($f->baseline->config->dhcpdv6->lan->staticmap);
    $f->request->changes[1]->before = Json::copy($f->baseline->config->unbound->hosts);
    $f->request->changes[0]->after[1]->hostname = 'renamed';
    $f->request->changes[1]->after[1]->host = 'renamed';
    $f->rehash();
    check($f->persist()->status === 'committed');
    refused(fn() => $f->tx->rollback($f->policy, $r->transaction_id, $r->current_revision_sha256, true), 'rollback_foreign_revision');
}));
test('schema two journals explicitly refuse without migration', fn() => fixture(function (Fixture $f) {
    $r = $f->persist();
    $path = $f->root . '/private/' . $r->transaction_id . '/journal.json';
    $j = Json::decode(file_get_contents($path));
    $j->schema_version = 2;
    unset($j->runtime);
    file_put_contents($path, Json::canonical($j));
    refused(fn() => $f->tx->status($r->transaction_id, $f->policy), 'legacy_journal_requires_manual_recovery');
    check(file_get_contents($path) === Json::canonical($j));
}));
test('rollback preparation cannot rebaseline damaged IPv4 or RA runtime', fn() => fixture(function (Fixture $f) {
    $r = $f->persist();
    $f->tx->activate($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true);
    $back = $f->tx->rollback($f->policy, $r->transaction_id, $r->current_revision_sha256, true);
    $f->env->protected = 'damaged';
    refused(fn() => $f->tx->activate($f->policy, $r->transaction_id, $back->current_revision_sha256, $r->request_sha256, true, true), 'protected_runtime_changed');
    check($f->tx->status($r->transaction_id, $f->policy)->activation === 'rollback_required');
}));
foreach (['boot_sha256', 'config_revision_sha256', 'protected_sha256', 'contract'] as $field) {
    test("tampered runtime proof $field refuses", fn() => fixture(function (Fixture $f) use ($field) {
        $r = $f->persist();
        $f->tx->activate($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true);
        $f->bootCandidate();
        $f->tx->verifyActivation($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true);
        $path = $f->root . '/private/' . $r->transaction_id . '/journal.json';
        $j = Json::decode(file_get_contents($path));
        $j->runtime->proof->$field = $field === 'boot_sha256' ? $j->runtime->boot_before_sha256 : str_repeat('0', 64);
        file_put_contents($path, Json::canonical($j));
        refused(fn() => $f->tx->status($r->transaction_id, $f->policy));
    }));
}

test('raw kernel boot ID preserves whitespace and NUL bytes with no wall-clock fallback', function () {
    $id = "\0\n " . str_repeat("\xa1", 10) . "\r\t\0";
    $calls = [];
    $runtime = new RuntimeHealth(fn() => '', function ($command) use ($id, &$calls) {
        $calls[] = $command;
        return $id;
    });
    check($runtime->bootIdentity() === hash('sha256', $id) && $calls === ['boot-id']);
    foreach (['', str_repeat('a', 15), str_repeat('a', 17), bin2hex($id), '{ sec = 1700000001, usec = 0 }'] as $bad) {
        refused(fn() => (new RuntimeHealth(fn() => '', fn() => $bad))->bootIdentity(), 'boot_identity');
    }
    $commands = (new \ReflectionClass(FixedCommands::class))->getReflectionConstant('ARGV')->getValue();
    check($commands['boot-id'] === ['/sbin/sysctl', '-b', 'kern.boot_id'] && !isset($commands['boot-time']));
});
foreach ([false, true] as $rollback) {
    test('wall-clock NTP step cannot satisfy ' . ($rollback ? 'rollback' : 'activation'), fn() => fixture(function (Fixture $f) use ($rollback) {
        $r = $f->persist();
        $expected = $r->current_revision_sha256;
        if ($rollback) {
            $expected = $f->tx->rollback($f->policy, $r->transaction_id, $expected, true)->current_revision_sha256;
        }
        $f->tx->activate($f->policy, $r->transaction_id, $expected, $r->request_sha256, true, $rollback);
        $path = $f->root . '/private/' . $r->transaction_id . '/journal.json';
        $before = Json::decode(file_get_contents($path))->runtime->boot_before_sha256;
        foreach ([3600, 1, 999999] as $clock) {
            $f->env->clock = $clock;
            refused(fn() => $f->tx->verifyActivation($f->policy, $r->transaction_id, $expected, $r->request_sha256, true, $rollback), 'cold_boot_required');
            $f->tx->activate($f->policy, $r->transaction_id, $expected, $r->request_sha256, true, $rollback);
            $j = Json::decode(file_get_contents($path));
            check($j->runtime->boot_before_sha256 === $before && $j->runtime->proof === null);
        }
        if ($rollback) { $f->env->boot = 'rollback-kernel'; }
        else { $f->bootCandidate(); }
        check($f->tx->verifyActivation($f->policy, $r->transaction_id, $expected, $r->request_sha256, true, $rollback)->runtime_health_verified);
    }));
}
test('legacy wall-clock boot contract cannot load as a v2 prepared journal', fn() => fixture(function (Fixture $f) {
    $r = $f->persist();
    $f->tx->activate($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true);
    $path = $f->root . '/private/' . $r->transaction_id . '/journal.json';
    $j = Json::decode(file_get_contents($path));
    $j->runtime->contract = 'pfsense-cold-boot-health-v1';
    file_put_contents($path, Json::canonical($j));
    refused(fn() => $f->tx->status($r->transaction_id, $f->policy), 'legacy_runtime_proof_requires_manual_recovery');
    check(file_get_contents($path) === Json::canonical($j));
}));
foreach (['dead', 'stale', 'wrong-ptr', 'bad-ttl'] as $case) {
    test("correct control table but $case served DNS cannot activate", fn() => fixture(function (Fixture $f) use ($case) {
        $r = $f->persist();
        $f->tx->activate($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true);
        $f->bootCandidate();
        switch ($case) {
            case 'dead': $f->env->servedHealthy = false; break;
            case 'stale': $f->env->servedRecords = str_replace('AAAA fd12:3456:789a:a::2', 'AAAA fd12:3456:789a:a::3', $f->env->records); break;
            case 'wrong-ptr': $f->env->servedRecords = str_replace('PTR workstation.', 'PTR other.', $f->env->records); break;
            case 'bad-ttl': $f->env->servedRecords = str_replace('3600', '3599', $f->env->records); break;
        }
        refused(fn() => $f->tx->verifyActivation($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true));
        $status = $f->tx->status($r->transaction_id, $f->policy);
        check($status->activation === 'activation_failed' && !$status->runtime_health_verified && $status->runtime_health_proof === null);
        $f->env->servedHealthy = true;
        $f->env->servedRecords = null;
        check($f->tx->verifyActivation($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true)->runtime_health_verified);
    }));
}
test('empty rollback requires a served system baseline even when control status is healthy', fn() => fixture(function (Fixture $f) {
    $f->raw = preg_replace('~<hosts>.*?</hosts>~s', '', $f->raw);
    file_put_contents($f->root . '/config.xml', $f->raw);
    $f->env->records = "localhost. 10800 IN AAAA ::1\nlocalhost.example.test. 10800 IN AAAA ::1\nsynthetic-router.example.test. 10800 IN A 192.0.2.1";
    $f->baseline = projection($f->raw, $f->policy, 100, $f->env->records);
    $f->request->expected_revision_sha256 = $f->baseline->config_revision_sha256;
    $f->request->baseline_projection_sha256 = Json::hash($f->baseline);
    $f->request->changes[1]->before = [];
    $f->request->changes[1]->after = [$f->request->changes[1]->after[1]];
    $f->rehash();
    $r = $f->persist();
    $back = $f->tx->rollback($f->policy, $r->transaction_id, $r->current_revision_sha256, true);
    $f->tx->activate($f->policy, $r->transaction_id, $back->current_revision_sha256, $r->request_sha256, true, true);
    $f->env->boot = 'rollback-kernel';
    $f->env->servedHealthy = false;
    refused(fn() => $f->tx->verifyActivation($f->policy, $r->transaction_id, $back->current_revision_sha256, $r->request_sha256, true, true), 'fixture_dns_listener_unavailable');
    check($f->tx->status($r->transaction_id, $f->policy)->activation === 'rollback_failed');
    $f->env->servedHealthy = true;
    $ok = $f->tx->verifyActivation($f->policy, $r->transaction_id, $back->current_revision_sha256, $r->request_sha256, true, true);
    check($ok->runtime_health_verified && $ok->runtime_health_proof->dns_native_host_count === 0 && $ok->runtime_health_proof->served_query_count === 1);
}));
foreach (['zero', 'missing-count', 'missing-hash', 'invalid-hash', 'too-few', 'too-many', 'v1'] as $case) {
    test("served proof schema rejects $case", fn() => fixture(function (Fixture $f) use ($case) {
        $f->bootCandidate();
        $raw = (new NativeXml($f->raw))->patch($f->request->changes);
        $proof = $f->env->verifyRuntime($raw, $f->policy, $f->baseline->external_dns, hash('sha256', 'protected'));
        switch ($case) {
            case 'zero': $proof->served_query_count = 0; break;
            case 'missing-count': unset($proof->served_query_count); break;
            case 'missing-hash': unset($proof->served_answers_sha256); break;
            case 'invalid-hash': $proof->served_answers_sha256 = 'not-a-hash'; break;
            case 'too-few': $proof->served_query_count = 1; break;
            case 'too-many': $proof->served_query_count = ServedDns::MAX_QUERIES + 1; break;
            case 'v1': $proof->contract = 'pfsense-cold-boot-health-v1'; break;
        }
        refused(fn() => RuntimeHealth::proof($proof));
    }));
}

final class RuntimeFixture {
    public string $raw;
    public Policy $policy;
    public array $files;
    public array $commands = [];
    public ?\Closure $onRun = null;
    public ?\Closure $onQuery = null;
    public array $queries = [];
    public RuntimeHealth $probe;
    public function __construct(Fixture $f) {
        $this->raw = (new NativeXml($f->raw))->patch($f->request->changes);
        $this->raw = str_replace('<lan><if>vtnet1</if>', '<lan><enable/><if>em1</if>', $this->raw);
        $data = Json::copy($f->policy->data);
        foreach (['opt1' => ['em2', 'b'], 'opt2' => ['em3', 'c']] as $scope => [$interface, $net]) {
            $router = "fd12:3456:789a:$net::1";
            $data->scopes->$scope = obj(['router_address' => $router, 'external_static_addresses' => [], 'approved_reservation_addresses' => []]);
            $this->raw = str_replace('</interfaces>', "<$scope><enable/><if>$interface</if><ipaddrv6>$router</ipaddrv6><subnetv6>64</subnetv6></$scope></interfaces>", $this->raw);
            $this->raw = str_replace('</dhcpdv6>', "<$scope><enable/><range><from>fd12:3456:789a:$net::1000</from><to>fd12:3456:789a:$net::ffff</to></range></$scope></dhcpdv6>", $this->raw);
        }
        $this->policy = new Policy($data);
        $config = (new NativeXml($this->raw))->projectedConfig($this->policy);
        $dhcp = "# Native-format synthetic configuration\noption domain-name \"example.test\";\n";
        foreach ($config->dhcpdv6 as $scope => $entry) {
            $dhcp .= 'subnet6 ' . subnet($config->interfaces->$scope->ipaddrv6) . "/64 {\nrange6 {$entry->range->from} {$entry->range->to};\n}\n";
            foreach ($entry->staticmap as $i => $record) {
                $dhcp .= "host s_{$scope}_{$i} {\nhost-identifier option dhcp6.client-id {$record->duid};\nfixed-address6 {$record->ipaddrv6};\noption host-name {$record->hostname};\n}\n";
            }
        }
        $this->files = [
            '/var/dhcpd/etc/dhcpdv6.conf' => $dhcp, '/var/dhcpd/etc/dhcpd.conf' => 'unchanged native IPv4',
            '/var/dhcpd/var/run/dhcpdv6.pid' => "3106\n", '/var/dhcpd/var/run/dhcpd.pid' => "3104\n",
            '/var/etc/radvd.conf' => 'unchanged native RA', '/var/run/radvd.pid' => "3101\n",
        ];
        $f->bootCandidate();
        $this->commands = [
            'boot-id' => "\0\n" . str_repeat("\xa5", 12) . " \0",
            'dhcp-check' => '', 'unbound-check' => 'unbound-checkconf: no errors',
            'dns-data' => $f->env->records,
            'dns-status' => "version: 1.24.2\nmodules: 2 [ validator iterator ]\nunbound (pid 3102) is running...\n",
            'dhcp-listener' => "USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS\ndhcpd dhcpd 3106 8 udp6 *:547 *:*\n",
        ];
        $processes = [
            3106 => ['/usr/local/sbin/dhcpd', '-6 -user dhcpd -group _dhcp -chroot /var/dhcpd -cf /etc/dhcpdv6.conf -pf /var/run/dhcpdv6.pid em1 em2 em3'],
            3104 => ['/usr/local/sbin/dhcpd', '-user dhcpd -group _dhcp -chroot /var/dhcpd -cf /etc/dhcpd.conf -pf /var/run/dhcpd.pid em1 em2 em3'],
            3101 => ['/usr/local/sbin/radvd', '-p /var/run/radvd.pid -C /var/etc/radvd.conf -m syslog'],
            3102 => ['/usr/local/sbin/unbound', '-c /var/unbound/unbound.conf'],
        ];
        foreach ($processes as $pid => [$exe, $args]) {
            $name = basename($exe);
            $this->commands["process:$pid"] = "$pid 0 Ss Thu Sep 24 12:00:00 2026 $exe $args\n";
            $this->commands["process-binary:$pid"] = " PID COMM OSREL PATH\n$pid $name 1500000 $exe\n";
            $this->commands["process-files:$pid"] = " PID COMM FD T V FLAGS REF OFFSET PRO NAME\n$pid $name root v d r------- - - - /var/dhcpd\n";
        }
        $this->probe = new RuntimeHealth(function ($path, $optional = false) {
            need($optional || isset($this->files[$path]), 'fixture_missing_runtime_file');
            return $this->files[$path] ?? null;
        }, function ($name, $pid = null) {
            if ($this->onRun !== null) { ($this->onRun)($name, $pid); }
            $key = $name . ($pid === null ? '' : ":$pid");
            need(array_key_exists($key, $this->commands), 'fixture_command_not_allowlisted');
            return $this->commands[$key];
        }, function ($target, $packet, $deadline) {
            $this->queries[] = [$target, $packet, $deadline];
            return $this->onQuery === null ? fixtureDnsReply($packet, $this->commands['dns-data']) :
                ($this->onQuery)($target, $packet, $deadline);
        });
    }
    public function protectedHash(): string { return RuntimeHealth::preservation($this->probe->protectedState()); }
    public function verify(array $external, ?string $protected = null): \stdClass {
        return $this->probe->verify($this->raw, $this->policy, $external, $protected ?? $this->protectedHash(), 100);
    }
}

test('production runtime verifier accepts exact synthetic process DHCP DNS and boot evidence', fn() => fixture(function (Fixture $f) {
    $runtime = new RuntimeFixture($f);
    $proof = $runtime->verify($f->baseline->external_dns);
    RuntimeHealth::proof($proof);
    check($proof->dhcp_mapping_count === 2 && $proof->dns_native_host_count === 2);
    check($proof->served_query_count === 24 && count($runtime->queries) === 24);
    check(SourceGate::path('services_dhcp.inc') === '/usr/local/pfSense/include/www/services_dhcp.inc');
}));
test('production verifier requires an explicitly configured served DNS probe', fn() => fixture(function (Fixture $f) {
    $probe = new RuntimeHealth(fn() => '', fn() => '');
    refused(fn() => $probe->verify($f->raw, $f->policy, [], '', 100), 'dns_query_unconfigured');
}));
test('all native aliases A AAAA PTR query each approved client-facing ULA with RD zero', fn() => fixture(function (Fixture $f) {
    $runtime = new RuntimeFixture($f);
    $proof = $runtime->verify($f->baseline->external_dns);
    $seen = [];
    foreach ($runtime->queries as [$target, $packet, $deadline]) {
        check(in_array($target, ['fd12:3456:789a:a::1', 'fd12:3456:789a:b::1', 'fd12:3456:789a:c::1'], true));
        check(substr($packet, 2, 10) === pack('nnnnn', 0, 1, 0, 0, 0));
        check($deadline <= hrtime(true) + 2000000000);
        $seen[$target][] = substr($packet, 12);
    }
    foreach ($seen as $questions) {
        check(count($questions) === 8 && count(array_unique($questions)) === 8);
        foreach (['AAAA', 'A'] as $type) {
            check(in_array(DnsWire::name('printer.demo.home.arpa.') . pack('nn', DnsWire::TYPES[$type], 1), $questions, true));
        }
    }
    $again = $runtime->verify($f->baseline->external_dns);
    check($again->served_answers_sha256 === $proof->served_answers_sha256);
}));
test('healthy loopback or first listener cannot hide a dead approved ULA listener', fn() => fixture(function (Fixture $f) {
    $runtime = new RuntimeFixture($f);
    $runtime->onQuery = function ($target, $packet) use ($runtime) {
        need($target !== 'fd12:3456:789a:b::1', 'fixture_dns_listener_unavailable');
        return fixtureDnsReply($packet, $runtime->commands['dns-data']);
    };
    refused(fn() => $runtime->verify($f->baseline->external_dns), 'fixture_dns_listener_unavailable');
}));
test('native control-table provenance is required before any served queries', fn() => fixture(function (Fixture $f) {
    $runtime = new RuntimeFixture($f);
    $runtime->commands['dns-data'] = str_replace('AAAA fd12:3456:789a:a::2', 'AAAA fd12:3456:789a:a::3', $runtime->commands['dns-data']);
    refused(fn() => $runtime->verify($f->baseline->external_dns));
    check($runtime->queries === []);
}));
test('empty production runtime uses known local baseline rather than vacuous DNS success', fn() => fixture(function (Fixture $f) {
    $runtime = new RuntimeFixture($f);
    $runtime->raw = preg_replace('~<hosts>.*?</hosts>~s', '', $runtime->raw);
    $runtime->raw = preg_replace('~<staticmap>.*?</staticmap>~s', '', $runtime->raw);
    $runtime->files['/var/dhcpd/etc/dhcpdv6.conf'] = preg_replace('/host \S+ \{[^}]*\}/s', '', $runtime->files['/var/dhcpd/etc/dhcpdv6.conf']);
    $runtime->commands['dns-data'] = "localhost. 10800 IN AAAA ::1\nlocalhost.example.test. 10800 IN AAAA ::1\nsynthetic-router.example.test. 10800 IN A 192.0.2.1";
    $external = projection($runtime->raw, $runtime->policy, 100, $runtime->commands['dns-data'])->external_dns;
    $proof = $runtime->verify($external);
    check($proof->dns_native_host_count === 0 && $proof->served_query_count === 3);
    $runtime->onQuery = fn() => throw new Refusal('fixture_dns_listener_unavailable');
    refused(fn() => $runtime->verify($external), 'fixture_dns_listener_unavailable');
}));
test('public link-local IPv4 and hostname DNS targets fail before transport', fn() => fixture(function (Fixture $f) {
    foreach (['2001:4860:4860::8888', 'fe80::1', '127.0.0.1', '8.8.8.8', 'resolver.example', '::', '::1%em1'] as $target) {
        refused(fn() => DnsUdp::target($target), 'dns_query_target');
    }
    DnsUdp::target('::1');
    DnsUdp::target('fd12:3456:789a:a::1');
    $data = Json::copy($f->policy->data);
    $data->scopes->lan->router_address = '2001:db8:a::1';
    $data->scopes->lan->external_static_addresses = [];
    $data->scopes->lan->approved_reservation_addresses = [];
    $policy = new Policy($data);
    $calls = obj(['count' => 0]);
    refused(fn() => ServedDns::verify($f->env->records, $f->baseline->config, ['localhost.'], $policy,
        function () use ($calls) { $calls->count++; return ''; }), 'dns_query_target');
    check($calls->count === 0);
}));
test('no known local baseline means no query of invented or external names', fn() => fixture(function (Fixture $f) {
    $config = Json::copy($f->baseline->config);
    $config->unbound->hosts = [];
    $calls = obj(['count' => 0]);
    refused(fn() => ServedDns::verify('outside.example. 3600 IN A 192.0.2.77', $config, ['router.example.'], $f->policy,
        function () use ($calls) { $calls->count++; return ''; }), 'dns_baseline_query_required');
    check($calls->count === 0);
}));
test('large native DNS inventory explicitly fails bounded query count before I/O', fn() => fixture(function (Fixture $f) {
    $runtime = new RuntimeFixture($f);
    $config = Json::copy($f->baseline->config);
    $config->unbound->hosts = [];
    $lines = [];
    for ($i = 0; $i < 700; $i++) {
        $address = 'fd12:3456:789a:a::' . dechex(0x100 + $i);
        $name = "node$i.example.";
        $config->unbound->hosts[] = obj(['host' => "node$i", 'domain' => 'example', 'ip' => $address, 'aliases' => obj(['item' => []])]);
        $lines[] = "$name 3600 IN AAAA $address";
        $lines[] = reverseName($address) . " 3600 IN PTR $name";
    }
    $calls = obj(['count' => 0]);
    refused(fn() => ServedDns::verify(implode("\n", $lines), $config, [], $runtime->policy,
        function () use ($calls) { $calls->count++; return ''; }), 'dns_query_limit');
    check($calls->count === 0);
}));
test('monotonic aggregate DNS deadline terminates inventory without partial proof', fn() => fixture(function (Fixture $f) {
    $calls = obj(['count' => 0]);
    $start = hrtime(true);
    refused(fn() => ServedDns::verify($f->env->records, $f->baseline->config, [], $f->policy,
        function ($target, $packet, $deadline) use ($f, $calls, $start) {
            $calls->count++;
            check($deadline <= $start + 200000000);
            usleep(250000);
            return fixtureDnsReply($packet, $f->env->records);
        }, $start + 200000000), 'dns_query_deadline');
    check($calls->count === 1 && hrtime(true) - $start < 2000000000 && ServedDns::BUDGET_NS <= 30000000000);
}));

test('DNS parser accepts binary normalized AAAA full RRsets and standard compressed PTR', function () {
    $name = 'node.example.';
    $packet = DnsWire::request($name, 'AAAA');
    $expected = ['name' => $name, 'type' => 'AAAA', 'records' => [['fd12::1', 3600], ['fd12::2', 3600]]];
    $wire = fixtureDnsReply($packet, "$name 3600 IN AAAA fd12:0:0:0:0:0:0:2\n$name 3600 IN AAAA fd12::1");
    check(DnsWire::response($wire, $packet, $expected) === $expected['records']);
    $packet = DnsWire::request(reverseName('fd12::1'), 'PTR');
    $rdata = "\x06router" . pack('n', 0xc000 | strpos($packet, "\x03ip6\x04arpa\0"));
    $wire = substr($packet, 0, 2) . pack('nnnnn', 0x8400, 1, 1, 0, 0) . substr($packet, 12) .
        "\xc0\x0c" . pack('nnNn', 12, 1, 3600, strlen($rdata)) . $rdata;
    $expected = ['name' => reverseName('fd12::1'), 'type' => 'PTR', 'records' => [['router.ip6.arpa.', 3600]]];
    check(DnsWire::response($wire, $packet, $expected) === $expected['records']);
});
foreach (['bad-id', 'qr', 'opcode', 'tc', 'refused', 'nxdomain', 'qd-count', 'answer-count', 'no-answer', 'extra-section',
    'question-name', 'question-type', 'question-class', 'answer-owner', 'answer-type', 'answer-class', 'cname',
    'wrong-address', 'ttl', 'extra-address', 'duplicate-answer', 'missing-address', 'truncated', 'short-header',
    'trailing', 'oversized', 'bad-rdlength', 'self-pointer', 'forward-pointer', 'header-pointer', 'pointer-loop',
    'label-length', 'name-length'] as $case) {
    test("DNS wire parser refuses $case", function () use ($case) {
        $name = 'node.example.';
        $packet = DnsWire::request($name, 'AAAA');
        $expected = ['name' => $name, 'type' => 'AAAA', 'records' => [['fd12::1', 3600]]];
        $wire = fixtureDnsReply($packet, "$name 3600 IN AAAA fd12::1");
        $start = strlen($packet);
        switch ($case) {
            case 'bad-id': $wire[0] = chr(ord($wire[0]) ^ 1); break;
            case 'qr': $wire = substr_replace($wire, pack('n', 0x0400), 2, 2); break;
            case 'opcode': $wire = substr_replace($wire, pack('n', 0x8c00), 2, 2); break;
            case 'tc': $wire = substr_replace($wire, pack('n', 0x8600), 2, 2); break;
            case 'refused': $wire = substr_replace($wire, pack('n', 0x8405), 2, 2); break;
            case 'nxdomain': $wire = substr_replace($wire, pack('n', 0x8403), 2, 2); break;
            case 'qd-count': $wire = substr_replace($wire, pack('n', 2), 4, 2); break;
            case 'answer-count': $wire = substr_replace($wire, pack('n', 65535), 6, 2); break;
            case 'no-answer': $wire = substr_replace($wire, pack('n', 0), 6, 2); break;
            case 'extra-section': $wire = substr_replace($wire, pack('n', 1), 8, 2); break;
            case 'question-name': $wire[13] = 'x'; break;
            case 'question-type': $wire = substr_replace($wire, pack('n', 1), $start - 4, 2); break;
            case 'question-class': $wire = substr_replace($wire, pack('n', 3), $start - 2, 2); break;
            case 'answer-owner': $wire = substr_replace($wire, DnsWire::name('unrelated.example.'), $start, 2); break;
            case 'answer-type': $wire = substr_replace($wire, pack('n', 1), $start + 2, 2); break;
            case 'answer-class': $wire = substr_replace($wire, pack('n', 3), $start + 4, 2); break;
            case 'cname': $wire = substr_replace($wire, pack('n', 5), $start + 2, 2); break;
            case 'wrong-address': $wire = substr_replace($wire, inet_pton('fd12::2'), $start + 12, 16); break;
            case 'ttl': $wire = substr_replace($wire, pack('N', 3599), $start + 6, 4); break;
            case 'extra-address': $wire = fixtureDnsReply($packet, "$name 3600 IN AAAA fd12::1\n$name 3600 IN AAAA fd12::2"); break;
            case 'duplicate-answer': $wire = fixtureDnsReply($packet, "$name 3600 IN AAAA fd12::1\n$name 3600 IN AAAA fd12::1"); break;
            case 'missing-address': $expected['records'][] = ['fd12::2', 3600]; break;
            case 'truncated': $wire = substr($wire, 0, -1); break;
            case 'short-header': $wire = substr($wire, 0, 11); break;
            case 'trailing': $wire .= "\0"; break;
            case 'oversized': $wire .= str_repeat("\0", DnsWire::MAX_PACKET); break;
            case 'bad-rdlength': $wire = substr_replace($wire, pack('n', 15), $start + 10, 2); break;
            case 'self-pointer': $wire = substr_replace($wire, pack('n', 0xc000 | $start), $start, 2); break;
            case 'forward-pointer': $wire = substr_replace($wire, pack('n', 0xc000 | ($start + 2)), $start, 2); break;
            case 'header-pointer': $wire = substr_replace($wire, "\xc0\x00", $start, 2); break;
            case 'pointer-loop': $wire = substr_replace($wire, "\x01a" . pack('n', 0xc000 | $start), $start, 2); break;
            case 'label-length': $wire = substr_replace($wire, "\x40", $start, 1); break;
            case 'name-length': $wire = substr_replace($wire, str_repeat("\x3f" . str_repeat('a', 63), 4) . "\0", $start, 2); break;
        }
        refused(fn() => DnsWire::response($wire, $packet, $expected));
    });
}
foreach (['wrong-target', 'rdata-loop', 'rdata-length'] as $case) {
    test("DNS PTR parser refuses $case", function () use ($case) {
        $name = reverseName('fd12::1');
        $packet = DnsWire::request($name, 'PTR');
        $wire = fixtureDnsReply($packet, "$name 3600 IN PTR node.example.");
        $expected = ['name' => $name, 'type' => 'PTR', 'records' => [['node.example.', 3600]]];
        if ($case === 'wrong-target') { $expected['records'] = [['wrong.example.', 3600]]; }
        if ($case === 'rdata-loop') { $wire = substr($wire, 0, strlen($packet) + 10) . pack('nn', 2, 0xc000 | (strlen($packet) + 12)); }
        if ($case === 'rdata-length') { $wire = substr_replace($wire, pack('n', strlen(DnsWire::name('node.example.')) + 1), strlen($packet) + 10, 2) . "\0"; }
        refused(fn() => DnsWire::response($wire, $packet, $expected));
    });
}

function fixtureUdp(string $mode, callable $body): void {
    $code = <<<'PHP'
$server = stream_socket_server('udp://[::1]:0', $errno, $error, STREAM_SERVER_BIND);
if (!$server) { exit(2); }
stream_set_timeout($server, 2);
echo stream_socket_get_name($server, false), "\n";
flush();
$packet = stream_socket_recvfrom($server, 512, 0, $peer);
if (!$packet) { exit(3); }
if ($argv[1] === 'timeout') { usleep(200000); exit(0); }
$type = unpack('n', substr($packet, -4, 2))[1];
$rdata = $type === 12 ? "\x04node\x07example\0" : inet_pton('fd12::1');
$reply = substr($packet, 0, 2) . pack('nnnnn', 0x8400, 1, 1, 0, 0) .
    substr($packet, 12) . "\xc0\x0c" . pack('nnNn', $type, 1, 3600, strlen($rdata)) . $rdata;
if ($argv[1] === 'wrong-source') {
    $other = stream_socket_server('udp://[::1]:0', $errno, $error, STREAM_SERVER_BIND);
    $wrong = $reply;
    $wrong[0] = chr(ord($wrong[0]) ^ 1);
    stream_socket_sendto($other, $wrong, 0, $peer);
    usleep(50000);
    fclose($other);
}
stream_socket_sendto($server, $reply, 0, $peer);
fclose($server);
PHP;
    $pipes = [];
    $child = proc_open([PHP_BINARY, '-n', '-r', $code, $mode], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    check(is_resource($child));
    fclose($pipes[0]);
    $socket = null;
    try {
        stream_set_timeout($pipes[1], 2);
        $address = trim((string)fgets($pipes[1], 80));
        check(preg_match('/^\[::1\]:[0-9]{1,5}$/D', $address) === 1);
        $socket = stream_socket_client("udp://$address", $errno, $error, 2, STREAM_CLIENT_CONNECT);
        check(is_resource($socket));
        $body($socket);
    } finally {
        if (is_resource($socket)) { fclose($socket); }
        if (proc_get_status($child)['running']) { proc_terminate($child, 9); }
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($child);
    }
}
foreach (['answer', 'ptr-answer', 'wrong-source', 'timeout'] as $mode) {
    test("actual connected IPv6 UDP transport $mode using only an owned loopback fixture", function () use ($mode) {
        fixtureUdp($mode, function ($socket) use ($mode) {
            $ptr = $mode === 'ptr-answer';
            $name = $ptr ? reverseName('fd12::1') : 'node.example.';
            $type = $ptr ? 'PTR' : 'AAAA';
            $packet = DnsWire::request($name, $type);
            $start = hrtime(true);
            if ($mode === 'timeout') {
                refused(fn() => DnsUdp::exchange($socket, $packet, $start + 100000000), 'dns_query_timeout');
                check(hrtime(true) - $start < 1000000000);
            } else {
                $wire = DnsUdp::exchange($socket, $packet, $start + 2000000000);
                $expected = ['name' => $name, 'type' => $type, 'records' => [[$ptr ? 'node.example.' : 'fd12::1', 3600]]];
                check(DnsWire::response($wire, $packet, $expected) === $expected['records']);
            }
        });
    });
}
test('native runtime metadata permits only root or service regular single-link safe files', function () {
    $base = ['mode' => 0100644, 'uid' => 0, 'nlink' => 1];
    RuntimeFiles::verifyStat($base, [0, 100], false);
    RuntimeFiles::verifyStat(array_replace($base, ['uid' => 100]), [0, 100], false);
    foreach ([['uid' => 101], ['mode' => 0120644], ['mode' => 0100664], ['mode' => 0100666], ['nlink' => 2], ['mode' => 0040755]] as $change) {
        refused(fn() => RuntimeFiles::verifyStat(array_replace($base, $change), [0, 100], false), 'unsafe_runtime_file');
    }
    refused(fn() => (new RuntimeFiles())->read('/etc/passwd'), 'runtime_path');
});
test('known native run directory permits root sticky mode without weakening file checks', function () {
    $run = ['mode' => 0041777, 'uid' => 0, 'nlink' => 2];
    RuntimeFiles::verifyStat($run, [0], true, true);
    foreach ([['mode' => 0040777], ['mode' => 0121777], ['uid' => 100]] as $change) {
        refused(fn() => RuntimeFiles::verifyStat(array_replace($run, $change), [0, 100], true, true), 'unsafe_runtime_file');
    }
    refused(fn() => RuntimeFiles::verifyStat($run, [0], true), 'unsafe_runtime_file');
    refused(fn() => RuntimeFiles::verifyStat($run, [0], false, true), 'unsafe_runtime_file');
});
test('FreeBSD process fields use separate empty-header format arguments', function () {
    $commands = (new \ReflectionClass(FixedCommands::class))->getReflectionConstant('ARGV')->getValue();
    check($commands['process'] === ['/bin/ps', '-ww', '-o', 'pid=', '-o', 'jid=', '-o', 'stat=', '-o', 'lstart=', '-o', 'command=', '-p']);
});
test('only exact pinned FreeBSD procstat may use its native hardlinks', function () {
    $stat = ['uid' => 0, 'mode' => 0100555, 'nlink' => 4, 'size' => 65536];
    $hash = '7e1cc05b7528a691515c6966e6bb1526588cf22c71e845b275648f052587a98b';
    FixedCommands::verifyProcstat($stat, $hash);
    foreach ([['uid' => 1], ['mode' => 0120555], ['mode' => 0100777], ['nlink' => 3], ['size' => MAX_BYTES + 1]] as $change) {
        refused(fn() => FixedCommands::verifyProcstat(array_replace($stat, $change), $hash), 'procstat_executable_pin');
    }
    refused(fn() => FixedCommands::verifyProcstat($stat, str_repeat('0', 64)), 'procstat_executable_pin');
});
foreach (['bridge1', 'pppoe0', 'em4'] as $interface) {
    test("cold boot contract refuses unapproved physical interface $interface", fn() => fixture(function (Fixture $f) use ($interface) {
        $runtime = new RuntimeFixture($f);
        $runtime->raw = str_replace('<if>em1</if>', "<if>$interface</if>", $runtime->raw);
        refused(fn() => $runtime->verify($f->baseline->external_dns), 'runtime_interface_contract');
    }));
}
foreach (['source', 'dirty', 'fsync'] as $case) {
    test("late $case failure leaves no accepted runtime proof", fn() => fixture(function (Fixture $f) use ($case) {
        $r = $f->persist();
        $f->tx->activate($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true);
        $f->bootCandidate();
        $f->env->onHealth = function () use ($f, $case) {
            if ($case === 'source') { $f->env->valid = false; }
            if ($case === 'dirty') { $f->env->dirty = true; }
            if ($case === 'fsync') { $f->files->failSync = true; }
        };
        refused(fn() => $f->tx->verifyActivation($f->policy, $r->transaction_id, $r->current_revision_sha256, $r->request_sha256, true));
        $j = Json::decode(file_get_contents($f->root . '/private/' . $r->transaction_id . '/journal.json'));
        check(in_array($j->activation, ['activation_verifying', 'activation_failed'], true) && $j->runtime->proof === null);
    }));
}
foreach (['wrong-address', 'wrong-duid', 'missing-host', 'comment-only', 'wrong-subnet', 'extra-host', 'extra-fixed', 'truncated', 'include', 'wrong-range'] as $case) {
    test("production DHCP runtime parser rejects $case", fn() => fixture(function (Fixture $f) use ($case) {
        $runtime = new RuntimeFixture($f);
        $raw = $runtime->files['/var/dhcpd/etc/dhcpdv6.conf'];
        switch ($case) {
            case 'wrong-address': $raw = str_replace('fixed-address6 fd12:3456:789a:a::2;', 'fixed-address6 fd12:3456:789a:a::3;', $raw); break;
            case 'wrong-duid': $raw = str_replace('00:01:aa:bb', '00:01:aa:cc', $raw); break;
            case 'missing-host': $raw = preg_replace('/host s_lan_1 \{[^}]*\}/s', '', $raw); break;
            case 'comment-only': $raw = preg_replace('/^fixed-address6 /m', '# fixed-address6 ', $raw); break;
            case 'wrong-subnet': $raw = str_replace('subnet6 fd12:3456:789a:b::/64', 'subnet6 fd12:3456:789a:d::/64', $raw); break;
            case 'extra-host': $raw .= "\nhost evil { host-identifier option dhcp6.client-id 00:01:aa:ff; }"; break;
            case 'extra-fixed': $raw = str_replace('option host-name workstation;', 'fixed-address6 fd12:3456:789a:a::5; option host-name workstation;', $raw); break;
            case 'truncated': $raw .= 'host'; break;
            case 'include': $raw .= 'include "/etc/other";'; break;
            case 'wrong-range': $raw = str_replace('a::ffff;', 'a::eeee;', $raw); break;
        }
        $runtime->files['/var/dhcpd/etc/dhcpdv6.conf'] = $raw;
        refused(fn() => $runtime->verify($f->baseline->external_dns));
    }));
}
foreach (['bad-pid', 'zombie', 'wrong-jail', 'wrong-binary', 'wrong-chroot', 'ipv4-argv', 'wrong-interface', 'wrong-config', 'missing-listener', 'stale-listener-pid', 'dead-unbound', 'dnssec-off', 'ttl', 'ptr', 'foreign-dns', 'radvd-changed', 'ipv4-changed', 'boot-shape', 'check-failed'] as $case) {
    test("production runtime health rejects $case", fn() => fixture(function (Fixture $f) use ($case) {
        $runtime = new RuntimeFixture($f);
        $protected = $runtime->protectedHash();
        switch ($case) {
            case 'bad-pid': $runtime->files['/var/dhcpd/var/run/dhcpdv6.pid'] = "3106;anything\n"; break;
            case 'zombie': $runtime->commands['process:3106'] = str_replace(' Ss ', ' Z ', $runtime->commands['process:3106']); break;
            case 'wrong-jail': $runtime->commands['process:3106'] = str_replace(' 0 Ss ', ' 1 Ss ', $runtime->commands['process:3106']); break;
            case 'wrong-binary': $runtime->commands['process-binary:3106'] = str_replace('/usr/local/sbin/dhcpd', '/usr/local/sbin/notdhcpd', $runtime->commands['process-binary:3106']); break;
            case 'wrong-chroot': $runtime->commands['process-files:3106'] = str_replace('/var/dhcpd', '/elsewhere', $runtime->commands['process-files:3106']); break;
            case 'ipv4-argv': $runtime->commands['process:3106'] = str_replace(' -6 ', ' ', $runtime->commands['process:3106']); break;
            case 'wrong-interface': $runtime->commands['process:3106'] = str_replace(' em3', ' em4', $runtime->commands['process:3106']); break;
            case 'wrong-config': $runtime->commands['process:3106'] = str_replace('/etc/dhcpdv6.conf', '/etc/other.conf', $runtime->commands['process:3106']); break;
            case 'missing-listener': $runtime->commands['dhcp-listener'] = ''; break;
            case 'stale-listener-pid': $runtime->commands['dhcp-listener'] = str_replace('3106', '3107', $runtime->commands['dhcp-listener']); break;
            case 'dead-unbound': $runtime->commands['dns-status'] = 'stopped'; break;
            case 'dnssec-off': $runtime->commands['dns-status'] = str_replace('validator ', '', $runtime->commands['dns-status']); break;
            case 'ttl': $runtime->commands['dns-data'] = str_replace('workstation.demo.home.arpa. 3600', 'workstation.demo.home.arpa. 60', $runtime->commands['dns-data']); break;
            case 'ptr': $runtime->commands['dns-data'] = str_replace('IN PTR workstation.', 'IN PTR wrong.', $runtime->commands['dns-data']); break;
            case 'foreign-dns': $runtime->commands['dns-data'] .= "\nforeign-new.example. 3600 IN AAAA fd12::2"; break;
            case 'radvd-changed': $runtime->files['/var/etc/radvd.conf'] .= 'changed'; break;
            case 'ipv4-changed': $runtime->files['/var/dhcpd/etc/dhcpd.conf'] .= 'changed'; break;
            case 'boot-shape': $runtime->commands['boot-id'] = 'unknown'; break;
            case 'check-failed': $runtime->onRun = function ($name) { need($name !== 'dhcp-check', 'command_failed'); }; break;
        }
        refused(fn() => $runtime->verify($f->baseline->external_dns, $protected));
    }));
}
foreach (['process', 'dns', 'dhcp', 'boot', 'radvd-process'] as $case) {
    test("production runtime verifier detects $case readback race", fn() => fixture(function (Fixture $f) use ($case) {
        $runtime = new RuntimeFixture($f);
        $protected = $runtime->protectedHash();
        $calls = 0;
        $runtime->onRun = function ($name, $pid) use ($runtime, $case, &$calls) {
            if ($name !== 'dns-data' || ++$calls !== 2) { return; }
            switch ($case) {
                case 'process': $runtime->commands['process:3106'] = str_replace('12:00:00', '12:00:01', $runtime->commands['process:3106']); break;
                case 'dns': $runtime->commands['dns-data'] .= "\nrace.example. 3600 IN A 192.0.2.200"; break;
                case 'dhcp': $runtime->files['/var/dhcpd/etc/dhcpdv6.conf'] .= "\n"; break;
                case 'boot': $runtime->commands['boot-id'] = str_repeat("\xb6", 16); break;
                case 'radvd-process': $runtime->commands['process:3101'] = str_replace('12:00:00', '12:00:01', $runtime->commands['process:3101']); break;
            }
        };
        refused(fn() => $runtime->verify($f->baseline->external_dns, $protected));
    }));
}

function child(array $argv, string $cwd): \stdClass {
    $pipes = [];
    $p = proc_open($argv, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $cwd);
    check(is_resource($p));
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);
    $out = $err = '';
    $deadline = hrtime(true) + 15000000000;
    $code = -1;
    try {
        do {
            $out .= stream_get_contents($pipes[1], 65536);
            $err .= stream_get_contents($pipes[2], 65536);
            check(strlen($out) + strlen($err) <= MAX_BYTES);
            $s = proc_get_status($p);
            if (!$s['running']) {
                $out .= stream_get_contents($pipes[1]);
                $err .= stream_get_contents($pipes[2]);
                $code = $s['exitcode'];
                break;
            }
            check(hrtime(true) < $deadline);
            usleep(10000);
        } while (true);
    } finally {
        if (proc_get_status($p)['running']) { proc_terminate($p, 9); }
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($p);
    }
    if ($code !== 0) { throw new \RuntimeException("child failed: $err"); }
    check($err === '');
    return Json::decode($out);
}

if (isset($argv[1])) {
    need(count($argv) === 3 && $argv[1] === '--rust-bin-dir' && is_dir($argv[2]), 'test_arguments');
    $bin = rtrim(realpath($argv[2]), '/');
    test('real Rust plan -> PHP durable persist -> exact rollback with cross-language hashes', function () use ($bin) {
        fixture(function (Fixture $f) use ($bin) {
            $root = dirname(__DIR__, 2);
            $f->raw = str_replace('opaque-boot-value', "Unicode 雪 / \u{2028}", $f->raw);
            $f->addUnmanagedScope();
            file_put_contents($f->root . '/config.xml', $f->raw);
            $f->env->clock = time();
            $f->baseline = projection($f->raw, $f->policy, $f->env->clock, $f->env->records);
            $capture = $f->root . '/capture.json';
            file_put_contents($capture, Json::canonical($f->baseline));
            $db = $f->root . '/inventory.sqlite';
            child([$bin . '/v6alias', 'inventory', '--database', $db, 'init'], $f->root);
            child([$bin . '/v6alias', 'inventory', '--database', $db, 'register', '--device', $root . '/examples/pfsense/device.json'], $f->root);
            child([$bin . '/v6alias', 'service', '--database', $db, '--service-config', $root . '/examples/pfsense/service.yaml', 'allocate', '--observation', $root . '/examples/pfsense/observation.json', '--trusted-link', 'demo-link'], $f->root);
            $command = [$bin . '/v6alias-pfsense', '--database', $db, '--service-config', $root . '/examples/pfsense/service.yaml', '--bindings', $root . '/examples/pfsense/bindings.json', '--capture', $capture];
            $f->request = child([...$command, 'plan'], $f->root);
            $simulation = child([...$command, 'simulate'], $f->root);
            check($simulation->rollback->request_sha256 === Json::hash($f->request));
            check($f->request->baseline_projection_sha256 === Json::hash($f->baseline));
            check($f->request->candidate_projection_sha256 === Json::hash($simulation->projection));
            $beforeDb = hash_file('sha256', $db);
            $r = $f->persist($simulation->rollback->request_sha256);
            check($r->current_revision_sha256 !== $f->request->expected_revision_sha256);
            check($r->request_sha256 === $simulation->rollback->request_sha256);
            check(Json::hash((new NativeXml($f->current()))->projectedConfig($f->policy)) === Json::hash($simulation->projection->config));
            $f->tx->rollback($f->policy, $r->transaction_id, $r->current_revision_sha256, true);
            check($f->current() === $f->raw && hash_file('sha256', $db) === $beforeDb);
        });
    });
} else {
    echo "Rust cross-language execution not requested; pass --rust-bin-dir PATH to built binaries.\n";
}

echo "Passed $count offline helper tests; no router access or activation.\n";
