<?php
declare(strict_types=1);

namespace V6Alias;

require_once __DIR__ . '/core.php';
require_once __DIR__ . '/dns.php';

/* Reads native daemon-owned data, never programs. Native PID/chroot directories
 * need not be root-owned; trust is limited to root and the named service user. */
final class RuntimeFiles {
    private const OWNERS = [
        '/var/dhcpd/etc/dhcpdv6.conf' => 'dhcpd',
        '/var/dhcpd/etc/dhcpd.conf' => 'dhcpd',
        '/var/dhcpd/var/run/dhcpdv6.pid' => 'dhcpd',
        '/var/dhcpd/var/run/dhcpd.pid' => 'dhcpd',
        '/var/etc/radvd.conf' => 'root',
        '/var/run/radvd.pid' => 'root',
    ];

    public static function verifyStat(array $stat, array $uids, bool $directory, bool $nativeRunDirectory = false): void {
        if ($nativeRunDirectory) {
            need($directory && ($stat['mode'] & 0170000) === 0040000 && $stat['uid'] === 0 &&
                (($stat['mode'] & 0022) === 0 || ($stat['mode'] & 01000) !== 0), 'unsafe_runtime_file');
            return;
        }
        need(($stat['mode'] & 0170000) === ($directory ? 0040000 : 0100000) &&
            in_array($stat['uid'], $uids, true) && ($stat['mode'] & 0022) === 0 &&
            ($directory || $stat['nlink'] === 1), 'unsafe_runtime_file');
    }

    public function read(string $path, bool $optional = false): ?string {
        need(isset(self::OWNERS[$path]), 'runtime_path');
        $account = posix_getpwnam(self::OWNERS[$path]);
        need(is_array($account), 'runtime_owner');
        $uids = [0, $account['uid']];
        $check = static function (string $name, bool $directory) use ($uids): array {
            clearstatcache(true, $name);
            $s = @lstat($name);
            need(is_array($s), 'unsafe_runtime_file');
            self::verifyStat($s, $uids, $directory, $directory && $name === '/var/run');
            return $s;
        };
        for ($parent = dirname($path); ; $parent = dirname($parent)) {
            $check($parent, true);
            if ($parent === '/') { break; }
        }
        clearstatcache(true, $path);
        if ($optional && @lstat($path) === false) { return null; }
        $before = $check($path, false);
        need($before['size'] <= MAX_BYTES, 'runtime_file_size');
        $file = @fopen($path, 'rb');
        need(is_resource($file), 'runtime_file_open');
        try {
            $opened = fstat($file);
            need($opened !== false && $opened['ino'] === $before['ino'] && $opened['dev'] === $before['dev'], 'runtime_file_race');
            self::verifyStat($opened, $uids, false);
            $raw = stream_get_contents($file, MAX_BYTES + 1);
            need(is_string($raw) && strlen($raw) === $before['size'], 'runtime_file_read');
            $after = $check($path, false);
            foreach (['ino', 'dev', 'size', 'mtime', 'ctime', 'uid', 'mode', 'nlink'] as $field) {
                need($after[$field] === $before[$field], 'runtime_file_race');
            }
            return $raw;
        } finally {
            fclose($file);
        }
    }
}

final class RuntimeHealth {
    public const CONTRACT = 'pfsense-cold-boot-health-v2';

    public function __construct(private \Closure $read, private \Closure $run, private ?\Closure $query = null) {}

    public function bootIdentity(): string {
        $raw = ($this->run)('boot-id');
        need(strlen($raw) === 16, 'boot_identity');
        return hash('sha256', $raw);
    }

    public static function interfaces(NativeXml $xml, Policy $policy): array {
        $names = [];
        foreach ($policy->data->scopes as $scope => $_) {
            $parts = NativeXml::children($xml->one("interfaces/$scope"));
            need(isset($parts['enable'], $parts['if']), 'runtime_interface_disabled');
            $name = NativeXml::scalar($parts['if'][0]);
            need(in_array($name, ['em1', 'em2', 'em3'], true) && !in_array($name, $names, true), 'runtime_interface_contract');
            $names[] = $name;
        }
        sort($names, SORT_STRING);
        need($names === ['em1', 'em2', 'em3'], 'runtime_interface_contract');
        return $names;
    }

    public static function pid(string $raw): int {
        need(preg_match('/^[1-9][0-9]{0,8}\n?$/D', $raw) === 1, 'runtime_pid');
        return (int)trim($raw);
    }

    private function process(int $pid, string $executable, array $prefix, ?array $interfaces, ?string $chroot): string {
        $ps = trim(($this->run)('process', $pid));
        need(preg_match('/^([0-9]+)\s+([0-9]+)\s+(\S+)\s+(.+?)\s{1,}((?:\/)[^\r\n]+)$/D', $ps, $m) === 1, 'runtime_process_shape');
        need((int)$m[1] === $pid && $m[2] === '0' && !strpbrk($m[3], 'ZXT'), 'runtime_process_state');
        $argv = preg_split('/\s+/', $m[5]);
        need(array_slice($argv, 0, count($prefix)) === $prefix, 'runtime_process_arguments');
        $tail = array_slice($argv, count($prefix));
        if ($interfaces === null) {
            need($tail === [], 'runtime_process_arguments');
        } else {
            sort($tail, SORT_STRING);
            if ($interfaces === []) {
                need($tail !== [] && count($tail) === count(array_unique($tail)), 'runtime_process_interfaces');
                foreach ($tail as $name) { need(preg_match('/^[a-z][a-z0-9]{0,15}$/D', $name) === 1, 'runtime_process_interfaces'); }
            } else {
                need($tail === $interfaces, 'runtime_process_interfaces');
            }
        }
        $binary = ($this->run)('process-binary', $pid);
        need(preg_match('/^\s*' . $pid . '\s+\S+\s+[0-9]+\s+' . preg_quote($executable, '/') . '\s*$/m', $binary) === 1, 'runtime_process_executable');
        if ($chroot !== null) {
            $files = ($this->run)('process-files', $pid);
            need(preg_match('/^\s*' . $pid . '\s+\S+\s+root\s+[^\r\n]*\s' . preg_quote($chroot, '/') . '\s*$/m', $files) === 1, 'runtime_process_chroot');
        }
        need(trim(($this->run)('process', $pid)) === $ps, 'runtime_process_race');
        return hash('sha256', $ps . "\n" . trim($binary));
    }

    private function dhcpProcess(bool $v6, ?array $interfaces = null): string {
        $name = $v6 ? 'dhcpdv6' : 'dhcpd';
        $pidPath = "/var/dhcpd/var/run/$name.pid";
        $raw = ($this->read)($pidPath);
        $pid = self::pid($raw);
        $prefix = ['/usr/local/sbin/dhcpd', ...($v6 ? ['-6'] : []), '-user', 'dhcpd', '-group', '_dhcp', '-chroot', '/var/dhcpd', '-cf', "/etc/$name.conf", '-pf', "/var/run/$name.pid"];
        $identity = $this->process($pid, $prefix[0], $prefix, $interfaces ?? [], '/var/dhcpd');
        need(($this->read)($pidPath) === $raw, 'runtime_pid_race');
        return $identity;
    }

    public function protectedState(): \stdClass {
        $v4 = ($this->read)('/var/dhcpd/etc/dhcpd.conf', true);
        $pid4 = ($this->read)('/var/dhcpd/var/run/dhcpd.pid', true);
        need(($v4 === null) === ($pid4 === null), 'protected_dhcp_state');
        $process4 = $v4 === null ? null : $this->dhcpProcess(false);
        $ra = ($this->read)('/var/etc/radvd.conf');
        $pid = ($this->read)('/var/run/radvd.pid');
        $processRa = $this->process(self::pid($pid), '/usr/local/sbin/radvd', ['/usr/local/sbin/radvd', '-p', '/var/run/radvd.pid', '-C', '/var/etc/radvd.conf', '-m', 'syslog'], null, null);
        need(($this->read)('/var/run/radvd.pid') === $pid, 'runtime_pid_race');
        return obj([
            'dhcp4_config_sha256' => $v4 === null ? null : hash('sha256', $v4), 'radvd_config_sha256' => hash('sha256', $ra),
            'dhcp4_process_sha256' => $process4, 'radvd_process_sha256' => $processRa,
        ]);
    }

    public static function preservation(\stdClass $state): string {
        return Json::hash(obj(['dhcp4_config_sha256' => $state->dhcp4_config_sha256, 'radvd_config_sha256' => $state->radvd_config_sha256]));
    }

    private function dhcpListener(): void {
        $pid = self::pid(($this->read)('/var/dhcpd/var/run/dhcpdv6.pid'));
        $sockets = ($this->run)('dhcp-listener');
        need(preg_match('/^\S+\s+\S+\s+' . $pid . '\s+[0-9]+\s+udp6\s+\S+:547\s+\S+\s*$/m', $sockets) === 1, 'dhcp_runtime_listener');
    }

    /* Parse the generated ISC grammar, not substring matches that can be satisfied
     * by comments, wrong hosts, or a reservation in the wrong subnet. */
    public static function dhcpConfig(string $raw, \stdClass $config): int {
        need(strlen($raw) <= MAX_BYTES, 'dhcp_runtime_size');
        preg_match_all('/"(?:[^"\\\\]|\\\\.)*"|#[^\r\n]*|[{};]|[^\s{};"#]+/', $raw, $matches);
        $blocks = $statement = $header = $body = [];
        $inside = false;
        foreach ($matches[0] as $token) {
            if (str_starts_with($token, '#')) { continue; }
            if ($token === '{') {
                need(!$inside && count($statement) === 2 && in_array($statement[0], ['host', 'subnet6'], true), 'dhcp_runtime_block');
                $inside = true;
                $header = $statement;
                $body = $statement = [];
            } elseif ($token === '}') {
                need($inside && $statement === [], 'dhcp_runtime_block');
                $blocks[] = [$header, $body];
                $inside = false;
            } elseif ($token === ';') {
                need($statement !== [] && !in_array($statement[0], ['include', 'execute', 'on'], true), 'dhcp_runtime_statement');
                if ($inside) { $body[] = $statement; }
                else { need(!in_array($statement[0], ['fixed-address6', 'host-identifier', 'range6'], true), 'dhcp_runtime_statement'); }
                $statement = [];
            } else {
                $statement[] = $token;
            }
        }
        need(!$inside && $statement === [], 'dhcp_runtime_truncated');
        $expectedHosts = $expectedSubnets = [];
        foreach ($config->dhcpdv6 as $name => $scope) {
            $net = subnet($config->interfaces->$name->ipaddrv6) . '/64';
            $expectedSubnets[$net] = [$scope->range->from, $scope->range->to];
            foreach ($scope->staticmap as $i => $record) {
                $expectedHosts["s_{$name}_{$i}"] = [$record->duid, ($record->ipaddrv6 ?? '') === '' ? null : ip($record->ipaddrv6, true)];
            }
        }
        $count = count($expectedHosts);
        foreach ($blocks as [$header, $body]) {
            if ($header[0] === 'host') {
                need(isset($expectedHosts[$header[1]]), 'dhcp_runtime_unexpected_host');
                $duid = $address = null;
                foreach ($body as $parts) {
                    if (array_slice($parts, 0, 3) === ['host-identifier', 'option', 'dhcp6.client-id']) {
                        need($duid === null && count($parts) === 4, 'dhcp_runtime_duid');
                        $duid = strtolower($parts[3]);
                    } elseif ($parts[0] === 'fixed-address6') {
                        need($address === null && count($parts) === 2, 'dhcp_runtime_address');
                        $address = ip($parts[1], true);
                    } else {
                        need(($parts[0] === 'filename' && count($parts) === 2) ||
                            ($parts[0] === 'option' && count($parts) === 3 && in_array($parts[1], ['host-name', 'root-path'], true)), 'dhcp_runtime_host_option');
                    }
                }
                need([$duid, $address] === $expectedHosts[$header[1]], 'dhcp_runtime_mapping');
                unset($expectedHosts[$header[1]]);
            } else {
                $parts = explode('/', $header[1]);
                need(count($parts) === 2 && $parts[1] === '64', 'dhcp_runtime_subnet');
                $net = ip($parts[0], true) . '/64';
                need(isset($expectedSubnets[$net]), 'dhcp_runtime_subnet');
                $range = null;
                foreach ($body as $line) {
                    if ($line[0] === 'range6') {
                        need($range === null && count($line) === 3, 'dhcp_runtime_range');
                        $range = [ip($line[1], true), ip($line[2], true)];
                    }
                }
                need($range === $expectedSubnets[$net], 'dhcp_runtime_range');
                unset($expectedSubnets[$net]);
            }
        }
        need(!$expectedHosts && !$expectedSubnets, 'dhcp_runtime_missing');
        return $count;
    }

    public function verify(string $raw, Policy $policy, array $external, string $protectedHash, int $now): \stdClass {
        need($this->query !== null, 'dns_query_unconfigured');
        $xml = new NativeXml($raw);
        $config = $xml->projectedConfig($policy);
        $interfaces = self::interfaces($xml, $policy);
        $boot = $this->bootIdentity();
        $protected = $this->protectedState();
        need(self::preservation($protected) === $protectedHash, 'protected_runtime_changed');
        $dhcp = ($this->read)('/var/dhcpd/etc/dhcpdv6.conf');
        $count = self::dhcpConfig($dhcp, $config);
        ($this->run)('dhcp-check');
        $process = $this->dhcpProcess(true, $interfaces);
        $this->dhcpListener();
        ($this->run)('unbound-check');
        $status = ($this->run)('dns-status');
        need(preg_match('/^modules:\s+[0-9]+\s+\[([^\r\n]*)\]\s*$/m', $status, $modules) === 1 &&
            (in_array('validator', preg_split('/\s+/', trim($modules[1])), true) === property_exists($config->unbound, 'dnssec')), 'runtime_dnssec');
        need(preg_match('/^unbound \(pid ([1-9][0-9]*)\) is running[^\r\n]*$/m', $status, $m) === 1, 'unbound_health');
        $unbound = $this->process((int)$m[1], '/usr/local/sbin/unbound', ['/usr/local/sbin/unbound', '-c', '/var/unbound/unbound.conf'], null, null);
        $dns = ($this->run)('dns-data');
        $projection = projection($raw, $policy, $now, $dns);
        need(Json::hash($projection->external_dns) === Json::hash($external), 'external_dns_runtime_changed');
        $served = ServedDns::verify($dns, $config, $xml->systemNames(), $policy, $this->query);
        need(($this->run)('dns-data') === $dns && ($this->run)('dns-status') !== '', 'dns_runtime_race');
        $this->dhcpListener();
        need(($this->read)('/var/dhcpd/etc/dhcpdv6.conf') === $dhcp &&
            $this->dhcpProcess(true, $interfaces) === $process &&
            $this->process((int)$m[1], '/usr/local/sbin/unbound', ['/usr/local/sbin/unbound', '-c', '/var/unbound/unbound.conf'], null, null) === $unbound &&
            Json::hash($this->protectedState()) === Json::hash($protected) && $this->bootIdentity() === $boot, 'runtime_health_race');
        return obj([
            'contract' => self::CONTRACT, 'boot_sha256' => $boot, 'config_revision_sha256' => hash('sha256', $raw),
            'dhcp_config_sha256' => hash('sha256', $dhcp), 'dns_data_sha256' => hash('sha256', $dns),
            'processes_sha256' => hash('sha256', $process . $unbound . Json::hash($protected)), 'protected_sha256' => $protectedHash,
            'dhcp_mapping_count' => $count, 'dns_native_host_count' => count($config->unbound->hosts), 'verified_at_unix_secs' => $now,
            'served_query_count' => $served->served_query_count, 'served_answers_sha256' => $served->served_answers_sha256,
        ]);
    }

    public static function proof(\stdClass $proof): void {
        need(($proof->contract ?? null) !== 'pfsense-cold-boot-health-v1', 'legacy_runtime_proof_requires_manual_recovery');
        fields($proof, ['contract', 'boot_sha256', 'config_revision_sha256', 'dhcp_config_sha256', 'dns_data_sha256', 'processes_sha256', 'protected_sha256', 'dhcp_mapping_count', 'dns_native_host_count', 'verified_at_unix_secs', 'served_query_count', 'served_answers_sha256']);
        need($proof->contract === self::CONTRACT, 'runtime_proof_contract');
        foreach (['boot_sha256', 'config_revision_sha256', 'dhcp_config_sha256', 'dns_data_sha256', 'processes_sha256', 'protected_sha256', 'served_answers_sha256'] as $field) { sha($proof->$field); }
        foreach (['dhcp_mapping_count', 'dns_native_host_count', 'verified_at_unix_secs'] as $field) {
            need(is_int($proof->$field) && $proof->$field >= 0, 'runtime_proof_count');
        }
        need(is_int($proof->served_query_count) && $proof->served_query_count >= max(1, 2 * $proof->dns_native_host_count) &&
            $proof->served_query_count <= ServedDns::MAX_QUERIES, 'runtime_proof_served_count');
    }
}
