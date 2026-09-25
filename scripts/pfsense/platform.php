<?php
declare(strict_types=1);

namespace V6Alias;

require_once __DIR__ . '/storage.php';

final class SourceGate {
    public const ACTIVATION_BLOCKER = 'hot_reload_unavailable_use_approved_external_cold_restart';
    public const PINS = [
        'config.inc' => 'e4b8260bc75108d390cc8bd0192597bfdd809b10f147fdb0cabd6b4893494460',
        'config.lib.inc' => 'a3c35727dd29e60223c4bb52b9fff9aa4aab82b7adeff637317cc330cbdad840',
        'services.inc' => '2fe344f0717d127319b574a54377ad81c4e83d75415ae878b4f02fb25d28c266',
        'unbound.inc' => 'c9695572de37b91743ede5ea05ca82d9f55b3a5d96f69f72ba7d8e37c7d8f6f2',
        'util.inc' => '3fbb5051daff1956959d91bcb25036e333d3f2394bcd00e1963704a1b0e50623',
        'xmlparse.inc' => 'a3a3585454803ace95926795eb6084d07e474ef56fc13e6960cc0a53eee3116f',
        'pfsense-utils.inc' => '60aa9e3f4391de3f067ad61025fb1abfe11a15c5902a8452576a8fe581e05910',
        'interfaces.inc' => '95e4dd2b519fa70c9cec5c3d26de5e14afcbe831fac05bb1ce9ab3b1bd460726',
        'services_dhcp.inc' => 'f8caec631c20bfb0b47e20d5a3d52d03273a627d2e3a88d33a2a271efb44d282',
    ];

    public static function verify(string $version, array $hashes, string $dhcpVersion, string $unboundVersion, Policy $policy): void {
        need(trim($version) === '2.8.1-RELEASE', 'pfsense_version_pin');
        foreach ([...self::PINS, 'globals.inc' => $policy->data->globals_sha256] as $name => $expected) {
            need(($hashes[$name] ?? null) === $expected, 'native_source_pin');
        }
        need(preg_match('/(?:^|\s)(?:isc-dhcpd-|ISC DHCP )4\.4\.3-P1(?:\s|$)/', $dhcpVersion) === 1, 'isc_version_pin');
        need(preg_match('/(?:^|\s)Version 1\.24\.2(?:\s|$)/', $unboundVersion) === 1, 'unbound_version_pin');
    }

    public static function identity(Policy $policy): string {
        $paths = [];
        foreach ([...array_keys(self::PINS), 'globals.inc'] as $name) { $paths[$name] = self::path($name); }
        return Json::hash(obj([
            'contract' => CONTRACT, 'files' => obj([...self::PINS, 'globals.inc' => $policy->data->globals_sha256]),
            'paths' => obj($paths), 'runtime_contract' => RuntimeHealth::CONTRACT,
        ]));
    }

    public static function path(string $name): string {
        need(isset(self::PINS[$name]) || $name === 'globals.inc', 'source_path');
        return $name === 'services_dhcp.inc' ? '/usr/local/pfSense/include/www/services_dhcp.inc' : '/etc/inc/' . $name;
    }
}

final class FixedCommands {
    private const PROCSTAT_SHA256 = '7e1cc05b7528a691515c6966e6bb1526588cf22c71e845b275648f052587a98b';
    private const ARGV = [
        'dhcp-version' => ['/usr/local/sbin/dhcpd', '--version'],
        'unbound-version' => ['/usr/local/sbin/unbound', '-V'],
        'dns-data' => ['/usr/local/sbin/unbound-control', '-c', '/var/unbound/unbound.conf', '-s', '127.0.0.1@953', 'list_local_data'],
        'dns-status' => ['/usr/local/sbin/unbound-control', '-c', '/var/unbound/unbound.conf', '-s', '127.0.0.1@953', 'status'],
        'boot-id' => ['/sbin/sysctl', '-b', 'kern.boot_id'],
        'dhcp-check' => ['/usr/local/sbin/dhcpd', '-6', '-t', '-cf', '/var/dhcpd/etc/dhcpdv6.conf'],
        'unbound-check' => ['/usr/local/sbin/unbound-checkconf', '/var/unbound/unbound.conf'],
        'process' => ['/bin/ps', '-ww', '-o', 'pid=', '-o', 'jid=', '-o', 'stat=', '-o', 'lstart=', '-o', 'command=', '-p'],
        'process-binary' => ['/usr/bin/procstat', '-b'],
        'process-files' => ['/usr/bin/procstat', '-f'],
        'dhcp-listener' => ['/usr/bin/sockstat', '-6', '-l', '-P', 'udp', '-p', '547'],
    ];

    public function __construct(private Files $files) {}

    public static function verifyProcstat(array $stat, string $hash): void {
        // This installed FreeBSD utility has four native hardlink entry points.
        need($stat['uid'] === 0 && $stat['mode'] === 0100555 && $stat['nlink'] === 4 &&
            $stat['size'] <= MAX_BYTES && hash_equals(self::PROCSTAT_SHA256, $hash), 'procstat_executable_pin');
    }

    public function run(string $command, ?int $pid = null): string {
        need(isset(self::ARGV[$command]), 'command_not_allowlisted');
        $argv = self::ARGV[$command];
        if (str_starts_with($command, 'process')) {
            need($pid !== null && $pid > 0 && $pid <= 999999999, 'command_pid');
            $argv[] = (string)$pid;
        } else {
            need($pid === null, 'command_pid');
        }
        $this->files->parents($argv[0]);
        if ($argv[0] === '/usr/bin/procstat') {
            clearstatcache(true, $argv[0]);
            $stat = @lstat($argv[0]);
            need(is_array($stat) && $stat['mode'] === 0100555 && $stat['size'] <= MAX_BYTES, 'procstat_executable_pin');
            self::verifyProcstat($stat, hash_file('sha256', $argv[0]));
            clearstatcache(true, $argv[0]);
            $after = @lstat($argv[0]);
            foreach (['ino', 'dev', 'size', 'mtime', 'ctime', 'uid', 'mode', 'nlink'] as $key) {
                need(is_array($after) && $after[$key] === $stat[$key], 'procstat_executable_race');
            }
        } else {
            $this->files->checked($argv[0]);
        }
        $pipes = [];
        $process = proc_open($argv, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $command === 'unbound-check' ? '/var/unbound' : '/', ['PATH' => '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin', 'LANG' => 'C', 'LC_ALL' => 'C'], ['bypass_shell' => true]);
        need(is_resource($process), 'command_start');
        fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $stdout = $stderr = '';
        $deadline = hrtime(true) + 5000000000;
        $exit = -1;
        try {
            do {
                $stdout .= stream_get_contents($pipes[1], 65536);
                $stderr .= stream_get_contents($pipes[2], 65536);
                need(strlen($stdout) + strlen($stderr) <= MAX_BYTES, 'command_output_limit');
                $status = proc_get_status($process);
                if (!$status['running']) {
                    $stdout .= stream_get_contents($pipes[1], MAX_BYTES + 1);
                    $stderr .= stream_get_contents($pipes[2], MAX_BYTES + 1);
                    $exit = $status['exitcode'];
                    break;
                }
                need(hrtime(true) < $deadline, 'command_timeout');
                usleep(10000);
            } while (true);
        } finally {
            $status = proc_get_status($process);
            if ($status['running']) {
                // Only this process handle is signalled; no name-based process killing.
                proc_terminate($process, 9);
            }
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($process);
        }
        need($exit === 0 && strlen($stdout) + strlen($stderr) <= MAX_BYTES, 'command_failed');
        $combined = in_array($command, ['dhcp-version', 'unbound-version', 'dhcp-check', 'unbound-check'], true);
        need($combined || ($command === 'boot-id' ? $stderr === '' : trim($stderr) === ''), 'runtime_command_warning');
        need($command !== 'boot-id' || strlen($stdout) === 16, 'boot_identity');
        return $combined ? $stdout . "\n" . $stderr : $stdout;
    }
}

final class LiveEnvironment implements Environment {
    private FixedCommands $commands;
    private RuntimeHealth $runtime;

    public function __construct(private Files $files) {
        need(PHP_SAPI === 'cli' && PHP_OS_FAMILY === 'BSD' && php_uname('s') === 'FreeBSD' && function_exists('posix_geteuid') && posix_geteuid() === 0 && PHP_INT_SIZE === 8 && PHP_VERSION_ID >= 80300, 'freebsd_root_cli_required');
        need(extension_loaded('dom') && function_exists('fsync') && function_exists('proc_open'), 'php_capabilities');
        $this->commands = new FixedCommands($files);
        $nativeFiles = new RuntimeFiles();
        $dns = new DnsUdp();
        $this->runtime = new RuntimeHealth($nativeFiles->read(...), $this->commands->run(...), $dns->query(...));
    }

    public function gate(Policy $policy): void {
        $hashes = [];
        foreach ([...array_keys(SourceGate::PINS), 'globals.inc'] as $name) {
            $hashes[$name] = hash('sha256', $this->files->read(SourceGate::path($name)));
        }
        SourceGate::verify($this->files->read('/etc/version', false, 256), $hashes, $this->commands->run('dhcp-version'), $this->commands->run('unbound-version'), $policy);
        need($policy->data->audited_at_unix_secs <= time(), 'future_policy_audit');
    }

    public function clean(): void {
        $this->files->checkRuntimeDirectory('/var/run');
        $this->files->checkRuntimeDirectory('/tmp');
        foreach (['dhcpd6', 'hosts', 'unbound', 'interfaces', 'filter', 'staticroutes'] as $name) {
            clearstatcache(true, '/var/run/' . $name . '.dirty');
            need(@lstat('/var/run/' . $name . '.dirty') === false, 'pending_native_changes');
        }
        // Sidecars/extensions have independent semantics which this writer cannot attest.
        need(@lstat('/tmp/config.extra.cache') === false, 'unsupported_config_extension_cache');
    }

    public function dnsData(): string {
        return $this->commands->run('dns-data');
    }

    public function now(): int {
        return time();
    }

    public function bootIdentity(): string { return $this->runtime->bootIdentity(); }

    public function prepareRuntime(string $raw, Policy $policy): string {
        $xml = new NativeXml($raw);
        $xml->projectedConfig($policy);
        RuntimeHealth::interfaces($xml, $policy);
        return RuntimeHealth::preservation($this->runtime->protectedState());
    }

    public function verifyRuntime(string $raw, Policy $policy, array $external, string $protectedHash): \stdClass {
        return $this->runtime->verify($raw, $policy, $external, $protectedHash, $this->now());
    }

    public static function configDirectory(Files $files): string {
        $path = '/conf';
        $stat = @lstat($path);
        need($stat !== false && $stat['uid'] === 0, 'config_directory');
        if (($stat['mode'] & 0170000) === 0120000) {
            // pfSense installations can use this specific immutable alias.
            need(readlink($path) === '/cf/conf', 'unsupported_conf_alias');
            $path = '/cf/conf';
        }
        $files->parents($path . '/config.xml');
        return $path;
    }
}
