<?php
declare(strict_types=1);

namespace V6Alias;

require_once __DIR__ . '/core.php';

final class DnsWire {
    public const TYPES = ['A' => 1, 'PTR' => 12, 'AAAA' => 28];
    public const MAX_PACKET = 4096;
    public const MAX_ANSWERS = 256;

    public static function name(string $name): string {
        $wire = '';
        foreach (explode('.', rtrim(dns($name), '.')) as $label) {
            $wire .= chr(strlen($label)) . $label;
        }
        return $wire . "\0";
    }

    public static function request(string $name, string $type): string {
        need(isset(self::TYPES[$type]), 'dns_query_type');
        // RD=0, no EDNS, no resolver search list or recursive fallback.
        return random_bytes(2) . pack('nnnnn', 0, 1, 0, 0, 0) .
            self::name($name) . pack('nn', self::TYPES[$type], 1);
    }

    private static function take(string $wire, int &$at, int $length): string {
        need($length >= 0 && $at + $length <= strlen($wire), 'dns_packet_truncated');
        $value = substr($wire, $at, $length);
        $at += $length;
        return $value;
    }

    private static function readName(string $wire, int &$at): string {
        $cursor = $at;
        $end = null;
        $labels = $seen = [];
        $length = 1;
        while (true) {
            need(count($seen) < 128 && !isset($seen[$cursor]), 'dns_name_loop');
            $seen[$cursor] = true;
            $start = $cursor;
            $size = ord(self::take($wire, $cursor, 1));
            if (($size & 0xc0) === 0xc0) {
                $offset = (($size & 0x3f) << 8) | ord(self::take($wire, $cursor, 1));
                need($offset >= 12 && $offset < $start, 'dns_name_pointer');
                $end ??= $cursor;
                $cursor = $offset;
                continue;
            }
            need($size <= 63, 'dns_label_length');
            if ($size === 0) { break; }
            $length += $size + 1;
            need($length <= 255, 'dns_name_length');
            $labels[] = self::take($wire, $cursor, $size);
        }
        $at = $end ?? $cursor;
        return dns(implode('.', $labels));
    }

    /** A deliberately narrow local-data answer: no CNAME chasing, referrals,
     * additional data, or partial RRsets can count as served proof. */
    public static function response(string $wire, string $query, array $expected): array {
        need(strlen($wire) >= 12 && strlen($wire) <= self::MAX_PACKET, 'dns_packet_size');
        $h = unpack('nid/nflags/nqd/nan/nns/nar', substr($wire, 0, 12));
        need(substr($wire, 0, 2) === substr($query, 0, 2), 'dns_response_id');
        need(($h['flags'] & 0x8000) !== 0 && ($h['flags'] & 0x7a0f) === 0, 'dns_response_flags');
        need($h['qd'] === 1 && $h['an'] >= 1 && $h['an'] <= self::MAX_ANSWERS &&
            $h['ns'] === 0 && $h['ar'] === 0, 'dns_response_counts');
        $at = 12;
        $question = self::readName($wire, $at);
        $q = unpack('ntype/nclass', self::take($wire, $at, 4));
        need($question === $expected['name'] && $q['type'] === self::TYPES[$expected['type']] &&
            $q['class'] === 1 && substr($wire, 12, $at - 12) === substr($query, 12), 'dns_response_question');
        $records = [];
        for ($i = 0; $i < $h['an']; $i++) {
            $owner = self::readName($wire, $at);
            $rr = unpack('ntype/nclass/Nttl/nlength', self::take($wire, $at, 10));
            need($owner === $expected['name'] && $rr['type'] === $q['type'] && $rr['class'] === 1, 'dns_answer_owner_type');
            $end = $at + $rr['length'];
            need($end <= strlen($wire), 'dns_packet_truncated');
            if ($q['type'] === self::TYPES['PTR']) {
                $value = self::readName($wire, $at);
                need($at === $end, 'dns_rdata_length');
            } else {
                need($rr['length'] === ($q['type'] === self::TYPES['AAAA'] ? 16 : 4), 'dns_rdata_length');
                $value = inet_ntop(self::take($wire, $at, $rr['length']));
            }
            $records[] = [$value, $rr['ttl']];
        }
        need($at === strlen($wire), 'dns_packet_trailing');
        $wanted = $expected['records'];
        sort($records, SORT_REGULAR);
        sort($wanted, SORT_REGULAR);
        need($records === $wanted, 'dns_served_rrset');
        return $records;
    }
}

final class DnsUdp {
    public static function target(string $target): void {
        $binary = @inet_pton($target);
        need($binary !== false && strlen($binary) === 16 &&
            ($target === '::1' || (ord($binary[0]) & 0xfe) === 0xfc), 'dns_query_target');
    }

    public function query(string $target, string $packet, int $deadline): string {
        self::target($target);
        $deadline = min($deadline, hrtime(true) + 2000000000);
        need($deadline > hrtime(true), 'dns_query_deadline');
        // A connected UDP socket restricts replies to this literal peer and port.
        $socket = @stream_socket_client("udp://[$target]:53", $errno, $error,
            max(0.001, ($deadline - hrtime(true)) / 1000000000), STREAM_CLIENT_CONNECT);
        need(is_resource($socket), 'dns_query_connect');
        try {
            return self::exchange($socket, $packet, $deadline);
        } finally {
            fclose($socket);
        }
    }

    /** Kept separate so tests exercise real UDP against an owned ephemeral port,
     * without adding a production port override or transport callback. */
    public static function exchange($socket, string $packet, int $deadline): string {
        $deadline = min($deadline, hrtime(true) + 2000000000);
        need(strlen($packet) <= 512 && stream_set_blocking($socket, false), 'dns_query_socket');
        $wait = static function (bool $writing) use ($socket, $deadline): void {
            $left = $deadline - hrtime(true);
            need($left > 0, 'dns_query_timeout');
            $read = $writing ? [] : [$socket];
            $write = $writing ? [$socket] : [];
            $except = [];
            $ready = @stream_select($read, $write, $except, intdiv($left, 1000000000), intdiv($left % 1000000000, 1000));
            need($ready === 1 && hrtime(true) < $deadline, 'dns_query_timeout');
        };
        $wait(true);
        need(@fwrite($socket, $packet) === strlen($packet), 'dns_query_send');
        $wait(false);
        $wire = @stream_socket_recvfrom($socket, DnsWire::MAX_PACKET + 1);
        need(is_string($wire) && $wire !== '' && hrtime(true) < $deadline, 'dns_query_receive');
        return $wire;
    }
}

final class ServedDns {
    public const MAX_QUERIES = 4096;
    public const BUDGET_NS = 30000000000;

    /** Only complete native RRsets, or a known system local-data baseline when
     * there are no overrides, may become questions. Validate before any I/O. */
    public static function plan(string $raw, \stdClass $config, array $systemNames): array {
        DnsRecords::external($raw, $config);
        $local = [];
        foreach (preg_split('/\r?\n/', trim($raw)) as $line) {
            if ($line === '') { continue; }
            preg_match('/^(\S+)\s+([0-9]+)\s+IN\s+([A-Z][A-Z0-9]*)\s+(.+)$/D', $line, $m);
            if (!isset(DnsWire::TYPES[$m[3]])) { continue; }
            need(strlen($m[2]) <= 10 && (int)$m[2] <= 0xffffffff, 'dns_query_ttl');
            $name = dns($m[1]);
            $type = $m[3];
            $local[$name][$type][] = [$type === 'PTR' ? dns(trim($m[4])) : ip(trim($m[4])), (int)$m[2]];
        }
        $questions = [];
        $add = static function (string $name, string $type) use (&$questions, $local): void {
            need(isset($local[$name][$type]) && count($local[$name][$type]) <= DnsWire::MAX_ANSWERS, 'dns_query_local_data');
            $questions["$name $type"] = ['name' => $name, 'type' => $type, 'records' => $local[$name][$type]];
        };
        foreach ($config->unbound->hosts as $host) {
            $name = hostName($host);
            foreach (explode(',', $host->ip) as $address) {
                $address = ip(trim($address));
                $type = str_contains($address, ':') ? 'AAAA' : 'A';
                foreach ([$name, ...array_map(fn($alias) => hostName($alias), $host->aliases->item)] as $owner) {
                    $add($owner, $type);
                }
                $add(reverseName($address), 'PTR');
                need(count($questions) <= self::MAX_QUERIES, 'dns_query_limit');
            }
        }
        if ($questions === []) {
            foreach (['localhost.', ...$systemNames] as $name) {
                foreach (['AAAA', 'A'] as $type) {
                    if (isset($local[$name][$type])) {
                        $add($name, $type);
                        break 2;
                    }
                }
            }
        }
        need($questions !== [], 'dns_baseline_query_required');
        ksort($questions, SORT_STRING);
        return array_values($questions);
    }

    public static function verify(string $raw, \stdClass $config, array $systemNames, Policy $policy, \Closure $query, ?int $deadline = null): \stdClass {
        $deadline = min($deadline ?? PHP_INT_MAX, hrtime(true) + self::BUDGET_NS);
        $questions = self::plan($raw, $config, $systemNames);
        $targets = [];
        foreach ($policy->data->scopes as $scope) {
            DnsUdp::target($scope->router_address);
            $targets[] = $scope->router_address;
        }
        sort($targets, SORT_STRING);
        need(count($questions) * count($targets) <= self::MAX_QUERIES, 'dns_query_limit');
        $served = [];
        foreach ($targets as $target) {
            foreach ($questions as $expected) {
                need(hrtime(true) < $deadline, 'dns_query_deadline');
                $packet = DnsWire::request($expected['name'], $expected['type']);
                $queryDeadline = min($deadline, hrtime(true) + 2000000000);
                $wire = $query($target, $packet, $queryDeadline);
                need(hrtime(true) < $deadline, 'dns_query_deadline');
                need(hrtime(true) < $queryDeadline, 'dns_query_timeout');
                $records = DnsWire::response($wire, $packet, $expected);
                $served[] = [$target, $expected['name'], $expected['type'], $records];
            }
        }
        need(hrtime(true) < $deadline, 'dns_query_deadline');
        return obj(['served_query_count' => count($served), 'served_answers_sha256' => Json::hash($served)]);
    }
}
