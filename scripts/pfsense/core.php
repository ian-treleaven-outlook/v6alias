<?php
declare(strict_types=1);

namespace V6Alias;

const MAX_BYTES = 16777216;
const MAX_RECORDS = 4096;
const CONTRACT = 'pfsense-2.8.1-isc-4.4.3P1-unbound-1.24.2-native-v1';
const COVERAGE = 'all-staticmaps-hosts-aliases-and-external-conflicts';
const TTL_CAPABILITY = 'unbound-local-data-default-3600-no-ttl-overrides';

final class Refusal extends \RuntimeException {}

function need(bool $condition, string $code): void {
    if (!$condition) {
        throw new Refusal($code);
    }
}

function obj(array $values = []): \stdClass {
    return (object)$values;
}

function fields(mixed $value, array $required, array $optional = []): void {
    need($value instanceof \stdClass, 'object_required');
    $keys = array_keys(get_object_vars($value));
    need(!array_diff($required, $keys) && !array_diff($keys, [...$required, ...$optional]), 'unsupported_fields');
}

function text(mixed $value, int $limit = 8192): string {
    need(is_string($value) && strlen($value) <= $limit && !preg_match('/[\x00-\x08\x0b\x0c\x0e-\x1f]/', $value), 'invalid_text');
    return $value;
}

function sha(mixed $value): string {
    need(is_string($value) && preg_match('/^[a-f0-9]{64}$/D', $value) === 1, 'invalid_sha256');
    return $value;
}

function sequence(mixed $value, int $limit = MAX_RECORDS): array {
    need(is_array($value) && array_is_list($value) && count($value) <= $limit, 'invalid_array');
    return $value;
}

/* Decode objects separately from arrays and reject duplicate keys before json_decode
 * could discard them. The signed-integer subset is deliberately narrower than Rust u64. */
final class Json {
    private int $at = 0;
    private int $tokens = 0;
    private function __construct(private string $raw) {}

    public static function decode(string $raw): mixed {
        need(strlen($raw) <= MAX_BYTES, 'json_size');
        $parser = new self($raw);
        $value = $parser->value(0);
        $parser->space();
        need($parser->at === strlen($raw), 'json_trailing_data');
        return $value;
    }

    private function space(): void {
        $this->at += strspn($this->raw, " \r\n\t", $this->at);
    }

    private function string(): string {
        $start = $this->at++;
        $end = strlen($this->raw);
        while ($this->at < $end) {
            $char = $this->raw[$this->at++];
            if ($char === '\\') {
                $this->at++;
            } elseif ($char === '"') {
                try {
                    $value = json_decode(substr($this->raw, $start, $this->at - $start), false, 64, JSON_THROW_ON_ERROR);
                } catch (\Throwable) {
                    throw new Refusal('json_string');
                }
                need(is_string($value), 'json_string');
                return $value;
            }
        }
        throw new Refusal('json_string');
    }

    private function value(int $depth): mixed {
        need($depth <= 64 && ++$this->tokens <= 200000, 'json_complexity');
        $this->space();
        $char = $this->raw[$this->at] ?? '';
        if ($char === '"') {
            return $this->string();
        }
        if ($char === '{' || $char === '[') {
            $object = $char === '{';
            $close = $object ? '}' : ']';
            $this->at++;
            $values = [];
            $seen = [];
            $this->space();
            if (($this->raw[$this->at] ?? '') === $close) {
                $this->at++;
                return $object ? obj() : [];
            }
            while (true) {
                $this->space();
                if ($object) {
                    need(($this->raw[$this->at] ?? '') === '"', 'json_key');
                    $key = $this->string();
                    need(!isset($seen["k:$key"]), 'json_duplicate_key');
                    $seen["k:$key"] = true;
                    $this->space();
                    need(($this->raw[$this->at++] ?? '') === ':', 'json_colon');
                    $values[$key] = $this->value($depth + 1);
                } else {
                    $values[] = $this->value($depth + 1);
                }
                $this->space();
                $next = $this->raw[$this->at++] ?? '';
                if ($next === $close) {
                    return $object ? obj($values) : $values;
                }
                need($next === ',', 'json_separator');
            }
        }
        foreach (['true' => true, 'false' => false, 'null' => null] as $word => $value) {
            if (substr($this->raw, $this->at, strlen($word)) === $word) {
                $this->at += strlen($word);
                return $value;
            }
        }
        need(preg_match('/\G-?(?:0|[1-9][0-9]*)/', $this->raw, $match, 0, $this->at) === 1, 'json_number');
        $token = $match[0];
        $this->at += strlen($token);
        need($token !== '-0' && !str_contains('.eE', $this->raw[$this->at] ?? ' '), 'json_noninteger');
        $number = filter_var($token, FILTER_VALIDATE_INT);
        need($number !== false, 'json_integer_overflow');
        return $number;
    }

    public static function canonical(mixed $value): string {
        $sort = function (mixed $v, int $depth = 0) use (&$sort): mixed {
            need($depth <= 64, 'json_complexity');
            if ($v instanceof \stdClass) {
                $values = get_object_vars($v);
                ksort($values, SORT_STRING);
                foreach ($values as &$item) {
                    $item = $sort($item, $depth + 1);
                }
                return obj($values);
            }
            if (is_array($v)) {
                need(array_is_list($v), 'json_array_keys');
                return array_map(fn($item) => $sort($item, $depth + 1), $v);
            }
            need(is_string($v) || is_int($v) || is_bool($v) || $v === null, 'json_noninteger');
            return $v;
        };
        try {
            $raw = json_encode($sort($value), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS);
        } catch (\JsonException) {
            throw new Refusal('json_encoding');
        }
        need(strlen($raw) <= MAX_BYTES, 'json_size');
        return $raw;
    }

    public static function hash(mixed $value): string {
        return hash('sha256', self::canonical($value));
    }

    public static function copy(mixed $value): mixed {
        return self::decode(self::canonical($value));
    }
}

function dns(string $name): string {
    $name = strtolower($name);
    need(!str_ends_with($name, '..'), 'dns_name');
    $name = rtrim($name, '.');
    need(strlen($name) <= 253 && $name !== '', 'dns_name');
    foreach (explode('.', $name) as $label) {
        need(preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $label) === 1, 'dns_label');
    }
    return $name . '.';
}

function ip(string $address, bool $v6 = false): string {
    $binary = @inet_pton($address);
    need($binary !== false && (!$v6 || strlen($binary) === 16), 'invalid_ip');
    return inet_ntop($binary);
}

function subnet(string $address): string {
    return inet_ntop(substr(inet_pton(ip($address, true)), 0, 8) . str_repeat("\0", 8));
}

function slot(string $network, int $value): string {
    return inet_ntop(substr(inet_pton(ip($network, true)), 0, 8) . str_repeat("\0", 6) . pack('n', $value));
}

function reverseName(string $address): string {
    $binary = inet_pton(ip($address));
    return strlen($binary) === 16
        ? implode('.', str_split(strrev(bin2hex($binary)))) . '.ip6.arpa.'
        : implode('.', array_reverse(explode('.', $address))) . '.in-addr.arpa.';
}

final class Policy {
    public function __construct(public readonly \stdClass $data) {
        fields($data, ['schema_version', 'source', 'audit_id', 'audited_at_unix_secs', 'max_age_secs', 'dns_zone', 'globals_sha256', 'standard_lock_path', 'scopes', 'managed_interfaces']);
        need($data->schema_version === 1 && dns(text($data->source, 63)) === $data->source . '.', 'policy_source');
        need(!str_contains($data->source, '.') && preg_match('/^[a-zA-Z0-9_-]{1,80}$/D', text($data->audit_id)) === 1, 'policy_audit');
        need(is_int($data->audited_at_unix_secs) && $data->audited_at_unix_secs > 0, 'policy_audit');
        need(is_int($data->max_age_secs) && $data->max_age_secs >= 1 && $data->max_age_secs <= 300, 'policy_age');
        need(dns(text($data->dns_zone)) === $data->dns_zone . '.', 'policy_zone');
        sha($data->globals_sha256);
        need($data->standard_lock_path === '/tmp/config.lock', 'standard_lock_contract');
        need($data->scopes instanceof \stdClass && count(get_object_vars($data->scopes)) >= 1 && count(get_object_vars($data->scopes)) <= 3, 'policy_scopes');
        $networks = [];
        foreach ($data->scopes as $name => $scope) {
            need(in_array($name, ['lan', 'opt1', 'opt2'], true), 'policy_interface');
            fields($scope, ['router_address', 'external_static_addresses', 'approved_reservation_addresses']);
            $router = ip(text($scope->router_address), true);
            need($router === $scope->router_address && $router === slot(subnet($router), 1), 'policy_router');
            need(!isset($networks[subnet($router)]), 'policy_duplicate_network');
            $networks[subnet($router)] = true;
            $addresses = [$router => true];
            foreach (['external_static_addresses', 'approved_reservation_addresses'] as $field) {
                foreach (sequence($scope->$field) as $value) {
                    $address = ip(text($value), true);
                    need($address === $value && subnet($address) === subnet($router) && !isset($addresses[$address]), 'policy_address');
                    $addresses[$address] = true;
                    if ($field === 'approved_reservation_addresses') {
                        $bin = inet_pton($address);
                        $iid = unpack('n', substr($bin, 14))[1];
                        need(substr($bin, 8, 6) === str_repeat("\0", 6) && $iid >= 2 && $iid <= 4095, 'policy_managed_pool');
                    }
                }
                $managed = sequence($data->managed_interfaces, 3);
                need($managed !== [], 'policy_managed_interfaces');
                $seen = [];
                foreach ($managed as $name) {
                    need(is_string($name) && isset($data->scopes->$name) && !isset($seen[$name]), 'policy_managed_interfaces');
                    $seen[$name] = true;
                }
            }
        }
    }

    public function paths(): array {
        $paths = array_map(fn($name) => "dhcpdv6/$name/staticmap", $this->data->managed_interfaces);
        sort($paths, SORT_STRING);
        return [...$paths, 'unbound/hosts'];
    }
}

final class NativeXml {
    public readonly \DOMDocument $dom;

    public function __construct(string $raw) {
        need(strlen($raw) > 0 && strlen($raw) <= MAX_BYTES, 'xml_size');
        need(!preg_match('/<!\s*(?:DOCTYPE|ENTITY)/i', $raw) && !str_contains($raw, "\0"), 'xml_entities');
        $this->dom = new \DOMDocument();
        $this->dom->preserveWhiteSpace = true;
        $this->dom->resolveExternals = false;
        $this->dom->substituteEntities = false;
        $old = libxml_use_internal_errors(true);
        try {
            $ok = $this->dom->loadXML($raw, LIBXML_NONET);
            need($ok && $this->dom->doctype === null, 'xml_parse');
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($old);
        }
        need($this->dom->documentElement?->tagName === 'pfsense', 'xml_root');
        $count = 0;
        $walk = function (\DOMNode $node, int $depth) use (&$walk, &$count): void {
            need($depth <= 64 && ++$count <= 200000, 'xml_complexity');
            need(!($node instanceof \DOMEntityReference) && !($node instanceof \DOMProcessingInstruction), 'xml_node');
            if ($node instanceof \DOMElement) {
                need(!$node->hasAttributes() && $node->namespaceURI === null, 'xml_attributes');
            }
            foreach ($node->childNodes as $child) {
                $walk($child, $depth + 1);
            }
        };
        $walk($this->dom, 0);
        self::children($this->dom->documentElement, ['staticmap', 'hosts']);
    }

    public static function children(\DOMElement $element, array $repeated = []): array {
        $result = [];
        foreach ($element->childNodes as $child) {
            if ($child instanceof \DOMElement) {
                need(in_array($child->tagName, $repeated, true) || !isset($result[$child->tagName]), 'xml_duplicate_element');
                $result[$child->tagName][] = $child;
            }
        }
        return $result;
    }

    public function one(string $path): \DOMElement {
        $node = $this->dom->documentElement;
        foreach (explode('/', $path) as $part) {
            $nodes = self::children($node)[$part] ?? [];
            need(count($nodes) === 1, 'xml_missing_section');
            $node = $nodes[0];
        }
        return $node;
    }

    public static function scalar(\DOMElement $element): string {
        need(!self::children($element), 'xml_scalar');
        return text($element->textContent);
    }

    public function systemNames(): array {
        // System users/groups legitimately repeat and are neither DNS inputs nor exportable.
        $system = [];
        foreach ($this->one('system')->childNodes as $node) {
            if ($node instanceof \DOMElement && in_array($node->tagName, ['hostname', 'domain'], true)) {
                need(!isset($system[$node->tagName]), 'xml_duplicate_element');
                $system[$node->tagName] = [$node];
            }
        }
        need(isset($system['hostname'], $system['domain']), 'system_dns_identity');
        $hostname = self::scalar($system['hostname'][0]);
        $domain = self::scalar($system['domain'][0]);
        need(!str_contains($hostname, '.'), 'system_dns_identity');
        return [dns("$hostname.$domain"), dns("localhost.$domain"), 'localhost.'];
    }

    public static function record(\DOMElement $node, string $kind): \stdClass {
        $allowed = $kind === 'staticmap'
            ? ['duid', 'ipaddrv6', 'hostname', 'descr', 'earlydnsregpolicy', 'filename', 'rootpath']
            : ($kind === 'hosts' ? ['host', 'domain', 'ip', 'descr', 'aliases'] : ['host', 'domain', 'description']);
        $result = [];
        foreach (self::children($node) as $name => $children) {
            need(in_array($name, $allowed, true), 'unsupported_native_record_field');
            if ($name === 'aliases') {
                $items = self::children($children[0], ['item']);
                need(!array_diff(array_keys($items), ['item']), 'unsupported_alias_shape');
                $result[$name] = obj(['item' => array_map(fn($item) => self::record($item, 'alias'), $items['item'] ?? [])]);
            } else {
                $result[$name] = self::scalar($children[0]);
            }
        }
        if ($kind === 'hosts' && !isset($result['aliases'])) {
            $result['aliases'] = obj(['item' => []]);
        }
        return obj($result);
    }

    public function projectedConfig(Policy $policy): \stdClass {
        $top = self::children($this->dom->documentElement);
        // The pinned dhcp_get_backend() reads the root key and defaults to ISC.
        $backend = isset($top['dhcpbackend']) ? self::scalar($top['dhcpbackend'][0]) : '';
        need(in_array($backend, ['', 'isc'], true), 'isc_backend_required');
        foreach (['installedpackages', 'dnsmasq'] as $name) {
            if (isset($top[$name])) {
                $children = self::children($top[$name][0]);
                need($name === 'dnsmasq' ? !isset($children['enable']) : !$children, 'unsupported_dns_extension');
            }
        }
        $interfaces = [];
        $scopes = self::children($this->one('dhcpdv6'));
        $expected = array_keys(get_object_vars($policy->data->scopes));
        need(!array_diff(array_keys($scopes), $expected) && !array_diff($expected, array_keys($scopes)), 'incomplete_scopes');
        $dhcp = [];
        foreach ($scopes as $name => $nodes) {
            $iface = self::children($this->one("interfaces/$name"));
            need(isset($iface['ipaddrv6'], $iface['subnetv6']), 'static_interface_required');
            $router = self::scalar($iface['ipaddrv6'][0]);
            // The pinned interface switch selects tracking only when ipaddrv6 is track6.
            // Fixed mode can retain inactive tracking preferences; no interface node is edited.
            need(ip($router, true) === $policy->data->scopes->$name->router_address && self::scalar($iface['subnetv6'][0]) === '64', 'scope_mismatch');
            $interfaces[$name] = obj(['ipaddrv6' => ip($router, true), 'subnetv6' => '64']);
            $value = [];
            foreach (self::children($nodes[0], ['staticmap', 'dnsserver', 'ntpserver']) as $field => $elements) {
                if ($field === 'staticmap') {
                    $value[$field] = array_map(fn($item) => self::record($item, 'staticmap'), $elements);
                } elseif ($field === 'range') {
                    $range = self::children($elements[0]);
                    need(count($range) === 2 && isset($range['from'], $range['to']), 'unsupported_range');
                    $from = ip(self::scalar($range['from'][0]), true);
                    $to = ip(self::scalar($range['to'][0]), true);
                    need($from === slot(subnet($router), 0x1000) && $to === slot(subnet($router), 0xffff), 'bootstrap_range');
                    $value[$field] = obj(['from' => $from, 'to' => $to]);
                } elseif (in_array($field, ['dnsserver', 'ntpserver'], true)) {
                    $value[$field] = array_map(fn($item) => self::scalar($item), $elements);
                } else {
                    $safe = ['enable', 'descr', 'domain', 'domainsearchlist', 'defaultleasetime', 'maxleasetime', 'dnsregpolicy', 'earlydnsregpolicy', 'dhcp6c-dns', 'denyunknown', 'dhcpv6leaseinlocaltime', 'netmask', 'ramode', 'rapriority'];
                    $emptyOnly = ['ddnsdomain', 'ddnsdomainprimary', 'ddnsdomainprimaryport', 'ddnsdomainsecondary', 'ddnsdomainsecondaryport', 'ddnsdomainkeyname', 'ddnsdomainkey', 'tftp', 'ldap', 'bootfile_url', 'pdprefix', 'pdprefixlen', 'pddellen', 'custom_kea_config'];
                    need(in_array($field, [...$safe, ...$emptyOnly], true), 'unsupported_dhcp_field');
                    $scalar = self::scalar($elements[0]);
                    need(!in_array($field, $emptyOnly, true) || $scalar === '', 'unsupported_dhcp_extension');
                    if (in_array($field, ['dnsregpolicy', 'earlydnsregpolicy'], true)) {
                        need(in_array($scalar, ['', 'disable'], true), 'dns_registration');
                    }
                    if ($field === 'ramode') {
                        need($scalar === 'managed', 'unsupported_ra_mode');
                    }
                    if ($field === 'rapriority') {
                        need(in_array($scalar, ['low', 'medium', 'high'], true), 'unsupported_ra_priority');
                    }
                    // Never export even an empty secret-bearing field.
                    if (!str_contains($field, 'key')) {
                        $value[$field] = $scalar;
                    }
                }
            }
            need(isset($value['enable'], $value['range']), 'dhcp_disabled');
            $value['staticmap'] ??= [];
            $dhcp[$name] = obj($value);
        }
        $unbound = [];
        foreach (self::children($this->one('unbound'), ['hosts']) as $field => $elements) {
            if ($field === 'hosts') {
                $unbound[$field] = array_map(fn($item) => self::record($item, 'hosts'), $elements);
                continue;
            }
            $safe = ['enable', 'dnssec', 'active_interface', 'outgoing_interface', 'port', 'system_domain_local_zone_type', 'hideidentity', 'hideversion', 'prefetch', 'prefetchkey', 'qname-minimisation', 'qnamemin', 'dnssecstripped', 'cachemin', 'cachemax', 'infrahostttl', 'infrakeepprobing', 'numqueriesperthread', 'jostletimeout', 'msgcachesize', 'rrsetcachesize', 'numhosts', 'unwantedreplythreshold', 'logqueries', 'logreplies', 'logtagqueryreply', 'logservfail', 'logverbosity', 'ednsbuffersize', 'so_rcvbuf', 'so_sndbuf', 'serveexpired', 'forwarding', 'strictout', 'tlsport', 'incoming_num_tcp', 'outgoing_num_tcp', 'unbound_hardenlargequeries', 'unbound_hardenshortbufsize'];
            $emptyOnly = ['custom_options', 'custom-options'];
            need(in_array($field, [...$safe, ...$emptyOnly], true), 'unsupported_unbound_field');
            $scalar = self::scalar($elements[0]);
            need(!in_array($field, $emptyOnly, true) || $scalar === '', 'custom_unbound_options');
            need($field !== 'system_domain_local_zone_type' || in_array($scalar, ['', 'transparent'], true), 'unsupported_local_zone');
            $unbound[$field] = $scalar;
        }
        need(array_key_exists('enable', $unbound), 'unbound_disabled');
        $unbound['hosts'] ??= [];
        $config = obj(['interfaces' => obj($interfaces), 'dhcpdv6' => obj($dhcp), 'unbound' => obj($unbound)]);
        validateNative($config, $policy);
        return $config;
    }

    public function patch(array $changes): string {
        foreach ($changes as $change) {
            $isHost = $change->path->kind === 'unbound_hosts';
            $tag = $isHost ? 'hosts' : 'staticmap';
            $parent = $this->one($isHost ? 'unbound' : 'dhcpdv6/' . $change->path->interface);
            $old = self::children($parent, $isHost ? [$tag] : [$tag, 'dnsserver', 'ntpserver'])[$tag] ?? [];
            $remaining = $change->after;
            foreach ($old as $node) {
                $record = self::record($node, $tag);
                $found = null;
                foreach ($remaining as $i => $entry) {
                    if (Json::hash($record) === Json::hash($entry)) {
                        $found = $i;
                        break;
                    }
                }
                if ($found !== null) {
                    unset($remaining[$found]);
                } else {
                    need(owned($record), 'foreign_delete');
                    $parent->removeChild($node);
                }
            }
            foreach ($remaining as $record) {
                need(owned($record), 'foreign_add');
                $node = $this->dom->createElement($tag);
                foreach ($record as $key => $value) {
                    $child = $this->dom->createElement($key);
                    if ($key !== 'aliases') {
                        $child->appendChild($this->dom->createTextNode($value));
                    }
                    $node->appendChild($child);
                }
                $parent->appendChild($node);
            }
        }
        $raw = $this->dom->saveXML();
        need(is_string($raw) && strlen($raw) <= MAX_BYTES, 'xml_serialization');
        return $raw;
    }
}

function owned(\stdClass $record): bool {
    return str_starts_with(text($record->descr ?? ''), 'v6alias:');
}

function hostName(\stdClass $record): string {
    $host = text($record->host);
    $domain = text($record->domain);
    need(!str_contains($host, '.') && $domain !== '', 'host_shape');
    return dns(($host === '' ? '' : "$host.") . $domain);
}

function validateNative(\stdClass $config, Policy $policy): void {
    $duids = $dhcpIps = $dhcpNames = $names = $dnsIps = $owners = [];
    $count = 0;
    $unique = function (array &$set, string $value): void {
        need(!isset($set[$value]), 'native_duplicate');
        $set[$value] = true;
    };
    foreach ($config->dhcpdv6 as $interface => $scope) {
        foreach (sequence($scope->staticmap) as $record) {
            $count++;
            fields($record, ['duid'], ['ipaddrv6', 'hostname', 'descr', 'earlydnsregpolicy', 'filename', 'rootpath']);
            need(preg_match('/^[0-9a-f]{2}(?::[0-9a-f]{2}){1,127}$/D', text($record->duid)) === 1, 'native_duid');
            $unique($duids, $record->duid);
            $address = text($record->ipaddrv6 ?? '');
            if ($address !== '') {
                $unique($dhcpIps, ip($address, true));
                need(subnet($address) === subnet($policy->data->scopes->$interface->router_address), 'mapping_scope');
            }
            $hostname = text($record->hostname ?? '');
            if ($hostname !== '') {
                $unique($dhcpNames, dns($hostname));
            }
            if (owned($record)) {
                fields($record, ['duid', 'ipaddrv6', 'hostname', 'descr', 'earlydnsregpolicy', 'filename', 'rootpath']);
                need(preg_match('/^v6alias:[a-zA-Z0-9_-]{1,128}$/D', $record->descr) === 1, 'owner_marker');
                need(!isset($owners[$record->descr]), 'owner_duplicate');
                need($record->earlydnsregpolicy === 'disable' && $record->filename === '' && $record->rootpath === '' && !str_contains($hostname, '.'), 'owned_mapping_fields');
                need(in_array($address, $policy->data->scopes->$interface->approved_reservation_addresses, true), 'unapproved_address');
                $owners[$record->descr] = [$hostname, $address];
            }
        }
    }
    $hostOwners = [];
    foreach (sequence($config->unbound->hosts) as $record) {
        $count++;
        fields($record, ['host', 'domain', 'ip', 'aliases'], ['descr']);
        $unique($names, hostName($record));
        foreach (sequence(explode(',', text($record->ip)), 128) as $value) {
            $unique($dnsIps, ip(trim($value)));
        }
        fields($record->aliases, ['item']);
        foreach (sequence($record->aliases->item, 128) as $alias) {
            fields($alias, ['host', 'domain'], ['description']);
            $unique($names, hostName($alias));
        }
        if (owned($record)) {
            need(isset($owners[$record->descr]) && !isset($hostOwners[$record->descr]), 'owned_pair_required');
            need($owners[$record->descr] === [$record->host, $record->ip] && $record->domain === $policy->data->dns_zone && $record->aliases->item === [], 'owned_host_fields');
            $hostOwners[$record->descr] = true;
        }
    }
    need(count($owners) === count($hostOwners) && $count <= MAX_RECORDS, 'owned_pair_or_record_limit');
}

final class DnsRecords {
    /** Match exact native counterparts, including PTR target and TTL. Everything else
     * stays external; unexpected records at native owners are drift, not exclusions. */
    public static function external(string $raw, \stdClass $config): array {
        need(strlen($raw) <= MAX_BYTES, 'dns_size');
        $expected = $nativeNames = [];
        foreach ($config->unbound->hosts as $host) {
            $name = hostName($host);
            $allNames = [$name, ...array_map(fn($alias) => hostName($alias), $host->aliases->item)];
            foreach (explode(',', $host->ip) as $address) {
                $address = ip(trim($address));
                $type = str_contains($address, ':') ? 'AAAA' : 'A';
                foreach ($allNames as $owner) {
                    $expected["$owner 3600 IN $type $address"] = true;
                    $nativeNames[$owner] = true;
                }
                $ptr = reverseName($address);
                $expected["$ptr 3600 IN PTR $name"] = true;
                $nativeNames[$ptr] = true;
            }
        }
        $external = $seen = [];
        $lines = preg_split('/\r?\n/', trim($raw));
        need(count($lines) <= MAX_RECORDS * 5, 'dns_record_limit');
        foreach ($lines as $line) {
            if ($line === '') {
                continue;
            }
            need(preg_match('/^(\S+)\s+([0-9]+)\s+IN\s+([A-Z][A-Z0-9]*)\s+(.+)$/D', $line, $m) === 1, 'dns_runtime_syntax');
            $owner = dns($m[1]);
            $type = $m[3];
            $value = trim($m[4]);
            if (in_array($type, ['A', 'AAAA'], true)) {
                $value = ip($value, $type === 'AAAA');
                need($type !== 'A' || !str_contains($value, ':'), 'dns_runtime_address');
            } elseif (in_array($type, ['PTR', 'CNAME'], true)) {
                $value = dns($value);
            }
            $key = "$owner {$m[2]} IN $type $value";
            need(!isset($seen[$key]), 'dns_runtime_duplicate');
            $seen[$key] = true;
            if (isset($expected[$key])) {
                unset($expected[$key]);
                continue;
            }
            need(!isset($nativeNames[$owner]), 'dns_native_drift');
            $external[$owner] ??= [];
            if (in_array($type, ['A', 'AAAA'], true)) {
                $external[$owner][$value] = true;
            }
        }
        need(!$expected, 'dns_native_missing');
        ksort($external, SORT_STRING);
        $result = [];
        foreach ($external as $name => $addresses) {
            $addresses = array_keys($addresses);
            sort($addresses, SORT_STRING);
            $result[] = obj(['name' => $name, 'addresses' => $addresses]);
        }
        need(count($result) <= MAX_RECORDS, 'dns_record_limit');
        return $result;
    }
}

function projection(string $raw, Policy $policy, int $now, string $dnsData): \stdClass {
    $xml = new NativeXml($raw);
    $config = $xml->projectedConfig($policy);
    $external = DnsRecords::external($dnsData, $config);
    // Automatic system names must not silently disappear from conflict coverage
    // when the running resolver is stale, even if there are no native overrides.
    foreach ($xml->systemNames() as $name) {
        $matches = array_filter($external, fn($entry) => $entry->name === $name && $entry->addresses !== []);
        need(count($matches) === 1, 'system_dns_runtime_missing_or_shadowed');
    }
    $count = count($external) + count($config->unbound->hosts);
    foreach ($config->dhcpdv6 as $scope) {
        $count += count($scope->staticmap);
    }
    need($count <= MAX_RECORDS, 'projection_record_limit');
    $scopes = [];
    foreach ($policy->data->scopes as $name => $scope) {
        $scopes[$name] = obj([
            'subnet' => subnet($scope->router_address), 'prefix_length' => 64,
            'router_address' => $scope->router_address, 'external_static_addresses' => $scope->external_static_addresses,
        ]);
    }
    return obj([
        'schema_version' => 1, 'source' => $policy->data->source, 'captured_at_unix_secs' => $now,
        'source_contract' => CONTRACT, 'pfsense_version' => '2.8.1-RELEASE', 'dhcp_backend' => 'isc',
        'isc_version' => '4.4.3P1', 'unbound_version' => '1.24.2', 'ttl_capability' => TTL_CAPABILITY,
        'complete' => true, 'coverage' => COVERAGE, 'config_revision_sha256' => hash('sha256', $raw),
        'offline_generation' => 0, 'scopes' => obj($scopes), 'external_dns' => $external, 'config' => $config,
    ]);
}

function validateRequest(Policy $policy, \stdClass $baseline, \stdClass $fresh, \stdClass $request, string $approval, int $now): \stdClass {
    fields($request, ['schema_version', 'mode', 'mutation_scope', 'network_writes', 'approval_required', 'source_contract', 'expected_revision_sha256', 'baseline_projection_sha256', 'authority_sha256', 'candidate_projection_sha256', 'allowed_paths', 'changes', 'activation_requirements']);
    need($request->schema_version === 1 && $request->mode === 'native_plan' && $request->mutation_scope === 'managed_dhcpv6_staticmaps_and_unbound_host_overrides' && $request->network_writes === false && $request->approval_required === true && $request->source_contract === CONTRACT, 'request_contract');
    foreach (['expected_revision_sha256', 'baseline_projection_sha256', 'authority_sha256', 'candidate_projection_sha256'] as $key) {
        sha($request->$key);
    }
    need(hash_equals(sha($approval), Json::hash($request)), 'request_approval_mismatch');
    need(is_int($baseline->captured_at_unix_secs ?? null) && $baseline->captured_at_unix_secs <= $now && $now - $baseline->captured_at_unix_secs <= $policy->data->max_age_secs && ($baseline->offline_generation ?? null) === 0, 'baseline_freshness');
    $fresh = Json::copy($fresh);
    $fresh->captured_at_unix_secs = $baseline->captured_at_unix_secs;
    need(Json::hash($fresh) === Json::hash($baseline) && Json::hash($baseline) === $request->baseline_projection_sha256 && $fresh->config_revision_sha256 === $request->expected_revision_sha256, 'baseline_revision_mismatch');
    need($request->allowed_paths === $policy->paths(), 'request_paths');
    foreach (sequence($request->activation_requirements, 64) as $item) {
        text($item, 256);
    }
    $candidate = Json::copy($baseline);
    $seen = [];
    foreach (sequence($request->changes, 4) as $change) {
        fields($change, ['path', 'before', 'after']);
        need($change->path instanceof \stdClass, 'request_path');
        $host = ($change->path->kind ?? '') === 'unbound_hosts';
        fields($change->path, $host ? ['kind'] : ['kind', 'interface']);
        if ($host) {
            $path = 'unbound/hosts';
            $collection = $candidate->config->unbound;
            $key = 'hosts';
        } else {
            need($change->path->kind === 'dhcpv6_staticmap' && is_string($change->path->interface) && in_array($change->path->interface, $policy->data->managed_interfaces, true), 'request_path');
            $path = 'dhcpdv6/' . $change->path->interface . '/staticmap';
            $collection = $candidate->config->dhcpdv6->{$change->path->interface};
            $key = 'staticmap';
        }
        need(in_array($path, $request->allowed_paths, true), 'request_path');
        need(!isset($seen[$path]), 'duplicate_request_path');
        $seen[$path] = true;
        sequence($change->before);
        sequence($change->after);
        need(Json::hash($collection->$key) === Json::hash($change->before), 'collection_precondition');
        need(Json::hash($change->before) !== Json::hash($change->after), 'empty_collection_change');
        $foreign = fn($entries) => array_values(array_filter($entries, fn($r) => !owned($r)));
        need(Json::hash($foreign($change->before)) === Json::hash($foreign($change->after)), 'foreign_record_changed');
        // The native compiler only retains existing entries in order, then appends.
        $retained = [];
        foreach ($change->before as $entry) {
            if (array_filter($change->after, fn($item) => Json::hash($item) === Json::hash($entry))) {
                $retained[] = $entry;
            }
        }
        need(Json::hash(array_slice($change->after, 0, count($retained))) === Json::hash($retained), 'record_reorder');
        $collection->$key = $change->after;
    }
    if ($request->changes !== []) {
        $candidate->offline_generation = 1;
    }
    validateNative($candidate->config, $policy);
    $foreignDuids = $foreignIps = $foreignNames = [];
    foreach ($candidate->config->dhcpdv6 as $scope) {
        foreach ($scope->staticmap as $record) {
            if (!owned($record)) {
                $foreignDuids[$record->duid] = true;
                if (($record->ipaddrv6 ?? '') !== '') {
                    $foreignIps[ip($record->ipaddrv6, true)] = true;
                }
                if (($record->hostname ?? '') !== '') {
                    $foreignNames[dns($record->hostname)] = true;
                }
            }
        }
    }
    foreach ($candidate->config->unbound->hosts as $record) {
        if (!owned($record)) {
            $foreignNames[hostName($record)] = true;
            foreach ($record->aliases->item as $alias) {
                $foreignNames[hostName($alias)] = true;
            }
            foreach (explode(',', $record->ip) as $address) {
                $foreignIps[ip(trim($address))] = true;
            }
        }
    }
    foreach ($candidate->external_dns as $external) {
        $foreignNames[$external->name] = true;
        foreach ($external->addresses as $address) {
            $foreignIps[$address] = true;
        }
    }
    // Check removed owned records as well, so retirement cannot authorize adoption.
    foreach ([$baseline->config, $candidate->config] as $config) {
        foreach ($config->dhcpdv6 as $scope) {
            foreach ($scope->staticmap as $record) {
                if (owned($record)) {
                    need(!isset($foreignDuids[$record->duid]) && !isset($foreignIps[$record->ipaddrv6]) && !isset($foreignNames[dns($record->hostname)]) && !isset($foreignNames[dns($record->hostname . '.' . $policy->data->dns_zone)]) && !isset($foreignNames[reverseName($record->ipaddrv6)]), 'foreign_conflict');
                }
            }
        }
    }
    need(Json::hash($candidate) === $request->candidate_projection_sha256, 'candidate_proof_mismatch');
    return $candidate;
}
