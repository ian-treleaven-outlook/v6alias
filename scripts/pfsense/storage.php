<?php
declare(strict_types=1);

namespace V6Alias;

require_once __DIR__ . '/core.php';
require_once __DIR__ . '/runtime.php';

class Files {
    private bool $initializingStockLock = false;

    public function __construct(protected readonly int $uid = 0) {}

    public static function verifyStat(array $stat, int $uid, bool $directory, bool $private, bool $stockLock = false): void {
        need(($stat['mode'] & 0170000) === ($directory ? 0040000 : 0100000) && $stat['uid'] === $uid, 'unsafe_file_type_owner');
        need($directory || $stat['nlink'] === 1, 'unsafe_hardlink');
        if ($private) {
            need(($stat['mode'] & 0777) === ($directory ? 0700 : 0600), 'private_permissions');
        } elseif (!$stockLock) {
            need(($stat['mode'] & 0022) === 0, 'unsafe_permissions');
        }
    }

    public function checked(string $path, bool $private = false, bool $directory = false, bool $stockLock = false): array {
        clearstatcache(true, $path);
        $stat = @lstat($path);
        need($stat !== false, 'file_missing');
        self::verifyStat($stat, $this->uid, $directory, $private, $stockLock);
        return $stat;
    }

    public function parents(string $path, bool $stickyParent = false): void {
        need(str_starts_with($path, '/') && !str_contains($path, "\0") && !preg_match('~(?:^|/)\.\.?(?:/|$)~', $path), 'absolute_trusted_path_required');
        $parent = dirname($path);
        while (true) {
            if ($stickyParent && in_array($parent, ['/tmp', '/var/run'], true)) {
                $s = @lstat($parent);
                need($s !== false && $s['uid'] === 0 && ($s['mode'] & 0170000) === 0040000 && ($s['mode'] & 01000) !== 0, 'unsafe_lock_parent');
            } else {
                $this->checked($parent, false, true);
            }
            if ($parent === '/') {
                break;
            }
            $parent = dirname($parent);
        }
    }

    public function checkRuntimeDirectory(string $path): void {
        need(in_array($path, ['/tmp', '/var/run'], true), 'runtime_directory');
        $this->parents($path);
        $stat = @lstat($path);
        need($stat !== false && $stat['uid'] === $this->uid && ($stat['mode'] & 0170000) === 0040000 &&
            (($stat['mode'] & 0022) === 0 || ($stat['mode'] & 01000) !== 0), 'unsafe_runtime_directory');
    }

    public function read(string $path, bool $private = false, int $limit = MAX_BYTES): string {
        $this->parents($path);
        $before = $this->checked($path, $private);
        need($before['size'] <= $limit, 'file_size');
        $file = @fopen($path, 'rb');
        need($file !== false, 'file_open');
        try {
            $opened = fstat($file);
            need($opened !== false && $before['ino'] === $opened['ino'] && $before['dev'] === $opened['dev'], 'file_race');
            $bytes = stream_get_contents($file, $limit + 1);
            need(is_string($bytes) && strlen($bytes) <= $limit && strlen($bytes) === $before['size'], 'file_short_read');
            $after = $this->checked($path, $private);
            foreach (['ino', 'dev', 'size', 'mtime', 'ctime', 'mode', 'uid', 'nlink'] as $field) {
                need($before[$field] === $after[$field], 'file_race');
            }
            return $bytes;
        } finally {
            fclose($file);
        }
    }

    public function point(string $stage): void {}

    protected function writeChunk($file, string $bytes): int|false {
        return fwrite($file, $bytes);
    }

    protected function syncFile($file): bool {
        return fflush($file) && fsync($file);
    }

    public function syncDirectory(string $path): void {
        $this->checked($path, false, true);
        $file = @fopen($path, 'r');
        need($file !== false, 'directory_open');
        try {
            need(@fsync($file), 'directory_fsync');
        } finally {
            fclose($file);
        }
    }

    public function mkdir(string $path): void {
        $this->parents($path);
        need(@lstat($path) === false && @mkdir($path, 0700), 'private_directory_create');
        $this->checked($path, true, true);
        $this->syncDirectory(dirname($path));
    }

    public function create(string $path, string $bytes): void {
        need(strlen($bytes) <= MAX_BYTES, 'file_size');
        $this->parents($path);
        $file = @fopen($path, 'x+b');
        need($file !== false, 'exclusive_file_create');
        try {
            need(@chmod($path, 0600), 'file_chmod');
            $this->checked($path, true);
            $offset = 0;
            while ($offset < strlen($bytes)) {
                $n = $this->writeChunk($file, substr($bytes, $offset, 65536));
                need(is_int($n) && $n > 0, 'file_short_write');
                $offset += $n;
            }
            need($this->syncFile($file), 'file_fsync');
        } finally {
            fclose($file);
        }
        need(hash('sha256', $this->read($path, true)) === hash('sha256', $bytes), 'file_readback');
        $this->syncDirectory(dirname($path));
    }

    protected function renameFile(string $from, string $to): bool {
        return @rename($from, $to);
    }

    public function publishDirectory(string $staging, string $destination): void {
        $this->parents($staging);
        $this->parents($destination);
        $this->checked($staging, true, true);
        need(dirname($staging) === dirname($destination) && @lstat($destination) === false, 'journal_publish_path');
        $this->syncDirectory($staging);
        need($this->renameFile($staging, $destination), 'journal_publish');
        $this->syncDirectory(dirname($destination));
    }

    public function discardPreparation(string $path): void {
        $this->parents($path);
        $this->checked($path, true, true);
        $entries = scandir($path);
        need(is_array($entries) && !array_diff($entries, ['.', '..', 'before.xml', 'activation.json', 'journal.json']), 'preparation_contents');
        foreach (['before.xml', 'activation.json', 'journal.json'] as $name) {
            $file = $path . '/' . $name;
            if (@lstat($file) !== false) {
                $this->checked($file, true);
                need(@unlink($file), 'preparation_cleanup');
            }
        }
        need(@rmdir($path), 'preparation_cleanup');
        $this->syncDirectory(dirname($path));
    }

    public function replace(string $path, string $bytes, ?string $expectedHash = null): void {
        $this->parents($path);
        $staging = dirname($path) . '/.v6alias-' . bin2hex(random_bytes(16));
        $this->create($staging, $bytes);
        try {
            if ($expectedHash !== null) {
                need(hash('sha256', $this->read($path)) === $expectedHash, 'revision_cas');
            } else {
                $this->checked($path, true);
            }
            $this->point('before_rename');
            // Recheck immediately after the injectable boundary as well.
            if ($expectedHash !== null) {
                need(hash('sha256', $this->read($path)) === $expectedHash, 'revision_cas');
            }
            need($this->renameFile($staging, $path), 'atomic_rename');
            $this->point('after_rename');
            $this->syncDirectory(dirname($path));
            need(hash('sha256', $this->read($path, true)) === hash('sha256', $bytes), 'commit_readback');
        } finally {
            if (@lstat($staging) !== false) {
                $this->checked($staging, true);
                @unlink($staging);
            }
        }
    }

    public function lock(string $path, bool $stock, float $seconds = 5.0) {
        $this->parents($path, $stock);
        if (!$stock && @lstat($path) === false) {
            // Parent is private; never create or unlink the shared pfSense lock.
            $this->create($path, '');
        }
        $before = $this->checked($path, !$stock, false, $stock);
        $file = @fopen($path, 'r+b');
        need($file !== false, 'lock_open');
        try {
            $this->assertLockIdentity($path, $file, $stock, $before);
            $this->acquireLock($file, $seconds);
            $this->assertLockIdentity($path, $file, $stock, $before);
            return $file;
        } catch (\Throwable $error) {
            fclose($file);
            throw $error;
        }
    }

    private function acquireLock($file, float $seconds): void {
        $deadline = hrtime(true) + (int)($seconds * 1000000000);
        do {
            if (flock($file, LOCK_EX | LOCK_NB)) {
                return;
            }
            usleep(10000);
        } while (hrtime(true) < $deadline);
        throw new Refusal('lock_timeout');
    }

    public function assertLockIdentity(string $path, $file, bool $stock, ?array $before = null): array {
        $named = $this->checked($path, !$stock, false, $stock);
        $opened = fstat($file);
        need($opened !== false, 'lock_stat');
        self::verifyStat($opened, $this->uid, false, !$stock, $stock);
        foreach ([$opened, $before ?? $opened] as $other) {
            need($named['ino'] === $other['ino'] && $named['dev'] === $other['dev'], 'lock_race');
        }
        return $named;
    }

    protected function standardLockPath(): string {
        return '/tmp/config.lock';
    }

    private function lockParent(string $path): array {
        $this->parents($path, true);
        clearstatcache(true, dirname($path));
        $stat = @lstat(dirname($path));
        need($stat !== false && $stat['uid'] === $this->uid &&
            ($stat['mode'] & 0177777) === 0041777, 'unsafe_lock_parent');
        return $stat;
    }

    public function initializeStandardLock(string $path, float $seconds = 5.0): bool {
        need($path === $this->standardLockPath(), 'standard_lock_contract');
        need(!$this->initializingStockLock, 'lock_initialization_reentrant');
        $this->initializingStockLock = true;
        $file = null;
        try {
            $parent = $this->lockParent($path);
            clearstatcache(true, $path);
            $created = false;
            if (@lstat($path) === false) {
                $this->point('lock_before_create');
                $mask = umask(0077);
                try {
                    $file = @fopen($path, 'x+b');
                } finally {
                    umask($mask);
                }
                $created = $file !== false;
            }
            if (!$created) {
                // An O_EXCL loser may adopt only the independently verified stock inode.
                $before = $this->checked($path, false, false, true);
                $file = @fopen($path, 'r+b');
                need($file !== false, 'lock_open');
            } else {
                $before = fstat($file);
                need($before !== false, 'lock_stat');
            }
            $this->point('lock_opened');
            $this->assertLockIdentity($path, $file, true, $before);
            $this->acquireLock($file, $seconds);
            $named = $this->assertLockIdentity($path, $file, true, $before);
            need(in_array($named['mode'] & 07777, [0600, 0666], true), 'stock_lock_permissions');
            // PHP has no fchmod. Sticky root-owned /tmp protects this root-owned name;
            // stock writers touch/truncate/chmod it but must never replace its inode.
            if (($named['mode'] & 07777) !== 0666) {
                need(@chmod($path, 0666), 'stock_lock_chmod');
            }
            $this->point('lock_permissions');
            $named = $this->assertLockIdentity($path, $file, true, $before);
            need(($named['mode'] & 07777) === 0666 && $this->syncFile($file), 'stock_lock_fsync');
            $directory = @fopen(dirname($path), 'r');
            need($directory !== false, 'directory_open');
            try {
                $opened = fstat($directory);
                $after = $this->lockParent($path);
                foreach ([$opened, $after] as $stat) {
                    need(is_array($stat) && $stat['ino'] === $parent['ino'] && $stat['dev'] === $parent['dev'], 'lock_parent_race');
                }
                need(@fsync($directory), 'directory_fsync');
            } finally {
                fclose($directory);
            }
            $this->point('lock_initialized');
            $this->assertLockIdentity($path, $file, true, $before);
            return $created;
        } finally {
            if (is_resource($file)) {
                flock($file, LOCK_UN);
                fclose($file);
            }
            $this->initializingStockLock = false;
        }
    }

    public function removeCache(string $path): void {
        $this->parents($path, true);
        if (@lstat($path) !== false) {
            $this->checked($path);
            need(@unlink($path), 'cache_invalidation');
        }
    }
}

interface Environment {
    public function gate(Policy $policy): void;
    public function dnsData(): string;
    public function clean(): void;
    public function now(): int;
    public function bootIdentity(): string;
    public function prepareRuntime(string $raw, Policy $policy): string;
    public function verifyRuntime(string $raw, Policy $policy, array $external, string $protectedHash): \stdClass;
}

final class Collector {
    public function __construct(private Files $files, private Environment $environment, private string $configPath) {}

    public function capture(Policy $policy): \stdClass {
        $this->environment->gate($policy);
        $this->environment->clean();
        $raw = $this->files->read($this->configPath);
        $dns = $this->environment->dnsData();
        $captured = projection($raw, $policy, $this->environment->now(), $dns);
        // A second runtime snapshot detects registration/reload races without DNS queries.
        need(Json::hash($captured->external_dns) === Json::hash(DnsRecords::external($this->environment->dnsData(), $captured->config)), 'runtime_capture_race');
        need(hash('sha256', $this->files->read($this->configPath)) === $captured->config_revision_sha256, 'config_capture_race');
        $this->environment->clean();
        return $captured;
    }
}

final class Transactions {
    public ?string $transactionId = null;
    public function __construct(
        private Files $files,
        private Environment $environment,
        private string $configPath,
        private string $statePath,
        private string $standardLock,
        private array $cachePaths,
    ) {}

    private function underHelperLock(Policy $policy, callable $action): mixed {
        $this->environment->gate($policy);
        if (@lstat($this->statePath) === false) {
            $this->files->mkdir($this->statePath);
        }
        $this->files->checked($this->statePath, true, true);
        $own = $this->files->lock($this->statePath . '/helper.lock', false);
        try {
            return $action();
        } finally {
            flock($own, LOCK_UN);
            fclose($own);
        }
    }

    private function underStandardLock(Policy $policy, callable $action): mixed {
        $standard = $this->files->lock($this->standardLock, true);
        try {
            $this->environment->gate($policy);
            $result = $action();
            $this->files->assertLockIdentity($this->standardLock, $standard, true);
            return $result;
        } finally {
            flock($standard, LOCK_UN);
            fclose($standard);
        }
    }

    private function underLock(Policy $policy, callable $action): mixed {
        return $this->underHelperLock($policy, fn() => $this->underStandardLock($policy, $action));
    }

    public function initializeLock(Policy $policy, bool $maintenance): \stdClass {
        need($maintenance, 'maintenance_window_required');
        return $this->underHelperLock($policy, function () use ($policy) {
            $this->environment->gate($policy);
            $this->environment->clean();
            $created = $this->files->initializeStandardLock($this->standardLock);
            return obj([
                'schema_version' => 1, 'mode' => 'local_stock_lock_initialization',
                'standard_lock_path' => $policy->data->standard_lock_path,
                'created' => $created, 'lock_ready' => true, 'config_persisted' => false,
                'runtime_activation_performed' => false,
            ]);
        });
    }

    private function journalPath(string $id): string {
        need(preg_match('/^[a-f0-9]{32}$/D', $id) === 1, 'transaction_id');
        return $this->statePath . '/' . $id . '/journal.json';
    }

    private function load(string $id): \stdClass {
        $journal = Json::decode($this->files->read($this->journalPath($id), true));
        need(!in_array($journal->schema_version ?? null, [1, 2], true), 'legacy_journal_requires_manual_recovery');
        fields($journal, ['schema_version', 'transaction_id', 'status', 'request_sha256', 'request_file_sha256', 'policy_sha256', 'source_sha256', 'evidence_sha256', 'before_sha256', 'after_sha256', 'created_at_unix_secs', 'activation', 'runtime', 'preserved_runtime_sha256']);
        need($journal->schema_version === 3 && $journal->transaction_id === $id &&
            in_array($journal->status, ['prepared', 'committed', 'rollback_prepared', 'rolled_back', 'aborted'], true), 'journal_contract');
        need(is_int($journal->created_at_unix_secs) && $journal->created_at_unix_secs > 0, 'journal_contract');
        foreach (['request_sha256', 'request_file_sha256', 'policy_sha256', 'source_sha256', 'evidence_sha256', 'before_sha256', 'after_sha256'] as $key) {
            sha($journal->$key);
        }
        if ($journal->preserved_runtime_sha256 !== null) { sha($journal->preserved_runtime_sha256); }
        if ($journal->runtime === null) {
            need(in_array($journal->activation, ['not_activated', 'rollback_required'], true), 'journal_runtime_state');
            need(($journal->status === 'rolled_back') === ($journal->activation === 'rollback_required'), 'journal_runtime_state');
        } else {
            $r = $journal->runtime;
            need(($r->contract ?? null) !== 'pfsense-cold-boot-health-v1', 'legacy_runtime_proof_requires_manual_recovery');
            fields($r, ['contract', 'target', 'boot_before_sha256', 'protected_sha256', 'prepared_at_unix_secs', 'proof']);
            need($r->contract === RuntimeHealth::CONTRACT && in_array($r->target, ['before', 'after'], true), 'journal_runtime_contract');
            need(in_array($journal->status, $r->target === 'after' ? ['committed', 'rollback_prepared'] : ['rolled_back'], true), 'journal_runtime_state');
            sha($r->boot_before_sha256);
            sha($r->protected_sha256);
            need($r->protected_sha256 === $journal->preserved_runtime_sha256, 'journal_preservation_contract');
            need(is_int($r->prepared_at_unix_secs) && $r->prepared_at_unix_secs > 0, 'journal_runtime_contract');
            $states = $r->target === 'after'
                ? ['awaiting_cold_boot', 'activation_verifying', 'activation_failed', 'activated']
                : ['rollback_awaiting_cold_boot', 'rollback_verifying', 'rollback_failed', 'rollback_verified'];
            need(in_array($journal->activation, $states, true), 'journal_runtime_state');
            need(($r->proof !== null) === in_array($journal->activation, ['activated', 'rollback_verified'], true), 'journal_runtime_proof');
            if ($r->proof !== null) {
                RuntimeHealth::proof($r->proof);
                need($r->proof->boot_sha256 !== $r->boot_before_sha256 &&
                    $r->proof->verified_at_unix_secs >= $r->prepared_at_unix_secs &&
                    $r->proof->protected_sha256 === $r->protected_sha256 &&
                    $r->proof->config_revision_sha256 === ($r->target === 'after' ? $journal->after_sha256 : $journal->before_sha256), 'journal_runtime_proof');
            }
        }
        $this->evidence($journal);
        return $journal;
    }

    private function evidence(\stdClass $journal): \stdClass {
        $raw = $this->files->read($this->statePath . '/' . $journal->transaction_id . '/activation.json', true);
        need(hash('sha256', $raw) === $journal->evidence_sha256, 'activation_evidence_integrity');
        $evidence = Json::decode($raw);
        fields($evidence, ['schema_version', 'request', 'baseline', 'baseline_dns']);
        need($evidence->schema_version === 1 && is_string($evidence->baseline_dns), 'activation_evidence_contract');
        need(Json::hash($evidence->request) === $journal->request_sha256, 'activation_request_integrity');
        return $evidence;
    }

    private function journalPolicy(Policy $policy, \stdClass $journal): void {
        need(Json::hash($policy->data) === $journal->policy_sha256, 'journal_policy_mismatch');
        need(SourceGate::identity($policy) === $journal->source_sha256, 'journal_source_mismatch');
    }

    private function verifyEvidence(Policy $policy, \stdClass $journal, string $before): void {
        $evidence = $this->evidence($journal);
        $baseline = projection($before, $policy, $journal->created_at_unix_secs, $evidence->baseline_dns);
        $candidate = validateRequest($policy, $evidence->baseline, $baseline, $evidence->request, $journal->request_sha256, $journal->created_at_unix_secs);
        $after = (new NativeXml($before))->patch($evidence->request->changes);
        need(hash('sha256', $after) === $journal->after_sha256 &&
            Json::hash((new NativeXml($after))->projectedConfig($policy)) === Json::hash($candidate->config), 'activation_candidate_integrity');
    }

    private function save(\stdClass $journal): void {
        $this->files->replace($this->journalPath($journal->transaction_id), Json::canonical($journal));
    }

    private function invalidate(): void {
        foreach ($this->cachePaths as $path) {
            $this->files->removeCache($path);
        }
    }

    private function result(\stdClass $journal, string $revision, bool $wrote, bool $healthNow = false): \stdClass {
        return obj([
            'schema_version' => 1, 'mode' => 'local_privileged_persistence', 'transaction_id' => $journal->transaction_id,
            'status' => $journal->status, 'activation' => $journal->activation, 'config_persisted' => $wrote,
            'network_writes' => $wrote || $revision === $journal->after_sha256 || !in_array($journal->status, ['prepared', 'aborted'], true),
            'runtime_activation_performed' => false,
            'runtime_health_verified' => $healthNow, 'runtime_activation_supported' => true,
            'runtime_health_previously_verified' => $journal->status !== 'rollback_prepared' && $journal->runtime?->proof !== null,
            'runtime_health_proof' => $journal->status === 'rollback_prepared' ? null : $journal->runtime?->proof,
            'activation_method' => 'operator_cold_restart_then_verify',
            'cold_restart_required' => in_array($journal->activation, ['awaiting_cold_boot', 'rollback_required', 'rollback_awaiting_cold_boot'], true),
            'hot_reload_supported' => false, 'hot_reload_blocker' => SourceGate::ACTIVATION_BLOCKER,
            'recovery_scope' => 'config_cache_and_explicit_cold_boot_runtime_verification',
            'recovery_required' => in_array($journal->status, ['prepared', 'rollback_prepared'], true) ||
                !in_array($journal->activation, ['not_activated', 'activated', 'rollback_verified'], true),
            'current_revision_sha256' => $revision, 'request_sha256' => $journal->request_sha256,
            'request_file_sha256' => $journal->request_file_sha256,
        ]);
    }

    private function noPending(): void {
        $entries = scandir($this->statePath);
        need(is_array($entries) && count($entries) <= MAX_RECORDS, 'journal_limit');
        foreach ($entries as $entry) {
            // Unpublished preparation cannot have reached the configuration write.
            if (preg_match('/^\.prepare-[a-f0-9]{32}$/D', $entry) === 1) {
                $this->files->discardPreparation($this->statePath . '/' . $entry);
            }
            if (preg_match('/^[a-f0-9]{32}$/D', $entry) === 1) {
                $j = $this->load($entry);
                need($j->status === 'aborted' ||
                    ($j->status === 'committed' && $j->activation === 'activated') ||
                    ($j->status === 'rolled_back' && $j->activation === 'rollback_verified'), 'prior_transaction_requires_recovery_or_activation');
            }
        }
    }

    public function persist(Policy $policy, \stdClass $baseline, \stdClass $request, string $approval, string $requestFileHash, bool $maintenance): \stdClass {
        need($maintenance, 'maintenance_window_required');
        sha($requestFileHash);
        // Approval ignores object-key order; make XML serialization reproducible
        // from the immutable canonical request retained for recovery.
        $request = Json::decode(Json::canonical($request));
        $this->transactionId = null;
        return $this->underLock($policy, function () use ($policy, $baseline, $request, $approval, $requestFileHash) {
            $this->noPending();
            $collector = new Collector($this->files, $this->environment, $this->configPath);
            $fresh = $collector->capture($policy);
            $approvedAt = $this->environment->now();
            $candidate = validateRequest($policy, $baseline, $fresh, $request, $approval, $approvedAt);
            need($request->changes !== [], 'empty_request');
            $raw = $this->files->read($this->configPath);
            need(hash('sha256', $raw) === $request->expected_revision_sha256, 'revision_cas');
            $xml = new NativeXml($raw);
            $after = $xml->patch($request->changes);
            need(Json::hash((new NativeXml($after))->projectedConfig($policy)) === Json::hash($candidate->config), 'serialized_candidate_mismatch');
            $id = bin2hex(random_bytes(16));
            $directory = $this->statePath . '/' . $id;
            $staging = $this->statePath . '/.prepare-' . $id;
            $this->files->mkdir($staging);
            $this->files->point('preparation_directory');
            $this->files->create($staging . '/before.xml', $raw);
            $this->files->point('preparation_backup');
            $dns = $this->environment->dnsData();
            need(Json::hash(DnsRecords::external($dns, $fresh->config)) === Json::hash($fresh->external_dns), 'runtime_capture_race');
            $evidence = Json::canonical(obj([
                'schema_version' => 1, 'request' => $request, 'baseline' => $baseline, 'baseline_dns' => $dns,
            ]));
            $this->files->create($staging . '/activation.json', $evidence);
            $this->files->point('preparation_evidence');
            $journal = obj([
                'schema_version' => 3, 'transaction_id' => $id, 'status' => 'prepared',
                'request_sha256' => Json::hash($request), 'request_file_sha256' => $requestFileHash,
                'policy_sha256' => Json::hash($policy->data), 'before_sha256' => hash('sha256', $raw),
                'source_sha256' => SourceGate::identity($policy), 'evidence_sha256' => hash('sha256', $evidence),
                'after_sha256' => hash('sha256', $after), 'created_at_unix_secs' => $approvedAt,
                'activation' => 'not_activated', 'runtime' => null, 'preserved_runtime_sha256' => null,
            ]);
            $this->files->create($staging . '/journal.json', Json::canonical($journal));
            $this->files->point('preparation_journal');
            $this->transactionId = $id;
            $this->files->publishDirectory($staging, $directory);
            $this->files->point('prepared');
            $this->environment->gate($policy);
            $this->environment->clean();
            // Recheck the approved age after potentially slow durable preparation.
            need($this->environment->now() - $baseline->captured_at_unix_secs <= $policy->data->max_age_secs, 'baseline_freshness');
            $this->files->replace($this->configPath, $after, $journal->before_sha256);
            $this->files->point('config_committed');
            $this->invalidate();
            need(hash('sha256', $this->files->read($this->configPath)) === $journal->after_sha256, 'post_commit_foreign_change');
            $journal->status = 'committed';
            $this->save($journal);
            need(hash('sha256', $this->files->read($this->configPath)) === $journal->after_sha256, 'post_journal_foreign_change');
            return $this->result($journal, $journal->after_sha256, true);
        });
    }

    public function recover(Policy $policy, string $id, bool $maintenance): \stdClass {
        need($maintenance, 'maintenance_window_required');
        return $this->underLock($policy, function () use ($policy, $id) {
            $this->transactionId = $id;
            $j = $this->load($id);
            $this->journalPolicy($policy, $j);
            $before = $this->files->read($this->statePath . '/' . $id . '/before.xml', true);
            need(hash('sha256', $before) === $j->before_sha256, 'backup_integrity');
            $this->verifyEvidence($policy, $j, $before);
            $current = hash('sha256', $this->files->read($this->configPath));
            need(in_array($current, [$j->before_sha256, $j->after_sha256], true), 'recovery_foreign_revision');
            if ($j->status === 'prepared') {
                $j->status = $current === $j->after_sha256 ? 'committed' : 'aborted';
            } elseif ($j->status === 'rollback_prepared') {
                $j->status = $current === $j->before_sha256 ? 'rolled_back' : 'committed';
                if ($j->status === 'rolled_back') { $j->activation = 'rollback_required'; $j->runtime = null; }
            } else {
                need($current === (in_array($j->status, ['rolled_back', 'aborted'], true) ? $j->before_sha256 : $j->after_sha256), 'recovery_state_mismatch');
            }
            $this->files->syncDirectory(dirname($this->configPath));
            $this->invalidate();
            need(hash('sha256', $this->files->read($this->configPath)) === $current, 'recovery_foreign_revision');
            $this->save($j);
            need(hash('sha256', $this->files->read($this->configPath)) === $current, 'recovery_foreign_revision');
            return $this->result($j, $current, false);
        });
    }

    public function rollback(Policy $policy, string $id, string $expected, bool $maintenance): \stdClass {
        need($maintenance, 'maintenance_window_required');
        sha($expected);
        return $this->underLock($policy, function () use ($policy, $id, $expected) {
            $this->transactionId = $id;
            $j = $this->load($id);
            need($j->status === 'committed' && Json::hash($policy->data) === $j->policy_sha256, 'rollback_journal_state');
            $this->journalPolicy($policy, $j);
            need($expected === $j->after_sha256 && hash('sha256', $this->files->read($this->configPath)) === $expected, 'rollback_foreign_revision');
            $before = $this->files->read($this->statePath . '/' . $id . '/before.xml', true);
            need(hash('sha256', $before) === $j->before_sha256, 'backup_integrity');
            $this->verifyEvidence($policy, $j, $before);
            $j->status = 'rollback_prepared';
            $this->save($j);
            $this->files->point('rollback_prepared');
            $this->environment->gate($policy);
            $this->files->replace($this->configPath, $before, $expected);
            $this->files->point('rollback_committed');
            $this->invalidate();
            need(hash('sha256', $this->files->read($this->configPath)) === $j->before_sha256, 'post_rollback_foreign_change');
            $j->status = 'rolled_back';
            $j->activation = 'rollback_required';
            $j->runtime = null;
            $this->save($j);
            need(hash('sha256', $this->files->read($this->configPath)) === $j->before_sha256, 'post_journal_foreign_change');
            return $this->result($j, $j->before_sha256, true);
        });
    }

    public function status(string $id, Policy $policy): \stdClass {
        $j = $this->load($id);
        $this->journalPolicy($policy, $j);
        $current = hash('sha256', $this->files->read($this->configPath));
        need(in_array($current, [$j->before_sha256, $j->after_sha256], true), 'status_foreign_revision');
        if (!in_array($j->status, ['prepared', 'rollback_prepared'], true)) {
            need($current === (in_array($j->status, ['rolled_back', 'aborted'], true) ? $j->before_sha256 : $j->after_sha256), 'status_requires_recovery');
        }
        return $this->result($j, $current, false);
    }

    private function activationJournal(Policy $policy, string $id, string $expected, string $approval, bool $rollback): array {
        $this->transactionId = $id;
        $j = $this->load($id);
        $this->journalPolicy($policy, $j);
        need($j->status === ($rollback ? 'rolled_back' : 'committed'), 'activation_journal_state');
        need(hash_equals($j->request_sha256, $approval), 'request_approval_mismatch');
        $raw = $this->files->read($this->configPath);
        need($expected === ($rollback ? $j->before_sha256 : $j->after_sha256) &&
            hash('sha256', $raw) === $expected, 'activation_foreign_revision');
        $before = $this->files->read($this->statePath . '/' . $id . '/before.xml', true);
        need(hash('sha256', $before) === $j->before_sha256, 'backup_integrity');
        $this->verifyEvidence($policy, $j, $before);
        (new NativeXml($raw))->projectedConfig($policy);
        $this->environment->clean();
        return [$j, $raw];
    }

    public function activate(Policy $policy, string $id, string $expected, string $approval, bool $maintenance, bool $rollback = false): \stdClass {
        need($maintenance, 'maintenance_window_required');
        sha($expected);
        sha($approval);
        $this->journalPath($id);
        $this->files->checked($this->statePath, true, true);
        return $this->underLock($policy, function () use ($policy, $id, $expected, $approval, $rollback) {
            [$j, $raw] = $this->activationJournal($policy, $id, $expected, $approval, $rollback);
            // Retry never resets the pre-restart boot identity or preservation contract.
            if ($j->runtime === null) {
                $boot = sha($this->environment->bootIdentity());
                $protected = sha($this->environment->prepareRuntime($raw, $policy));
                need($j->preserved_runtime_sha256 === null || $j->preserved_runtime_sha256 === $protected, 'protected_runtime_changed');
                need($this->environment->bootIdentity() === $boot, 'boot_identity_race');
                need(hash('sha256', $this->files->read($this->configPath)) === $expected, 'activation_foreign_revision');
                $j->runtime = obj([
                    'contract' => RuntimeHealth::CONTRACT, 'target' => $rollback ? 'before' : 'after',
                    'boot_before_sha256' => $boot, 'protected_sha256' => $protected,
                    'prepared_at_unix_secs' => $this->environment->now(), 'proof' => null,
                ]);
                $j->preserved_runtime_sha256 = $protected;
                $j->activation = $rollback ? 'rollback_awaiting_cold_boot' : 'awaiting_cold_boot';
                $this->save($j);
                $this->files->point('activation_prepared');
            }
            need(hash('sha256', $this->files->read($this->configPath)) === $expected, 'activation_foreign_revision');
            return $this->result($j, $expected, false);
        });
    }

    public function verifyActivation(Policy $policy, string $id, string $expected, string $approval, bool $maintenance, bool $rollback = false): \stdClass {
        need($maintenance, 'maintenance_window_required');
        sha($expected);
        sha($approval);
        $this->journalPath($id);
        $this->files->checked($this->statePath, true, true);
        return $this->underLock($policy, function () use ($policy, $id, $expected, $approval, $rollback) {
            [$j, $raw] = $this->activationJournal($policy, $id, $expected, $approval, $rollback);
            need($j->runtime !== null && $j->runtime->target === ($rollback ? 'before' : 'after'), 'activation_not_prepared');
            $j->activation = $rollback ? 'rollback_verifying' : 'activation_verifying';
            $j->runtime->proof = null;
            $this->save($j);
            $this->files->point('activation_verifying');
            try {
                $boot = sha($this->environment->bootIdentity());
                need($boot !== $j->runtime->boot_before_sha256, 'cold_boot_required');
                $evidence = $this->evidence($j);
                $proof = $this->environment->verifyRuntime($raw, $policy, $evidence->baseline->external_dns, $j->runtime->protected_sha256);
                RuntimeHealth::proof($proof);
                need($proof->boot_sha256 === $boot && $proof->config_revision_sha256 === $expected &&
                    $proof->verified_at_unix_secs >= $j->runtime->prepared_at_unix_secs &&
                    $proof->protected_sha256 === $j->runtime->protected_sha256 &&
                    $this->environment->bootIdentity() === $boot, 'runtime_proof_mismatch');
                $this->environment->gate($policy);
                $this->environment->clean();
                need(hash('sha256', $this->files->read($this->configPath)) === $expected, 'activation_foreign_revision');
                $this->files->point('activation_health_verified');
                $j->activation = $rollback ? 'rollback_verified' : 'activated';
                $j->runtime->proof = $proof;
                need(hash('sha256', $this->files->read($this->configPath)) === $expected, 'activation_foreign_revision');
                $this->save($j);
                $this->files->point('activation_recorded');
                need(hash('sha256', $this->files->read($this->configPath)) === $expected, 'activation_foreign_revision');
                return $this->result($j, $expected, false, true);
            } catch (\Throwable $error) {
                $j->activation = $rollback ? 'rollback_failed' : 'activation_failed';
                $j->runtime->proof = null;
                $this->save($j);
                throw $error;
            }
        });
    }
}
