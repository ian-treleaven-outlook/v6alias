#!/usr/local/bin/php -f
<?php
declare(strict_types=1);

namespace V6Alias;

require_once __DIR__ . '/platform.php';

ini_set('display_errors', '0');
ini_set('log_errors', '0');
umask(0077);
set_error_handler(static function (int $severity): bool {
    if (!(error_reporting() & $severity)) {
        return false;
    }
    throw new Refusal('local_io_failure');
});

$transactions = null;
$operation = '';
try {
    $args = $argv;
    array_shift($args);
    $operation = array_shift($args) ?? '';
    $schemas = [
        'capture' => ['policy'],
        'initialize-lock' => ['policy', 'maintenance-window'],
        'persist' => ['policy', 'baseline', 'request', 'approve-request-sha256', 'maintenance-window'],
        'rollback' => ['policy', 'transaction', 'expected-current-revision', 'maintenance-window'],
        'recover' => ['policy', 'transaction', 'maintenance-window'],
        'status' => ['policy', 'transaction'],
        'activate' => ['policy', 'transaction', 'expected-current-revision', 'approve-request-sha256', 'maintenance-window'],
        'activate-rollback' => ['policy', 'transaction', 'expected-current-revision', 'approve-request-sha256', 'maintenance-window'],
        'verify-activation' => ['policy', 'transaction', 'expected-current-revision', 'approve-request-sha256', 'maintenance-window'],
        'verify-rollback' => ['policy', 'transaction', 'expected-current-revision', 'approve-request-sha256', 'maintenance-window'],
    ];
    if ($operation === '--help' && !$args) {
        fwrite(STDOUT, "Root-local pfSense 2.8.1 helper; activation uses an explicitly approved EXTERNAL cold restart.\n" .
            "capture --policy FILE\n" .
            "initialize-lock --policy FILE --maintenance-window\n" .
            "persist --policy FILE --baseline FILE --request FILE --approve-request-sha256 HEX --maintenance-window\n" .
            "rollback --policy FILE --transaction ID --expected-current-revision HEX --maintenance-window\n" .
            "recover --policy FILE --transaction ID --maintenance-window\n" .
            "status --policy FILE --transaction ID\n" .
            "activate --policy FILE --transaction ID --expected-current-revision HEX --approve-request-sha256 HEX --maintenance-window\n" .
            "activate-rollback / verify-activation / verify-rollback use the same arguments as activate.\n" .
            "activate prepares durable acceptance only; verify requires changed kern.boot_id and real local DHCP/served-DNS health.\n" .
            "No command reboots, reloads, starts or stops services. Rollback restores XML only; prepare/restart/verify rollback separately.\n" .
            "Approval is an independently supplied SHA256 of canonical reviewed request JSON, NOT a raw file checksum.\n");
        exit(0);
    }
    need(isset($schemas[$operation]), 'unsupported_command');
    $options = [];
    while ($args) {
        $arg = array_shift($args);
        need(str_starts_with($arg, '--'), 'invalid_arguments');
        $key = substr($arg, 2);
        need(in_array($key, $schemas[$operation], true) && !isset($options[$key]), 'invalid_arguments');
        if ($key === 'maintenance-window') {
            $options[$key] = true;
        } else {
            $value = array_shift($args);
            need(is_string($value) && $value !== '' && !str_starts_with($value, '--'), 'invalid_arguments');
            $options[$key] = $value;
        }
    }
    need(count($options) === count($schemas[$operation]), 'missing_arguments');
    $files = new Files();
    $environment = new LiveEnvironment($files);
    $policy = new Policy(Json::decode($files->read($options['policy'], true)));
    $directory = LiveEnvironment::configDirectory($files);
    $config = $directory . '/config.xml';
    $transactions = new Transactions($files, $environment, $config, $directory . '/v6alias', '/tmp/config.lock', ['/tmp/config.cache']);
    $output = match ($operation) {
        'capture' => (new Collector($files, $environment, $config))->capture($policy),
        'initialize-lock' => $transactions->initializeLock($policy, $options['maintenance-window']),
        'persist' => (function () use ($files, $transactions, $policy, $options) {
            $raw = $files->read($options['request'], true);
            return $transactions->persist(
                $policy, Json::decode($files->read($options['baseline'], true)), Json::decode($raw),
                $options['approve-request-sha256'], hash('sha256', $raw), $options['maintenance-window'],
            );
        })(),
        'rollback' => $transactions->rollback($policy, $options['transaction'], $options['expected-current-revision'], $options['maintenance-window']),
        'recover' => $transactions->recover($policy, $options['transaction'], $options['maintenance-window']),
        'status' => (function () use ($environment, $policy, $transactions, $options) {
            $environment->gate($policy);
            return $transactions->status($options['transaction'], $policy);
        })(),
        'activate' => $transactions->activate($policy, $options['transaction'], $options['expected-current-revision'], $options['approve-request-sha256'], $options['maintenance-window']),
        'activate-rollback' => $transactions->activate($policy, $options['transaction'], $options['expected-current-revision'], $options['approve-request-sha256'], $options['maintenance-window'], true),
        'verify-activation' => $transactions->verifyActivation($policy, $options['transaction'], $options['expected-current-revision'], $options['approve-request-sha256'], $options['maintenance-window']),
        'verify-rollback' => $transactions->verifyActivation($policy, $options['transaction'], $options['expected-current-revision'], $options['approve-request-sha256'], $options['maintenance-window'], true),
    };
    $bytes = Json::canonical($output) . "\n";
    need(fwrite(STDOUT, $bytes) === strlen($bytes), 'output_failure');
} catch (\Throwable $error) {
    $code = $error instanceof Refusal ? $error->getMessage() : 'invalid_input_or_local_failure';
    $message = [
        'schema_version' => 1, 'event' => 'refused', 'error' => $code,
        'activation' => 'unknown_inspect_durable_status',
        'runtime_health_verified' => false,
        'lock_initialization_may_have_occurred' => $operation === 'initialize-lock',
        'persistence_may_have_occurred' => in_array($operation, ['persist', 'rollback', 'recover'], true),
        'activation_journal_may_have_changed' => in_array($operation, ['activate', 'activate-rollback', 'verify-activation', 'verify-rollback'], true),
        'transaction_id' => $transactions?->transactionId,
        'recovery' => $operation === 'initialize-lock'
            ? 'inspect_stock_lock_then_explicit_initialize_lock_retry_never_unlink'
            : 'inspect_status_then_explicit_recover_never_overwrite_foreign_revision',
    ];
    // No exception details, raw XML, subprocess stderr, input paths, or credentials.
    @fwrite(STDERR, json_encode($message, JSON_UNESCAPED_SLASHES) . "\n");
    exit(1);
}
