<?php
require_once __DIR__ . '/../vendor/autoload.php';

use Application\SuspiciousActivityService;
use Infrastructure\Utils\JsonLoader;

$logsPath = __DIR__ . '/sample_logs.json';
$configPath = __DIR__ . '/../config.json';

try {
    $loader = new JsonLoader();
    $logs = $loader->load($logsPath);
    $config = $loader->load($configPath);

    $service = new SuspiciousActivityService();
    $report = $service->detect($logs, $config);

    echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} catch (Throwable $e) {
    fwrite(STDERR, "Error: " . $e->getMessage() . PHP_EOL);
    exit(1);
}
