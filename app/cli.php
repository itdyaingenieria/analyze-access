<?php
require_once __DIR__ . '/../vendor/autoload.php';

use Application\SuspiciousActivityService;
use Infrastructure\Utils\JsonLoader;

$options = getopt('', ['file::', 'config::', 'verbose::']);
$file = $options['file'] ?? __DIR__ . '/../tests/sample_logs.json';
$configFile = $options['config'] ?? __DIR__ . '/../config.json';

$loader = new JsonLoader();
$logs = $loader->load($file);
$config = $loader->load($configFile);

$service = new SuspiciousActivityService();
$reporte = $service->detect($logs, $config);

echo json_encode($reporte, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
