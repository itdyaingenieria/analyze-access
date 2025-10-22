<?php
require_once __DIR__ . '/../vendor/autoload.php';

use Application\SuspiciousActivityService;
use Infrastructure\Utils\JsonLoader;

$loader = new JsonLoader();
$logs   = $loader->load(__DIR__ . '/../tests/sample_logs.json');
$config = $loader->load(__DIR__ . '/../config.json');

$service = new SuspiciousActivityService();
$resultado = $service->detect($logs, $config);

print_r($resultado);
