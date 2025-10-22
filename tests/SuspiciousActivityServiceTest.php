<?php

use PHPUnit\Framework\TestCase;
use Application\SuspiciousActivityService;

class SuspiciousActivityServiceTest extends TestCase
{
    public function testDetectsBlockedUserAgents()
    {
        $logs = [
            ['ip' => '1.1.1.1', 'endpoint' => '/api/login', 'status' => 401, 'timestamp' => '2025-10-22T10:00:00Z', 'user_agent' => 'curl/7.88'],
            ['ip' => '1.1.1.1', 'endpoint' => '/api/login', 'status' => 401, 'timestamp' => '2025-10-22T10:01:00Z', 'user_agent' => 'curl/7.88'],
            ['ip' => '2.2.2.2', 'endpoint' => '/home', 'status' => 200, 'timestamp' => '2025-10-22T10:02:00Z', 'user_agent' => 'Mozilla/5.0']
        ];

        $config = [
            'blocked_user_agents' => ['curl'],
            'suspicious_endpoints' => ['/api/login'],
            'max_failed_logins' => 5,
            'time_window' => 300000
        ];

        $service = new SuspiciousActivityService();
        $report = $service->detect($logs, $config);

        $this->assertArrayHasKey('anomalias_detectadas', $report);
        $this->assertStringContainsString('curl', implode(',', array_keys($report['anomalias_detectadas'])));
    }

    public function testDetectsBruteForceByFailedLogins()
    {
        $logs = [];
        $base = strtotime('2025-10-22T10:00:00Z') * 1000;

        for ($i = 0; $i < 6; $i++) {
            $logs[] = [
                'ip' => '9.9.9.9',
                'endpoint' => '/api/login',
                'status' => 401,
                'timestamp' => $base + ($i * 30_000),
                'user_agent' => 'bot/1.0'
            ];
        }

        $config = [
            'max_failed_logins' => 5,
            'time_window' => 300000,
            'suspicious_endpoints' => ['/api/login']
        ];

        $service = new SuspiciousActivityService();
        $report = $service->detect($logs, $config);

        $this->assertArrayHasKey('ataques_fuerza_bruta', $report);
        $this->assertArrayHasKey('9.9.9.9', $report['ataques_fuerza_bruta']);
        $this->assertGreaterThanOrEqual(5, $report['ataques_fuerza_bruta']['9.9.9.9']);
    }

    public function testDetectsEndpointFlood()
    {
        $logs = [];
        $base = strtotime('2025-10-22T10:00:00Z') * 1000;

        for ($i = 0; $i < 100; $i++) {
            $logs[] = [
                'ip' => '3.3.3.' . ($i % 10),
                'endpoint' => '/api/login',
                'status' => 200,
                'timestamp' => $base + ($i * 500),
                'user_agent' => 'bot'
            ];
        }

        $config = [
            'max_requests_per_minute' => 60,
            'time_window' => 60000,
            'suspicious_endpoints' => ['/api/login']
        ];

        $service = new SuspiciousActivityService();
        $report = $service->detect($logs, $config);

        $this->assertArrayHasKey('endpoints_bajo_ataque', $report);
        $this->assertArrayHasKey('/api/login', $report['endpoints_bajo_ataque']);
    }

    public function testDetectsResponseTimeAnomaly()
    {
        $logs = [];
        for ($i = 0; $i < 10; $i++) {
            $logs[] = [
                'ip' => '5.5.5.5',
                'endpoint' => '/api/data',
                'status' => 200,
                'timestamp' => '2025-10-22T10:' . str_pad((string)$i, 2, '0', STR_PAD_LEFT) . ':00Z',
                'user_agent' => 'Mozilla/5.0',
                'response_time' => 100
            ];
        }

        // Extreme outlier: z-score > 3.0
        $logs[] = [
            'ip' => '5.5.5.5',
            'endpoint' => '/api/data',
            'status' => 200,
            'timestamp' => '2025-10-22T10:10:00Z',
            'user_agent' => 'Mozilla/5.0',
            'response_time' => 100000
        ];

        $config = ['time_window' => 600000];

        $service = new SuspiciousActivityService();
        $report = $service->detect($logs, $config);

        $this->assertArrayHasKey('anomalias_detectadas', $report);
        $this->assertArrayHasKey('response_time:5.5.5.5', $report['anomalias_detectadas']);
    }

    public function testHandlesMixedTimestampFormats()
    {
        $logs = [
            ['ip' => '6.6.6.6', 'endpoint' => '/api/test', 'status' => 200, 'timestamp' => '2025-10-22T10:00:00Z', 'user_agent' => 'test'],
            ['ip' => '6.6.6.6', 'endpoint' => '/api/test', 'status' => 200, 'timestamp' => 1729594800, 'user_agent' => 'test'],
            ['ip' => '6.6.6.6', 'endpoint' => '/api/test', 'status' => 200, 'timestamp' => 1729594800000, 'user_agent' => 'test'],
        ];

        $config = ['time_window' => 300000];

        $service = new SuspiciousActivityService();
        $report = $service->detect($logs, $config);

        $this->assertIsArray($report);
        $this->assertArrayHasKey('total_eventos_sospechosos', $report);
    }
}
