<?php

declare(strict_types=1);

namespace Application;

use Domain\Detector;

/**
 * SuspiciousActivityService
 *
 * Implements advanced detection algorithms for suspicious access patterns.
 *
 * Tu implementación debe detectar:
 * 1. IPs con exceso de requests por minuto
 * 2. Patrones de fuerza bruta (múltiples fallos de login)
 * 3. Acceso masivo a endpoints sensibles
 * 4. Comportamiento anómalo por User-Agent
 *
 * Algorithms:
 * - Sliding time windows for request-rate detection
 * - Brute-force detection based on failed login counts per IP
 * - Sensitive endpoint flood detection
 * - Basic statistical anomaly detection (z-score) on response_time per IP
 *
 * Complexity: O(n log n) due to grouping and sorting timestamps per key.
 */
class SuspiciousActivityService
{
    /**
     * Detect suspicious activity in logs.
     *
     * @param array<int, array{ip:string,endpoint:string,timestamp:int|string,status:int,user_agent:string,response_time?:int}> $logs - Array de logs de acceso
     * @param array{max_requests_per_minute:int,max_failed_logins:int,suspicious_endpoints:array<string>,time_window:int,blocked_user_agents:array<string>} $config - Configuración de detección
     * @return array<string,mixed> Reporte de actividad sospechosa
     *
     * Estructura de log:
     * {
     *   ip: "192.168.1.1",
     *   endpoint: "/api/login",
     *   timestamp: 1697123456789,
     *   status: 401,
     *   user_agent: "Mozilla/5.0...",
     *   response_time: 150
     * }
     *
     * Config ejemplo:
     * {
     *   max_requests_per_minute: 60,
     *   max_failed_logins: 5,
     *   suspicious_endpoints: ["/api/login", "/api/admin"],
     *   time_window: 300000 // 5 minutos en ms
     * }
     */
    public function detect(array $logs, array $config): array
    {
        $detector = new Detector();
        $report   = $detector->detect($logs, $config);

        return $report->toArray();
    }
}
