<?php

declare(strict_types=1);

namespace Domain;

final class Detector implements DetectorInterface
{
    /**
     * Detect suspicious activity in logs.
     *
     * Tu implementación debe detectar:
     * 1. IPs con exceso de requests por minuto
     * 2. Patrones de fuerza bruta (múltiples fallos de login)
     * 3. Acceso masivo a endpoints sensibles
     * 4. Comportamiento anómalo por User-Agent
     *
     * @param array<int, array{ip:string,endpoint:string,timestamp:int|string,status:int,user_agent:string,response_time?:int}> $logs - Array de logs de acceso
     * @param array{max_requests_per_minute:int,max_failed_logins:int,suspicious_endpoints:array<string>,time_window:int,blocked_user_agents:array<string>} $config - Configuración de detección
     * @return Report Reporte de actividad sospechosa
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
    public function detect(array $logs, array $config): Report
    {
        $maxRequestsPerMinute = (int)($config['max_requests_per_minute'] ?? 60);
        $maxFailedLogins      = (int)($config['max_failed_logins'] ?? 5);
        $sensitiveEndpoints   = $config['suspicious_endpoints'] ?? [];
        $timeWindow           = (int)($config['time_window'] ?? 300000);

        $byIpTimestamps    = [];
        $failedLoginsByIp  = [];
        $endpointHits      = [];
        $uaCounts          = [];
        $responseTimesByIp = [];

        foreach ($logs as $entry) {
            $ip = $entry['ip'] ?? 'unknown';
            $endpoint = $entry['endpoint'] ?? '/';
            $status = (int)($entry['status'] ?? 0);
            $ua = strtolower((string)($entry['user_agent'] ?? ''));
            $ts = $this->normalizeTimestamp($entry['timestamp'] ?? null);

            $byIpTimestamps[$ip][] = $ts;
            if ($status === 401) {
                $failedLoginsByIp[$ip][] = $ts;
            }
            if (in_array($endpoint, $sensitiveEndpoints, true)) {
                $endpointHits[$endpoint][] = $ts;
            }
            $uaCounts[$ua] = ($uaCounts[$ua] ?? 0) + 1;
            if (isset($entry['response_time'])) {
                $responseTimesByIp[$ip][] = (int)$entry['response_time'];
            }
        }

        $windowMs = max(1, $timeWindow);
        $maxPerWindow = max(1, (int)($maxRequestsPerMinute * ($windowMs / 60000)));

        $ipsSospechosas = $this->detectHighRateIps($byIpTimestamps, $windowMs, $maxPerWindow);
        $ataquesFuerzaBruta = $this->detectBruteForceIps($failedLoginsByIp, $windowMs, $maxFailedLogins);

        foreach (array_keys($ataquesFuerzaBruta) as $ip) {
            if (!in_array($ip, $ipsSospechosas, true)) {
                $ipsSospechosas[] = $ip;
            }
        }

        $endpointsBajoAtaque = $this->detectEndpointFloods($endpointHits, $windowMs, $maxRequestsPerMinute);

        $blockedUas = array_map('strtolower', $config['blocked_user_agents'] ?? []);
        $anomalias = array_merge(
            $this->detectUaAnomalies($uaCounts, $blockedUas),
            $this->detectResponseTimeAnomalies($responseTimesByIp)
        );

        $totalEventos = count($ipsSospechosas)
            + count($ataquesFuerzaBruta)
            + count($endpointsBajoAtaque)
            + count($anomalias);

        return new Report(
            ips_sospechosas: array_values($ipsSospechosas),
            ataques_fuerza_bruta: $ataquesFuerzaBruta,
            endpoints_bajo_ataque: $endpointsBajoAtaque,
            anomalias_detectadas: $anomalias,
            total_eventos_sospechosos: $totalEventos
        );
    }

    private function detectHighRateIps(array $byIpTimestamps, int $windowMs, int $maxPerWindow): array
    {
        $result = [];
        foreach ($byIpTimestamps as $ip => $timestamps) {
            sort($timestamps);
            if ($this->hasHighRate($timestamps, $windowMs, $maxPerWindow)) {
                $result[] = $ip;
            }
        }
        return $result;
    }

    private function detectBruteForceIps(array $failedLoginsByIp, int $windowMs, int $maxFailedLogins): array
    {
        $result = [];
        foreach ($failedLoginsByIp as $ip => $timestamps) {
            sort($timestamps);
            $count = $this->countWithinWindow($timestamps, $windowMs);
            if ($count >= $maxFailedLogins) {
                $result[$ip] = $count;
            }
        }
        return $result;
    }

    private function detectEndpointFloods(array $endpointHits, int $windowMs, int $threshold): array
    {
        $result = [];
        foreach ($endpointHits as $endpoint => $timestamps) {
            sort($timestamps);
            if ($this->hasHighRate($timestamps, $windowMs, $threshold)) {
                $result[$endpoint] = count($timestamps);
            }
        }
        return $result;
    }

    /**
     * Detect User-Agent anomalies.
     */
    private function detectUaAnomalies(array $uaCounts, array $blockedUas): array
    {
        $anomalies = [];
        foreach ($uaCounts as $ua => $count) {
            foreach ($blockedUas as $blocked) {
                if ($blocked !== '' && str_contains($ua, $blocked)) {
                    $anomalies['ua_blocked:' . $ua] = ['reason' => 'blocked_signature', 'count' => $count];
                    break;
                }
            }
            if (strlen($ua) > 0 && strlen($ua) < 10) {
                $anomalies['ua_short:' . $ua] = ['reason' => 'short_user_agent', 'count' => $count];
            }
        }
        return $anomalies;
    }

    /**
     * Detect response time anomalies using z-score (threshold > 3.0).
     */
    private function detectResponseTimeAnomalies(array $responseTimesByIp): array
    {
        $anomalies = [];
        foreach ($responseTimesByIp as $ip => $times) {
            if (count($times) < 3) {
                continue;
            }

            $mean = array_sum($times) / count($times);
            $variance = array_sum(array_map(fn($t) => ($t - $mean) ** 2, $times)) / count($times);
            $std = sqrt($variance);

            if ($std === 0.0) {
                continue;
            }

            foreach ($times as $t) {
                if ((($t - $mean) / $std) > 3.0) {
                    $anomalies['response_time:' . $ip] = [
                        'reason' => 'high_response_time',
                        'value' => $t,
                        'mean' => $mean,
                        'std' => $std
                    ];
                    break;
                }
            }
        }
        return $anomalies;
    }


    /**
     * Normalize timestamp to milliseconds since epoch.
     * Supports: Unix ms, Unix sec, ISO8601 strings.
     */
    private function normalizeTimestamp(mixed $input): int
    {
        if (is_numeric($input)) {
            $n = (int)$input;
            return $n >= 1_000_000_000_000 ? $n : $n * 1000;
        }

        if (is_string($input) && ($ts = strtotime($input)) !== false) {
            return $ts * 1000;
        }

        return (int)round(microtime(true) * 1000);
    }

    /**
     * Check if timestamps exceed threshold using sliding window algorithm.
     */
    private function hasHighRate(array $timestamps, int $windowMs, int $threshold): bool
    {
        $j = 0;
        for ($i = 0, $n = count($timestamps); $i < $n; $i++) {
            while ($timestamps[$i] - $timestamps[$j] > $windowMs) {
                $j++;
            }
            if (($i - $j + 1) > $threshold) {
                return true;
            }
        }
        return false;
    }

    /**
     * Count maximum timestamps within sliding window.
     */
    private function countWithinWindow(array $timestamps, int $windowMs): int
    {
        $max = 0;
        $j = 0;
        for ($i = 0, $n = count($timestamps); $i < $n; $i++) {
            while ($timestamps[$i] - $timestamps[$j] > $windowMs) {
                $j++;
            }
            $max = max($max, $i - $j + 1);
        }
        return $max;
    }
}
