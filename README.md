# 🕵️‍♂️ Analyze Access

Sistema de análisis de logs HTTP desarrollado en PHP 8.2 con **Arquitectura Hexagonal** para detectar patrones sospechosos y posibles ataques de fuerza bruta o spam.

---

## 🚀 Características donde se puede- usar

- Detección de **IPs con alta tasa de requests** usando ventanas de tiempo deslizantes (sliding window)
- Detección de **ataques de fuerza bruta** basados en intentos fallidos de login (status 401)
- Detección de **accesos masivos a endpoints sensibles**
- Análisis estadístico de anomalías en **response_time** usando z-score (outliers > 3σ)
- Detección de **User-Agents bloqueados** y heurísticas para UAs sospechosos
- Soporte de **múltiples formatos de timestamp** (ISO8601, Unix seconds, Unix milliseconds)
- Arquitectura **Hexagonal (Ports & Adapters)** con separación Domain/Application/Infrastructure
- Tests automáticos con **PHPUnit** (5 tests unitarios)

**Complejidad temporal:** O(n log n) por agrupación y ordenación de timestamps

---

## ⚙️ Instalación

### Requisitos

- PHP >= 8.2
- Composer

### Pasos

```powershell
# Clonar el repositorio
git clone https://github.com/itdyaingenieria/analyze-access.git
cd analyze-access

# Instalar dependencias
composer install

# Generar autoload optimizado
composer dump-autoload -o
```

---

## 🧪 Ejecución de tests

```powershell
# Ejecutar todos los tests con PHPUnit
composer test

# Alternativamente
vendor/bin/phpunit --testdox
```

**Salida esperada:**

```
Suspicious Activity Service
 ✔ Detects blocked user agents
 ✔ Detects brute force by failed logins
 ✔ Detects endpoint flood
 ✔ Detects response time anomaly
 ✔ Handles mixed timestamp formats

Tests: 5, Assertions: 12
```

---

## 💻 Uso

### 1. Smoke Test (Runner rápido)

```powershell
php tests/run_detection.php
```

Carga `tests/sample_logs.json` y `config.json`, ejecuta el servicio y muestra el reporte en JSON.

### 2. Ejemplo mínimo (`app/main.php`)

```powershell
php app/main.php
```

Imprime el resultado con `print_r` (útil para debugging).

### 3. CLI con opciones (`app/cli.php`)

```powershell
php app/cli.php --file=tests/sample_logs.json --config=config.json
```

**Opciones disponibles:**

- `--file=<path>` — Ruta al archivo JSON de logs (default: `tests/sample_logs.json`)
- `--config=<path>` — Ruta al archivo de configuración (default: `config.json`)
- `--verbose` — (reservado para salida adicional)

**Salida:** JSON formateado con el reporte.

---

## 📊 Ejemplo de salida

```json
{
  "ips_sospechosas": ["192.168.1.1"],
  "ataques_fuerza_bruta": {
    "192.168.1.1": 6
  },
  "endpoints_bajo_ataque": {
    "/api/login": 120
  },
  "anomalias_detectadas": {
    "ua_blocked:curl/7.88": {
      "reason": "blocked_signature",
      "count": 2
    },
    "response_time:5.5.5.5": {
      "reason": "high_response_time",
      "value": 10000,
      "mean": 105.5,
      "std": 152.3
    }
  },
  "total_eventos_sospechosos": 4
}
```

---

## 🏗 Arquitectura Hexagonal

```
analyze-access/
├── domain/                          # Lógica de negocio pura (sin dependencias)
│   ├── DetectorInterface.php        # Contrato del detector
│   ├── Detector.php                 # Implementación del algoritmo de detección
│   ├── Report.php                   # Value Object del reporte
│   └── LogLoaderInterface.php       # Puerto para carga de logs
├── application/                     # Casos de uso y orquestación
│   └── SuspiciousActivityService.php # Adaptador que delega a Domain
├── infrastructure/                  # Adaptadores e implementaciones concretas
│   └── Utils/
│       └── JsonLoader.php           # Implementa LogLoaderInterface
├── app/                             # Puntos de entrada
│   ├── cli.php                      # CLI con opciones
│   └── main.php                     # Ejemplo mínimo
└── tests/                           # Tests unitarios
    ├── SuspiciousActivityServiceTest.php
    ├── run_detection.php
    └── sample_logs.json
```

### Capas

- **Domain** → Interfaces y entidades puras (Detector, Report, LogLoaderInterface)
- **Application** → Casos de uso (SuspiciousActivityService delega a Domain\Detector)
- **Infrastructure** → Implementaciones concretas (JsonLoader)
- **App** → Puntos de entrada (CLI, ejemplos)

---

## 🧩 Algoritmo de detección

El servicio implementa múltiples patrones de detección simultáneos:

### 1. High Request Rate (Sliding Window)

Detecta IPs que exceden `max_requests_per_minute` en una ventana deslizante de `time_window` ms.

**Algoritmo:** Two-pointer sliding window sobre timestamps ordenados → O(n log n)

### 2. Brute Force Detection

Cuenta intentos fallidos de login (status 401) por IP en la ventana temporal.

**Threshold:** `max_failed_logins` (default: 5)

### 3. Endpoint Flood

Detecta acceso masivo a `suspicious_endpoints` (ej: `/api/login`, `/admin`).

### 4. User-Agent Anomalies

- Bloqueo por firma conocida (`blocked_user_agents` en config)
- Heurística para UAs cortos (< 10 caracteres)

### 5. Response Time Anomaly (Z-Score)

Calcula z-score por IP: z = (value - mean) / std

Marca como anómalo si z > 3.0 (outlier significativo).

---

## 📄 Configuración (`config.json`)

```json
{
  "max_requests_per_minute": 60,
  "max_failed_logins": 5,
  "time_window": 300000,
  "suspicious_endpoints": ["/api/login", "/admin", "/auth/reset"],
  "blocked_user_agents": ["sqlmap", "nmap", "curl"]
}
```

**Parámetros:**

- `max_requests_per_minute` — Umbral de requests por minuto
- `max_failed_logins` — Máximo de 401s antes de marcar como brute-force
- `time_window` — Ventana temporal en ms (default: 300000 = 5 min)
- `suspicious_endpoints` — Lista de endpoints a monitorear
- `blocked_user_agents` — Lista de UAs a bloquear (case-insensitive)

---

## 📝 Estructura de logs

Los logs deben ser un array JSON con el siguiente esquema:

```json
{
  "ip": "192.168.1.1",
  "endpoint": "/api/login",
  "timestamp": 1697123530000,
  "status": 401,
  "user_agent": "curl/7.88",
  "response_time": 150
}
```

---

## 🧪 Tests incluidos

| Test                                  | Descripción                                            |
| ------------------------------------- | ------------------------------------------------------ |
| `testDetectsBlockedUserAgents`        | Verifica detección de UAs bloqueados                   |
| `testDetectsBruteForceByFailedLogins` | Verifica detección de 6 intentos 401 en ventana        |
| `testDetectsEndpointFlood`            | Verifica detección de 100 requests a endpoint sensible |
| `testDetectsResponseTimeAnomaly`      | Verifica z-score > 3.0 para response_time outlier      |
| `testHandlesMixedTimestampFormats`    | Verifica parseo de ISO8601, Unix sec y ms              |

---

## 📜 Licencia

MIT © 2025 Ing. Diego Yama Andrade
