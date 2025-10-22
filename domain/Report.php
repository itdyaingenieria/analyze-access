<?php

declare(strict_types=1);

namespace Domain;

/**
 * Value Object representing detection results.
 */
final class Report
{
    public function __construct(
        public readonly array $ips_sospechosas,
        public readonly array $ataques_fuerza_bruta,
        public readonly array $endpoints_bajo_ataque,
        public readonly array $anomalias_detectadas,
        public readonly int $total_eventos_sospechosos
    ) {}

    /**
     * Create Report from array data.
     */
    public static function fromArray(array $data): self
    {
        return new self(
            ips_sospechosas: $data['ips_sospechosas'] ?? [],
            ataques_fuerza_bruta: $data['ataques_fuerza_bruta'] ?? [],
            endpoints_bajo_ataque: $data['endpoints_bajo_ataque'] ?? [],
            anomalias_detectadas: $data['anomalias_detectadas'] ?? [],
            total_eventos_sospechosos: (int)($data['total_eventos_sospechosos'] ?? 0)
        );
    }

    /**
     * Convert to array representation.
     */
    public function toArray(): array
    {
        return [
            'ips_sospechosas' => $this->ips_sospechosas,
            'ataques_fuerza_bruta' => $this->ataques_fuerza_bruta,
            'endpoints_bajo_ataque' => $this->endpoints_bajo_ataque,
            'anomalias_detectadas' => $this->anomalias_detectadas,
            'total_eventos_sospechosos' => $this->total_eventos_sospechosos,
        ];
    }
}
