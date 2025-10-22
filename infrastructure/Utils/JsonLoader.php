<?php

declare(strict_types=1);

namespace Infrastructure\Utils;

use Domain\LogLoaderInterface;
use RuntimeException;

final class JsonLoader implements LogLoaderInterface
{
    public function load(string $path): array
    {
        if (!file_exists($path)) {
            throw new RuntimeException("File not found: $path");
        }

        $content = file_get_contents($path);
        if ($content === false) {
            throw new RuntimeException("Unable to read file: $path");
        }

        $data = json_decode($content, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new RuntimeException("Invalid JSON in file: $path - " . json_last_error_msg());
        }

        return $data ?? [];
    }
}
