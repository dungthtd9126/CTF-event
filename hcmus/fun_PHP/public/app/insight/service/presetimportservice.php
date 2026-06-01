<?php
declare(strict_types=1);

namespace App\Insight\Service;

use App\Insight\Model\DashboardPreset;
use RuntimeException;

final class PresetImportService
{
    public function importFromRequest(array $post): DashboardPreset
    {
        $preset = $this->extractPreset($post);
        if ($preset === '') {
            throw new RuntimeException('Missing preset');
        }

        $raw = $this->decodeBase64Url($preset);
        $this->validateEnvelope($raw);
        $unserialized = @unserialize($raw);

        if (!$unserialized instanceof DashboardPreset) {
            throw new RuntimeException('Preset is not a dashboard preset');
        }

        $this->validatePreset($unserialized);
        return $unserialized;
    }

    private function extractPreset(array $post): string
    {
        $candidate = $post['preset'] ?? '';
        if (is_array($candidate)) {
            return '';
        }

        return trim((string)$candidate);
    }

    private function decodeBase64Url(string $payload): string
    {
        if (strlen($payload) > 65536) {
            throw new RuntimeException('Preset is too large');
        }

        $payload = str_replace(['-', '_'], ['+', '/'], $payload);
        $padding = strlen($payload) % 4;
        if ($padding > 0) {
            $payload .= str_repeat('=', 4 - $padding);
        }

        $decoded = base64_decode($payload, true);
        if ($decoded === false) {
            throw new RuntimeException('Invalid base64url');
        }

        return $decoded;
    }

    private function validateEnvelope(string $raw): void
    {
        if ($raw === '' || strlen($raw) > 49152) {
            throw new RuntimeException('Invalid preset envelope');
        }

        if (!str_contains($raw, 'DashboardPreset')) {
            throw new RuntimeException('Preset envelope is not supported');
        }
    }

    private function validatePreset(DashboardPreset $preset): void
    {
        if (trim($preset->name) === '') {
            throw new RuntimeException('Preset name is empty');
        }

        if (count($preset->getBlocks()) > 12) {
            throw new RuntimeException('Preset has too many blocks');
        }
    }
}
