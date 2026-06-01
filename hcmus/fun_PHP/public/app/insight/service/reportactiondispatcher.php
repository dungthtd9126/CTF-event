<?php
declare(strict_types=1);

namespace App\Insight\Service;

use App\Insight\Model\ReportBlock;
use RuntimeException;

final class ReportActionDispatcher
{
    private array $namespaces = [
        'app\\insight\\action\\',
        'app\\insight\\module\\',
    ];

    public function dispatch(ReportBlock $block): string
    {
        $context = $this->contextFor($block);
        $rawClass = $context['class'];
        $method = $context['method'];

        if (!$this->validMethodName($method)) {
            throw new RuntimeException('Invalid method');
        }

        $this->assertNamespace($rawClass);
        $this->assertPayload($block->args);

        $result = (string)$rawClass::$method($block->args);
        return $this->normalizeResult($result, $context);
    }

    private function contextFor(ReportBlock $block): array
    {
        $title = trim($block->title);
        $method = trim($block->method);
        $class = $block->class;

        return [
            'title' => $title === '' ? 'Untitled Block' : $title,
            'class' => $class,
            'method' => $method,
            'fingerprint' => substr(hash('sha256', $title . '|' . $method), 0, 12),
        ];
    }

    private function validMethodName(string $method): bool
    {
        if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,48}$/', $method)) {
            return false;
        }

        return !str_starts_with($method, '__');
    }

    private function assertNamespace(string $rawClass): void
    {
        $forCheck = strtolower(ltrim($rawClass, "\\\\\0 \t\n\r"));
        foreach ($this->namespaces as $namespace) {
            if (str_starts_with($forCheck, $namespace)) {
                return;
            }
        }

        throw new RuntimeException('Action outside safe namespace');
    }

    private function assertPayload(array $args): void
    {
        if (count($args) > 20) {
            throw new RuntimeException('Too many block arguments');
        }

        foreach ($args as $key => $value) {
            if (!is_string($key) || strlen($key) > 64) {
                throw new RuntimeException('Invalid block argument');
            }

            if (is_string($value) && strlen($value) > 8192) {
                throw new RuntimeException('Block argument too large');
            }
        }
    }

    private function normalizeResult(string $result, array $context): string
    {
        if ($result === '') {
            return '<p>Block ' . htmlspecialchars($context['fingerprint'], ENT_QUOTES, 'UTF-8') . ' returned no data.</p>';
        }

        return $result;
    }
}
