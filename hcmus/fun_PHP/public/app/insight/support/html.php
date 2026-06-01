<?php
declare(strict_types=1);

namespace App\Insight\Support;

final class Html
{
    public static function e(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    public static function badge(string $label, string $kind = 'default'): string
    {
        return '<span class="badge badge-' . self::e($kind) . '">' . self::e($label) . '</span>';
    }
}
