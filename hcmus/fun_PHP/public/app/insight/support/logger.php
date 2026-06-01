<?php
declare(strict_types=1);

namespace App\Insight\Support;

final class Logger
{
    public static function info(string $message): void
    {
        error_log(sprintf('[InsightBoard][INFO] %s', $message));
    }

    public static function warn(string $message): void
    {
        error_log(sprintf('[InsightBoard][WARN] %s', $message));
    }
}
