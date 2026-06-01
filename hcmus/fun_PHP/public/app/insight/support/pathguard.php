<?php
declare(strict_types=1);

namespace App\Insight\Support;

final class PathGuard
{
    public static function inStorage(string $path): bool
    {
        $normalized = str_replace('\\', '/', $path);
        return str_starts_with($normalized, '/var/www/storage/');
    }

    public static function rejectPhpExtension(string $path): bool
    {
        return !str_ends_with(strtolower($path), '.php');
    }

    public static function inDocumentRoot(string $path): bool
    {
        $normalized = str_replace('\\', '/', $path);
        return str_starts_with($normalized, '/var/www/html/');
    }
}
