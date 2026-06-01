<?php
declare(strict_types=1);

namespace App\Insight\Action;

final class ExportAction
{
    public static function exportCsv(array $args = []): string
    {
        return 'CSV export staged in report queue.';
    }

    public static function exportJson(array $args = []): string
    {
        return 'JSON export staged in report queue.';
    }

    public static function stageExport(array $args = []): string
    {
        return 'Export package prepared.';
    }

    public static function finalizeExport(array $args = []): string
    {
        return 'Export finalized and pending approval.';
    }

    public static function estimateSize(array $args = []): string
    {
        return 'Estimated export size: 18.2 MB';
    }
}
