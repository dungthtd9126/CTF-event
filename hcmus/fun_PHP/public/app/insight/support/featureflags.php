<?php
declare(strict_types=1);

namespace App\Insight\Support;

final class FeatureFlags
{
    private static array $flags = [
        'board_pack_builder' => false,
        'forecasting_suite' => false,
        'cohort_explorer' => false,
        'executive_briefing' => false,
        'margin_analyzer' => false,
        'retention_studio' => false,
        'attribution_lab' => false,
        'data_quality_panel' => false,
        'partner_report_hub' => false,
        'revenue_workbench' => false,
        'campaign_optimizer' => false,
        'audit_timeline' => false,
        'board_metric_pack' => false,
        'enterprise_snapshots' => false,
    ];

    public static function enabled(string $flag): bool
    {
        return self::$flags[$flag] ?? false;
    }
}
