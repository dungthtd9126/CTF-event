<?php
declare(strict_types=1);

namespace App\Insight\Action;

final class AlertAction
{
    public static function recentAlerts(array $args = []): string
    {
        return 'Recent alert digest generated.';
    }

    public static function thresholdStatus(array $args = []): string
    {
        return 'Threshold status dashboard refreshed.';
    }

    public static function mutePreview(array $args = []): string
    {
        return 'Preview alert muted for 24 hours.';
    }

    public static function riskSummary(array $args = []): string
    {
        return 'Risk summary for monitored KPIs prepared.';
    }

    public static function explainAlert(array $args = []): string
    {
        return 'Alert explanation generated for operators.';
    }
}
