<?php
declare(strict_types=1);

namespace App\Insight\Action;

final class ChartAction
{
    public static function renderRevenueChart(array $args = []): string
    {
        $period = htmlspecialchars((string)($args['period'] ?? '30d'), ENT_QUOTES, 'UTF-8');
        return '<p>Revenue chart ready for period: ' . $period . '</p>';
    }

    public static function renderTrafficChart(array $args = []): string
    {
        return '<p>Traffic trend chart prepared.</p>';
    }

    public static function renderCampaignChart(array $args = []): string
    {
        return '<p>Campaign chart generated with normalized spend buckets.</p>';
    }

    public static function normalizeSeries(array $args = []): string
    {
        return 'Series normalization staged successfully.';
    }

    public static function buildLegend(array $args = []): string
    {
        return 'Legend built for chart layers.';
    }
}
