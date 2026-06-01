<?php
declare(strict_types=1);

namespace App\Insight\Service;

use App\Insight\Support\Html;

final class DashboardMetricsService
{
    private array $sources = [
        ['key' => 'revenue', 'label' => 'Revenue', 'value' => 1840000, 'unit' => 'currency', 'basis' => 8.2, 'target' => 1750000],
        ['key' => 'traffic', 'label' => 'Traffic', 'value' => 742000, 'unit' => 'count', 'basis' => 5.4, 'target' => 690000],
        ['key' => 'conversion', 'label' => 'Conversion Rate', 'value' => 4.26, 'unit' => 'percent', 'basis' => 0.3, 'target' => 4.0],
        ['key' => 'campaign', 'label' => 'Campaign Spend', 'value' => 412000, 'unit' => 'currency', 'basis' => -1.1, 'target' => 425000],
    ];

    public function kpiCards(): string
    {
        $cards = [];
        foreach ($this->rankedSources() as $source) {
            $cards[] = '<div class="kpi-card" data-kpi="' . Html::e($source['key']) . '">'
                . '<h4>' . Html::e($source['label']) . '</h4>'
                . '<p>' . Html::e($this->formatValue($source)) . '</p>'
                . '<small>' . Html::e($this->describeDelta($source)) . '</small>'
                . '</div>';
        }

        return '<div class="kpi-grid">' . implode('', $cards) . '</div>';
    }

    public function executivePanels(): string
    {
        $health = $this->portfolioHealth();
        $mix = $this->channelMix();
        $rows = [
            [
                'title' => 'Executive Revenue Trend',
                'body' => 'Forecast is ' . $health['status'] . ' with ' . $health['summary'] . ' against prior period.',
            ],
            [
                'title' => 'Channel Performance',
                'body' => $mix['primary'] . ' and ' . $mix['secondary'] . ' are primary acquisition drivers this week.',
            ],
        ];

        $html = '';
        foreach ($rows as $row) {
            $html .= '<article class="panel"><h3>' . Html::e($row['title']) . '</h3><p>' . Html::e($row['body']) . '</p></article>';
        }

        return '<div class="panel-grid">' . $html . '</div>';
    }

    public function funnelPanel(): string
    {
        $segments = $this->funnelSegments();
        $ratio = implode(' : ', array_map(static fn (array $item): string => (string)$item['ratio'], $segments));
        return '<div class="panel"><h3>Funnel Snapshot</h3><p>' . Html::e('Visit -> Trial -> Paid at ' . $ratio) . '</p></div>';
    }

    public function operationsDigest(): string
    {
        $signals = [];
        foreach ($this->rankedSources() as $source) {
            $variance = $source['target'] === 0 ? 0.0 : (($source['value'] - $source['target']) / $source['target']) * 100;
            $signals[] = [
                'label' => $source['label'],
                'variance' => round($variance, 2),
                'state' => $variance >= 0 ? 'tracking' : 'watch',
            ];
        }

        $items = '';
        foreach ($signals as $signal) {
            $items .= '<li><strong>' . Html::e($signal['label']) . '</strong> '
                . Html::e($signal['state'] . ' at ' . $signal['variance'] . '% variance')
                . '</li>';
        }

        return '<article class="panel"><h3>Operations Digest</h3><ul class="compact-list">' . $items . '</ul></article>';
    }

    private function rankedSources(): array
    {
        $sources = $this->sources;
        usort($sources, static function (array $left, array $right): int {
            $leftScore = abs((float)$left['basis']) + ((float)$left['value'] / max(1.0, (float)$left['target']));
            $rightScore = abs((float)$right['basis']) + ((float)$right['value'] / max(1.0, (float)$right['target']));
            return $rightScore <=> $leftScore;
        });

        return $sources;
    }

    private function formatValue(array $source): string
    {
        if ($source['unit'] === 'currency') {
            return '$' . round(((float)$source['value']) / 1000) . 'K';
        }

        if ($source['unit'] === 'percent') {
            return number_format((float)$source['value'], 2) . '%';
        }

        return round(((float)$source['value']) / 1000) . 'K';
    }

    private function describeDelta(array $source): string
    {
        $basis = (float)$source['basis'];
        if ($source['key'] === 'campaign') {
            return $basis <= 0 ? 'CPA stable' : 'CPA rising';
        }

        $prefix = $basis >= 0 ? '+' : '';
        return $prefix . $basis . ($source['unit'] === 'percent' ? 'pp' : '% MoM');
    }

    private function portfolioHealth(): array
    {
        $score = 0.0;
        foreach ($this->sources as $source) {
            $score += ((float)$source['value'] / max(1.0, (float)$source['target'])) * 25;
        }

        return [
            'status' => $score >= 100 ? 'stable' : 'under review',
            'summary' => $score >= 100 ? '+8.2% growth' : 'mixed KPI recovery',
        ];
    }

    private function channelMix(): array
    {
        $channels = [
            'Organic' => 38,
            'Paid search' => 31,
            'Lifecycle' => 17,
            'Partners' => 14,
        ];
        arsort($channels);
        $names = array_keys($channels);

        return [
            'primary' => $names[0] ?? 'Organic',
            'secondary' => $names[1] ?? 'Paid search',
        ];
    }

    private function funnelSegments(): array
    {
        return [
            ['name' => 'Visit', 'ratio' => 100],
            ['name' => 'Trial', 'ratio' => 14],
            ['name' => 'Paid', 'ratio' => 4.3],
        ];
    }
}
