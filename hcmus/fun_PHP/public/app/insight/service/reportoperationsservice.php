<?php
declare(strict_types=1);

namespace App\Insight\Service;

use App\Insight\Model\DashboardPreset;
use App\Insight\Model\ReportBlock;
use App\Insight\Support\Html;

final class ReportOperationsService
{
    private ReportRepository $repository;

    public function __construct(?ReportRepository $repository = null)
    {
        $this->repository = $repository ?? new ReportRepository();
    }

    public function renderLibrary(): string
    {
        $rows = '';
        foreach ($this->enrichedReports() as $report) {
            $rows .= '<tr>'
                . '<td>' . Html::e($report['name']) . '</td>'
                . '<td>' . Html::e($report['owner']) . '</td>'
                . '<td>' . Html::e($report['status']) . '</td>'
                . '<td>' . Html::e($report['priority']) . '</td>'
                . '</tr>';
        }

        return '<div class="panel"><table class="data-table"><thead><tr><th>Name</th><th>Owner</th><th>Status</th><th>Priority</th></tr></thead><tbody>' . $rows . '</tbody></table></div>';
    }

    public function renderTemplateCards(): string
    {
        $cards = '';
        foreach ($this->presetTemplates() as $template) {
            $cards .= '<article class="panel preset-card">'
                . '<h3>' . Html::e($template['title']) . '</h3>'
                . '<p>' . Html::e($template['summary']) . '</p>'
                . '<p class="preset-meta">Owner: ' . Html::e($template['owner']) . '</p>'
                . '<form method="post" action="/reports/import-preset">'
                . '<input type="hidden" name="preset" value="' . Html::e($template['payload']) . '">'
                . '<button class="btn" type="submit">Preview Template</button>'
                . '</form>'
                . '</article>';
        }

        return '<section class="preset-grid">' . $cards . '</section>';
    }

    public function renderArchivePanel(): string
    {
        $queue = $this->archiveQueue();
        $summary = $queue['open'] . ' retained exports, ' . $queue['aging'] . ' pending owner review';

        return '<div class="panel export-archive-panel">'
            . '<h3>Export Archive</h3>'
            . '<p>' . Html::e($summary) . '</p>'
            . '<p><a class="btn btn-ghost" href="/reports/download?file=monthly-overview.txt">View Monthly Overview Export</a></p>'
            . '</div>';
    }

    private function enrichedReports(): array
    {
        $items = [];
        foreach ($this->repository->all() as $report) {
            $score = $this->priorityScore($report);
            $report['priority'] = $score >= 80 ? 'Executive' : ($score >= 50 ? 'Team' : 'Backlog');
            $items[] = $report;
        }

        usort($items, static fn (array $left, array $right): int => strcmp($left['owner'], $right['owner']));
        return $items;
    }

    private function priorityScore(array $report): int
    {
        $score = 20;
        $score += $report['status'] === 'Ready' ? 35 : 10;
        $score += str_contains($report['name'], 'Executive') ? 40 : 15;
        $score += strlen($report['owner']) % 9;
        return min(100, $score);
    }

    private function archiveQueue(): array
    {
        return [
            'open' => count($this->repository->all()) + 7,
            'aging' => 2,
        ];
    }

    private function presetTemplates(): array
    {
        return [
            [
                'title' => 'Revenue Momentum Pack',
                'summary' => 'Preview monthly revenue trend and regional rollup for executive standups.',
                'owner' => 'Finance Ops',
                'payload' => $this->encodePreset(new DashboardPreset('Revenue Momentum Pack', 'grid-2', [
                    new ReportBlock('Revenue Trend', 'App\\Insight\\Action\\ChartAction', 'renderRevenueChart', [
                        'period' => 'last_30_days',
                        'segment' => 'enterprise',
                    ]),
                    new ReportBlock('Regional Revenue', 'App\\Insight\\Action\\RevenueAction', 'revenueByRegion', [
                        'region' => 'all',
                    ]),
                ])),
            ],
            [
                'title' => 'Campaign Health Pack',
                'summary' => 'Inspect channel spend and campaign ROI with a single click preview.',
                'owner' => 'Marketing Analytics',
                'payload' => $this->encodePreset(new DashboardPreset('Campaign Health Pack', 'grid-2', [
                    new ReportBlock('Campaign Spend', 'App\\Insight\\Action\\CampaignAction', 'campaignSpend', [
                        'window' => 'qtd',
                    ]),
                    new ReportBlock('Campaign ROI', 'App\\Insight\\Action\\CampaignAction', 'campaignRoi', [
                        'window' => 'qtd',
                    ]),
                ])),
            ],
            [
                'title' => 'Traffic and Funnel Pulse',
                'summary' => 'View traffic breakdown with conversion-focused funnel narrative blocks.',
                'owner' => 'Growth',
                'payload' => $this->encodePreset(new DashboardPreset('Traffic and Funnel Pulse', 'grid-3', [
                    new ReportBlock('Traffic Overview', 'App\\Insight\\Action\\TrafficAction', 'trafficOverview', [
                        'window' => '7d',
                    ]),
                    new ReportBlock('Source Breakdown', 'App\\Insight\\Action\\TrafficAction', 'sourceBreakdown', [
                        'window' => '7d',
                    ]),
                    new ReportBlock('Segment Snapshot', 'App\\Insight\\Action\\SegmentAction', 'segmentOverview', [
                        'segment' => 'all',
                    ]),
                ])),
            ],
        ];
    }

    private function encodePreset(DashboardPreset $preset): string
    {
        $serialized = serialize($preset);
        return rtrim(strtr(base64_encode($serialized), '+/', '-_'), '=');
    }
}
