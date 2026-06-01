<?php
declare(strict_types=1);

namespace App\Insight\Action;

final class CampaignAction
{
    public static function campaignOverview(array $args = []): string
    {
        return '<p>Campaign overview generated for active channels.</p>';
    }

    public static function campaignSpend(array $args = []): string
    {
        return '<p>Spend profile computed for paid campaigns.</p>';
    }

    public static function campaignRoi(array $args = []): string
    {
        return '<p>ROI projection prepared for top 5 campaigns.</p>';
    }

    public static function compareCampaigns(array $args = []): string
    {
        return 'Campaign comparison matrix rendered.';
    }

    public static function forecastCampaign(array $args = []): string
    {
        return 'Campaign forecast generated using historical signals.';
    }
}
