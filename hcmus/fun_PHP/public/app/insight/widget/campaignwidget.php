<?php
declare(strict_types=1);

namespace App\Insight\Widget;

final class CampaignWidget
{
    public static function render(): string
    {
        return '<div class="kpi-card"><h4>Campaign Spend</h4><p>$412K</p><small>CPA stable</small></div>';
    }
}
