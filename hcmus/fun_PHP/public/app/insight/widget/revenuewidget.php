<?php
declare(strict_types=1);

namespace App\Insight\Widget;

final class RevenueWidget
{
    public static function render(): string
    {
        return '<div class="kpi-card"><h4>Revenue</h4><p>$1.84M</p><small>+8.2% MoM</small></div>';
    }
}
