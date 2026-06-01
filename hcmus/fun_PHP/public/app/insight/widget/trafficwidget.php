<?php
declare(strict_types=1);

namespace App\Insight\Widget;

final class TrafficWidget
{
    public static function render(): string
    {
        return '<div class="kpi-card"><h4>Traffic</h4><p>742K</p><small>+5.4% WoW</small></div>';
    }
}
