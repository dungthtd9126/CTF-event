<?php
declare(strict_types=1);

namespace App\Insight\Widget;

final class ConversionWidget
{
    public static function render(): string
    {
        return '<div class="kpi-card"><h4>Conversion Rate</h4><p>4.26%</p><small>+0.3pp</small></div>';
    }
}
