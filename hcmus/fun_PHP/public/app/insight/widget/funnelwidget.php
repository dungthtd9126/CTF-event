<?php
declare(strict_types=1);

namespace App\Insight\Widget;

final class FunnelWidget
{
    public static function render(): string
    {
        return '<div class="panel"><h3>Funnel Snapshot</h3><p>Visit -> Trial -> Paid at 100 : 14 : 4.3</p></div>';
    }
}
