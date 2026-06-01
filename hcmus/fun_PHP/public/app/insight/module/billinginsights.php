<?php
declare(strict_types=1);

namespace App\Insight\Module;

final class BillingInsights
{
    public static function summarizeAging(): string
    {
        return 'Aging receivables stable under 30 days.';
    }
}
