<?php
declare(strict_types=1);

namespace App\Insight\Service;

final class ReportRepository
{
    public function all(): array
    {
        return [
            ['name' => 'Revenue Momentum', 'status' => 'Ready', 'owner' => 'Finance Ops'],
            ['name' => 'Campaign Efficiency', 'status' => 'Building', 'owner' => 'Marketing Analytics'],
            ['name' => 'Traffic Source Pulse', 'status' => 'Ready', 'owner' => 'Growth'],
            ['name' => 'Executive Board Summary', 'status' => 'Queued', 'owner' => 'BizOps'],
        ];
    }
}
