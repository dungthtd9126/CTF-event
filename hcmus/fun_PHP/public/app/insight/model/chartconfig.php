<?php
declare(strict_types=1);

namespace App\Insight\Model;

final class ChartConfig
{
    public string $type;
    public string $xAxis;
    public string $yAxis;
    public array $palette;

    public function __construct(string $type, string $xAxis, string $yAxis, array $palette)
    {
        $this->type = $type;
        $this->xAxis = $xAxis;
        $this->yAxis = $yAxis;
        $this->palette = $palette;
    }
}
