<?php
declare(strict_types=1);

namespace App\Insight\Model;

final class ReportFilter
{
    public string $dateStart;
    public string $dateEnd;
    public string $segment;
    public string $campaign;
    public string $channel;

    public function __construct(
        string $dateStart,
        string $dateEnd,
        string $segment,
        string $campaign,
        string $channel
    ) {
        $this->dateStart = $dateStart;
        $this->dateEnd = $dateEnd;
        $this->segment = $segment;
        $this->campaign = $campaign;
        $this->channel = $channel;
    }

    public function toLabel(): string
    {
        return sprintf(
            '%s to %s | %s | %s | %s',
            $this->dateStart,
            $this->dateEnd,
            $this->segment,
            $this->campaign,
            $this->channel
        );
    }
}
