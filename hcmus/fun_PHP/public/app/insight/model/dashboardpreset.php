<?php
declare(strict_types=1);

namespace App\Insight\Model;

final class DashboardPreset
{
    public string $name;
    public string $layout;
    public array $blocks;

    public function __construct(string $name, string $layout, array $blocks)
    {
        $this->name = $name;
        $this->layout = $layout;
        $this->blocks = $blocks;
    }

    public function getBlocks(): array
    {
        return $this->blocks;
    }
}
