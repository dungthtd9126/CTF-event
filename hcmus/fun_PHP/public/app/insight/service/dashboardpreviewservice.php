<?php
declare(strict_types=1);

namespace App\Insight\Service;

use App\Insight\Model\DashboardPreset;
use App\Insight\Support\Html;

final class DashboardPreviewService
{
    private ReportActionDispatcher $dispatcher;

    public function __construct(?ReportActionDispatcher $dispatcher = null)
    {
        $this->dispatcher = $dispatcher ?? new ReportActionDispatcher();
    }

    public function renderPreview(DashboardPreset $preset): string
    {
        $items = [];
        foreach ($preset->getBlocks() as $block) {
            try {
                $result = $this->dispatcher->dispatch($block);
                $items[] = '<article class="panel"><h3>' . Html::e($block->title) . '</h3><div>' . $result . '</div></article>';
            } catch (\Throwable $e) {
                $items[] = '<article class="panel panel-error"><h3>' . Html::e($block->title) . '</h3><p>' . Html::e($e->getMessage()) . '</p></article>';
            }
        }

        return '<section class="preview-grid">' . implode('', $items) . '</section>';
    }
}
