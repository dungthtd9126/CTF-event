<?php
declare(strict_types=1);

namespace App\Insight\Controller;

use App\Insight\Model\ImportResult;
use App\Insight\Service\DashboardPreviewService;
use App\Insight\Service\PresetImportService;
use App\Insight\Service\ReportOperationsService;
use App\Insight\Support\Html;

final class ReportController
{
    public function index(): void
    {
        $operations = new ReportOperationsService();

        $content = '<h1>Report Library</h1>'
            . $operations->renderLibrary()
            . $operations->renderArchivePanel()
            . $operations->renderTemplateCards();

        echo $this->layout('Reports', $content);
    }

    public function preview(): void
    {
        $content = '<h1>Preset Preview</h1>'
            . '<div class="panel">'
            . '<p>Select a report template from the Reports page to preview revenue, traffic, and campaign blocks.</p>'
            . '<p><a class="btn btn-ghost" href="/reports">Choose a Template</a></p>'
            . '</div>';
        echo $this->layout('Preview', $content);
    }

    public function download(): void
    {
        $file = $_GET['file'] ?? '';
        if (!is_string($file) || $file === '') {
            http_response_code(400);
            header('Content-Type: text/plain; charset=utf-8');
            echo 'Missing report export filename.';
            return;
        }

        $file = str_replace("\0", '', $file);
        if (str_contains(strtolower($file), 'proc')) {
            http_response_code(404);
            header('Content-Type: text/plain; charset=utf-8');
            echo 'Report export not found.';
            return;
        }

        $file = str_replace('\\', '/', $file);
        if ($file === '') {
            http_response_code(404);
            header('Content-Type: text/plain; charset=utf-8');
            echo 'Report export not found.';
            return;
        }

        $path = '/var/www/storage/reports/' . $file;
        header('Content-Type: text/plain; charset=utf-8');
        header('Content-Disposition: inline; filename="' . basename($file) . '"');
        echo (string)file_get_contents($path);
    }

    public function importPreset(): void
    {
        $importer = new PresetImportService();
        $previewService = new DashboardPreviewService();

        try {
            $preset = $importer->importFromRequest($_POST);
            $preview = $previewService->renderPreview($preset);
            $result = new ImportResult(true, 'Preset imported successfully.', $preview);
        } catch (\Throwable $e) {
            $result = new ImportResult(false, 'Import failed: ' . $e->getMessage());
        }

        $content = '<h1>Import Result</h1><div class="panel">'
            . '<p class="status ' . ($result->success ? 'ok' : 'err') . '">' . Html::e($result->message) . '</p>'
            . ($result->previewHtml !== '' ? $result->previewHtml : '<p>No preview generated.</p>')
            . '<p><a class="btn btn-ghost" href="/reports">Back to Reports</a></p>'
            . '</div>';

        echo $this->layout('Import Result', $content);
    }

    private function layout(string $title, string $content): string
    {
        return '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            . '<title>' . $title . ' - InsightBoard</title><link rel="stylesheet" href="/assets/app.css"></head><body>'
            . '<header class="topbar"><h2>InsightBoard</h2><nav><a href="/">Home</a><a href="/dashboard">Dashboard</a><a href="/reports">Reports</a></nav></header>'
            . '<main class="layout"><aside class="sidebar"><h3>Reports</h3><ul><li>Library</li><li>Preview</li><li>Imports</li><li>Scheduled</li></ul></aside>'
            . '<section class="content">' . $content . '</section></main><script src="/assets/dashboard.js"></script></body></html>';
    }

}