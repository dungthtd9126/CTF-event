<?php
declare(strict_types=1);

namespace App\Insight\Controller;

use App\Insight\Service\DashboardMetricsService;
use App\Insight\Support\Html;
use App\Insight\Support\PathGuard;

final class DashboardController
{
    private const APPROVAL_ROOT = '/var/www';
    private const EXPORT_MANIFEST_PATH = '/var/www/storage/reports/admin-export-manifest.txt';

    public function index(): void
    {
        $this->startSession();

        $metrics = new DashboardMetricsService();
        $notice = $this->pullNotice();
        $content = '<h1>Dashboard Overview</h1>'
            . $this->renderNotice($notice)
            . $metrics->kpiCards()
            . $metrics->executivePanels()
            . $metrics->funnelPanel()
            . $metrics->operationsDigest()
            . $this->renderAdminPanel();

        echo $this->layout('Dashboard', $content);
    }

    public function importReference(): void
    {
        $this->startSession();

        if (!isset($_POST['ticket_ref']) || !is_string($_POST['ticket_ref']) || $_POST['ticket_ref'] === '') {
            $this->flash('err', 'Missing import reference.');
            $this->redirectToDashboard();
        }

        $reference = $_POST['ticket_ref'];
        if ($this->blockedReference($reference)) {
            $this->flash('err', 'Import reference was rejected by policy.');
            $this->redirectToDashboard();
        }

        $approvalBytes = $this->readApprovalBytes();
        if ($approvalBytes === null) {
            $this->flash('err', 'Credential import backend is unavailable.');
            $this->redirectToDashboard();
        }

        try {
            $candidate = @file_get_contents($reference);
        } catch (\Throwable $e) {
            $candidate = false;
        }

        if (is_string($candidate) && strlen($candidate) === 12 && hash_equals($approvalBytes, $candidate)) {
            $_SESSION['insightboard_admin'] = true;
            $this->flash('ok', 'Operator workspace enabled for this session.');
            $this->redirectToDashboard();
        }

        $this->flash('err', 'Import reference did not match an active credential.');
        $this->redirectToDashboard();
    }

    public function publishSnapshot(): void
    {
        $this->startSession();

        if (!$this->isAdmin()) {
            $this->flash('err', 'Operator approval is required before publishing manifests.');
            $this->redirectToDashboard();
        }

        if (!PathGuard::inStorage(self::EXPORT_MANIFEST_PATH) || !PathGuard::rejectPhpExtension(self::EXPORT_MANIFEST_PATH)) {
            $this->flash('err', 'Export manifest destination was rejected.');
            $this->redirectToDashboard();
        }

        if (@file_put_contents(self::EXPORT_MANIFEST_PATH, 'EXPORT_READY') === false) {
            $this->flash('err', 'Export manifest could not be published.');
            $this->redirectToDashboard();
        }

        $this->flash('ok', 'Export manifest published.');
        $this->redirectToDashboard();
    }

    private function layout(string $title, string $content): string
    {
        return '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            . '<title>' . $title . ' - InsightBoard</title><link rel="stylesheet" href="/assets/app.css"></head><body>'
            . '<header class="topbar"><h2>InsightBoard</h2><nav><a href="/">Home</a><a href="/dashboard">Dashboard</a><a href="/reports">Reports</a></nav></header>'
            . '<main class="layout"><aside class="sidebar"><h3>Dashboards</h3><ul><li>Overview</li><li>Revenue</li><li>Acquisition</li><li>Retention</li></ul></aside>'
            . '<section class="content">' . $content . '</section></main><script src="/assets/dashboard.js"></script></body></html>';
    }

    private function renderAdminPanel(): string
    {
        $status = $this->isAdmin()
            ? '<p class="status ok">Operator workspace is active for this browser session.</p>'
            : '<p class="preset-meta">Restricted publishing requires an approved import reference.</p>';

        $feature = $this->isAdmin()
            ? '<form method="post" action="/dashboard/operations/publish-manifest">'
                . '<button class="btn" type="submit">Publish Export Manifest</button>'
                . '</form>'
            : '<button class="btn btn-disabled" type="button" disabled>Publisher Locked</button>';

        return '<article class="panel admin-panel">'
            . '<h3>Operations Access</h3>'
            . $status
            . '<form class="reference-form" method="post" action="/dashboard/integrations/import-reference">'
            . '<label for="ticket_ref">Import operator approval reference</label>'
            . '<input id="ticket_ref" name="ticket_ref" type="text" autocomplete="off" placeholder="Approval reference">'
            . '<button class="btn" type="submit">Import Reference</button>'
            . '</form>'
            . '<div class="admin-feature">'
            . '<h4>Manifest Publisher</h4>'
            . '<p class="preset-meta">Publishes compatibility manifests for scheduled analytics exports.</p>'
            . $feature
            . '</div>'
            . '</article>';
    }

    private function renderNotice(?array $notice): string
    {
        if ($notice === null) {
            return '';
        }

        $type = $notice['type'] === 'ok' ? 'ok' : 'err';
        return '<p class="status ' . $type . '">' . Html::e($notice['message']) . '</p>';
    }

    private function readApprovalBytes(): ?string
    {
        $path = self::APPROVAL_ROOT . '/secrets/admin_ticket.txt';
        $approvalBytes = @file_get_contents($path);
        if (!is_string($approvalBytes) || strlen($approvalBytes) !== 12) {
            return null;
        }

        return $approvalBytes;
    }

    private function blockedReference(string $reference): bool
    {
        if (str_contains($reference, "\0")) {
            return true;
        }

        foreach ([
            'zlib',
            '../',
            '..\\',
            'data',
            'file',
            'fd',
            'stdin',
            'dechunk',
            'stdout',
            'stderr',
            'input',
            'memory',
            "compress",
            'secrets',
            'admin_ticket.txt',
            'secrets/admin_ticket.txt',
        ] as $blocked) {
            if ($this->containsBannedToken($reference, $blocked)) {
                return true;
            }
        }

        return false;
    }

    private function containsBannedToken(string $input, string $token): bool
    {
        $lower = strtolower($input);
        if (str_contains($lower, $token)) {
            return true;
        }

        $decoded = $lower;
        for ($i = 0; $i < 2; $i++) {
            $next = rawurldecode($decoded);
            if ($next === $decoded) {
                break;
            }
            $decoded = $next;
            if (str_contains($decoded, $token)) {
                return true;
            }
        }

        return false;
    }

    private function isAdmin(): bool
    {
        return ($_SESSION['insightboard_admin'] ?? false) === true;
    }

    private function startSession(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
    }

    private function flash(string $type, string $message): void
    {
        $_SESSION['dashboard_notice'] = ['type' => $type, 'message' => $message];
    }

    private function pullNotice(): ?array
    {
        $notice = $_SESSION['dashboard_notice'] ?? null;
        unset($_SESSION['dashboard_notice']);

        if (!is_array($notice)) {
            return null;
        }

        return [
            'type' => (string)($notice['type'] ?? 'err'),
            'message' => (string)($notice['message'] ?? ''),
        ];
    }

    private function redirectToDashboard(): never
    {
        header('Location: /dashboard', true, 303);
        exit;
    }
}
