<?php
declare(strict_types=1);

namespace App\Insight\Controller;

final class HomeController
{
    public function index(): void
    {
        $content = '<section class="hero">'
            . '<h1>InsightBoard</h1>'
            . '<p>Internal analytics workspace for revenue, traffic, campaigns, and executive reporting previews.</p>'
            . '<div class="hero-actions">'
            . '<a class="btn" href="/dashboard">Open Dashboard</a>'
            . '<a class="btn btn-ghost" href="/reports">Open Reports</a>'
            . '</div>'
            . '</section>';

        echo $this->layout('Home', $content);
    }

    private function layout(string $title, string $content): string
    {
        return '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            . '<title>' . $title . ' - InsightBoard</title><link rel="stylesheet" href="/assets/app.css"></head><body>'
            . '<header class="topbar"><h2>InsightBoard</h2><nav><a href="/">Home</a><a href="/dashboard">Dashboard</a><a href="/reports">Reports</a></nav></header>'
            . '<main class="layout">'
            . '<aside class="sidebar"><h3>Analytics</h3><ul><li>Revenue</li><li>Traffic</li><li>Campaigns</li><li>Forecasting</li></ul></aside>'
            . '<section class="content">' . $content . '</section></main><script src="/assets/dashboard.js"></script></body></html>';
    }
}
