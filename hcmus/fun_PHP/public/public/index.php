<?php
declare(strict_types=1);

require '/var/www/app/bootstrap.php';
require '/var/www/config/reports.php';
require '/var/www/app/insight/module/enterprisereports.php';

use App\Router;
use App\Insight\Controller\DashboardController;
use App\Insight\Controller\HomeController;
use App\Insight\Controller\ReportController;
$router = new Router();
$dashboardController = new DashboardController();
$reportController = new ReportController();
$router->add('GET', '/', [new HomeController(), 'index']);
$router->add('GET', '/dashboard', [$dashboardController, 'index']);
$router->add('POST', '/dashboard/integrations/import-reference', [$dashboardController, 'importReference']);
$router->add('POST', '/dashboard/operations/publish-manifest', [$dashboardController, 'publishSnapshot']);
$router->add('GET', '/reports', [$reportController, 'index']);
$router->add('GET', '/reports/preview', [$reportController, 'preview']);
$router->add('GET', '/reports/download', [$reportController, 'download']);
$router->add('POST', '/reports/import-preset', [$reportController, 'importPreset']);

$router->dispatch($_SERVER['REQUEST_METHOD'] ?? 'GET', $_SERVER['REQUEST_URI'] ?? '/');
