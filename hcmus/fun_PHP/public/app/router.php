<?php
declare(strict_types=1);

namespace App;

final class Router
{
    private array $routes = [];

    public function add(string $method, string $path, callable $handler): void
    {
        $key = strtoupper($method) . ' ' . $path;
        $this->routes[$key] = $handler;
    }

    public function dispatch(string $method, string $path): void
    {
        $normalizedPath = parse_url($path, PHP_URL_PATH) ?: '/';
        $key = strtoupper($method) . ' ' . $normalizedPath;

        if (!isset($this->routes[$key])) {
            http_response_code(404);
            echo '<h1>404</h1><p>Page not found.</p>';
            return;
        }

        ($this->routes[$key])();
    }
}
