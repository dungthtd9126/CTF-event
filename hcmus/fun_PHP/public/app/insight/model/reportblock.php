<?php
declare(strict_types=1);

namespace App\Insight\Model;

final class ReportBlock
{
    public string $title;
    public string $class;
    public string $method;
    public array $args;

    public function __construct(string $title, string $class, string $method, array $args = [])
    {
        $this->title = $title;
        $this->class = $class;
        $this->method = $method;
        $this->args = $args;
    }
}
