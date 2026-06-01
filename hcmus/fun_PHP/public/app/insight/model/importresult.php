<?php
declare(strict_types=1);

namespace App\Insight\Model;

final class ImportResult
{
    public bool $success;
    public string $message;
    public string $previewHtml;

    public function __construct(bool $success, string $message, string $previewHtml = '')
    {
        $this->success = $success;
        $this->message = $message;
        $this->previewHtml = $previewHtml;
    }
}
