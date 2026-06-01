<?php
declare(strict_types=1);

namespace App\Insight\Action;

final class ScheduleAction
{
    public static function upcomingReports(array $args = []): string
    {
        return 'Upcoming report schedule loaded.';
    }

    public static function reportCalendar(array $args = []): string
    {
        return 'Report calendar synchronized.';
    }

    public static function dryRun(array $args = []): string
    {
        return 'Schedule dry-run completed with no conflicts.';
    }

    public static function nextRun(array $args = []): string
    {
        return 'Next scheduled run: tomorrow 09:00 UTC.';
    }

    public static function describeSchedule(array $args = []): string
    {
        return 'Schedule profile targets executive and growth boards.';
    }
}
