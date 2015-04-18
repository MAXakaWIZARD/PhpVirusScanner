<?php

namespace PhpVirusScanner\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Application;

class AbstractCommand extends Command
{
    /**
     * @var float
     */
    protected $startTime;

    /**
     * @var Application
     */
    protected $console;

    /**
     * @var InputInterface
     */
    protected $input;

    /**
     * @var OutputInterface
     */
    protected $output;

    /**
     *
     */
    public function __construct(Application $console)
    {
        $this->startTime = microtime(true);

        $this->console = $console;

        parent::__construct();
    }

    /**
     *
     */
    protected function printProfilerOutput()
    {
        $end = microtime(true);
        $totalSecs = $end - $this->startTime;

        $mins = floor($totalSecs / 60);
        $secs = $totalSecs - ($mins * 60);

        $this->output->write('Done in: ' . sprintf('%.3f', $totalSecs) . ' secs');
        $this->output->writeln(" ({$mins} mins " . sprintf('%.3f', $secs) . " secs)");

        $this->output->writeln('Max mem: ' . sprintf('%.3f', memory_get_peak_usage() / 1048576) . ' Mb');
    }
}
