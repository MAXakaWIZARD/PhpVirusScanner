<?php

namespace PhpVirusScanner\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class AbstractCommand extends Command
{
    protected $startTime;

    /**
     * @var \Symfony\Component\Console\Application
     */
    protected $console;

    /**
     *
     */
    public function __construct(\Symfony\Component\Console\Application $console)
    {
        $this->startTime = microtime(true);

        $this->console = $console;

        parent::__construct();
    }

    /**
     * @param OutputInterface $output
     */
    protected function printProfilerOutput(OutputInterface $output)
    {
        $end = microtime(true);
        $totalSecs = $end - $this->startTime;

        $mins = floor($totalSecs / 60);
        $secs = $totalSecs - ($mins * 60);

        $output->write('Done in: ' . sprintf('%.3f', $totalSecs) . ' secs');
        $output->writeln(" ({$mins} mins " . sprintf('%.3f', $secs) . " secs)");


        $output->writeln('Max mem: ' . sprintf('%.3f', memory_get_peak_usage() / 1048576) . ' Mb');
    }
}
