<?php
namespace PhpVirusScanner\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Finder\Finder;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Helper\ProgressBar;

/**
 *
 */
class Scan extends AbstractCommand
{
    /**
     *
     */
    protected function configure()
    {
        $this->setName('scan');
        $this->setDescription('scan directory for infected files');

        $this->addArgument(
            'dir',
            InputArgument::REQUIRED,
            'Directory to scan'
        );

        $this->addArgument(
            'signature',
            InputArgument::REQUIRED,
            'Signature to search for'
        );

        $this->addOption(
            'delete',
            null,
            InputOption::VALUE_NONE,
            'If set, command will delete all infected files'
        );
    }

    /**
     * @param \Symfony\Component\Console\Input\InputInterface   $input
     * @param \Symfony\Component\Console\Output\OutputInterface $output
     *
     * @return int|null|void
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        set_time_limit(0);

        $dir = $input->getArgument('dir');
        if (!is_dir($dir) || !is_readable($dir)) {
            $output->writeln('Specified directory not exists or is not readable.');
            return;
        }

        $signature = $input->getArgument('signature');
        if (!$signature) {
            $output->writeln('Specify signature.');
            return;
        }

        $output->writeln('Scanning dir ' . $dir . ' ...');

        $finder = new Finder();
        $finder->files()->followLinks()->in($dir)->name('*.php');

        foreach ($finder as $file) {
            /** @var \SplFileinfo $file */
            $file->getPath();
        }

        $this->printProfilerOutput($output);
    }
}
