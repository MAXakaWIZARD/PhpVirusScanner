<?php
namespace PhpVirusScanner\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Finder\Finder;
use Symfony\Component\Finder\SplFileInfo;
use PhpVirusScanner\Helper\Table;
use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Helper\TableStyle;

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

        $this->addOption(
            'show-full-paths',
            null,
            InputOption::VALUE_NONE,
            'If set, full file paths will be displayed'
        );

        $this->addOption(
            'size',
            null,
            InputOption::VALUE_REQUIRED,
            'If set, only files with specified size will be examined',
            0
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
            $output->writeln('Invalid signature.');
            return;
        }

        $doDelete = (bool) $input->getOption('delete');
        $showFullPaths = (bool) $input->getOption('show-full-paths');
        $targetSize = intval($input->getOption('size'));

        $output->writeln("Target signature: {$signature}");
        $output->writeln("Scanning dir {$dir}...");

        $finder = new Finder();
        $finder->files()->followLinks()->in($dir)->name('*.php');
        if ($targetSize) {
            $finder->size('==' . $targetSize);
        }

        $table = new Table($output);
        $table->setHeaders(['#', 'Path', 'Size']);

        $style = new TableStyle();
        $style->setPadType(STR_PAD_LEFT);

        $table->setColumnStyle(2, $style);

        $analyzedCount = 0;
        $infectedCount = 0;
        $deletedCount = 0;
        $deleteErrorsCount = 0;
        $dirStrLength = strlen($dir);
        foreach ($finder as $file) {
            $analyzedCount++;

            if (!$this->isInfected($file, $signature)) {
                continue;
            }

            /** @var SplFileinfo $file */

            $infectedCount++;
            $filePath = $file->getRealPath();
            if (!$showFullPaths) {
                $filePath = substr($filePath, $dirStrLength);
            }
            $table->addRow([$infectedCount, $filePath, number_format($file->getSize(), 0, '.', ' ')]);

            if ($doDelete) {
                if (@unlink($file->getRealPath())) {
                    $deletedCount++;
                } else {
                    $deleteErrorsCount++;
                }
            }
        }

        if ($infectedCount > 0) {
            $table->render();

            $output->writeln('Total infected files: ' . $infectedCount);

            if ($doDelete) {
                $output->writeln('Deleted files: ' . $deletedCount);
                if ($deleteErrorsCount > 0) {
                    $output->writeln('Failed to delete: ' . $deleteErrorsCount);
                }
            }
        } else {
            $output->writeln('Nothing found!');
        }

        $output->writeln('Total analyzed files: ' . $analyzedCount);

        $this->printProfilerOutput($output);
    }

    /**
     * @param SplFileInfo $file
     * @param              $signature
     *
     * @return bool
     */
    protected function isInfected(\SplFileInfo $file, $signature)
    {
        if (!$file->isReadable()) {
            return false;
        }

        $content = $file->getContents();
        if (!$content) {
            return false;
        }

        $contains = strpos($content, $signature) !== false;
        return $contains;
    }
}
