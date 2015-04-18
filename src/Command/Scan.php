<?php
namespace PhpVirusScanner\Command;

use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Finder\Finder;
use Symfony\Component\Finder\SplFileInfo;
use PhpVirusScanner\Helper\Table;
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

        $this->input = $input;
        $this->output = $output;

        $dir = $this->input->getArgument('dir');
        if (!is_dir($dir) || !is_readable($dir)) {
            $this->output->writeln('Specified directory not exists or is not readable.');
            return;
        }

        $signature = $this->input->getArgument('signature');
        if (!$signature) {
            $this->output->writeln('Invalid signature.');
            return;
        }

        $doDelete = (bool) $this->input->getOption('delete');
        $showFullPaths = (bool) $this->input->getOption('show-full-paths');

        $this->output->writeln("Target signature: {$signature}");
        $this->output->writeln("Scanning dir {$dir}...");

        $table = $this->getTable();

        $analyzedCount = 0;
        $unreadableCount = 0;
        $infectedCount = 0;
        $deletedCount = 0;
        $deleteErrorsCount = 0;
        $dirStrLength = strlen($dir);

        /** @var SplFileinfo $file */
        foreach ($this->searchFiles($dir) as $file) {
            $analyzedCount++;

            if (!$file->isReadable()) {
                $unreadableCount++;
                continue;
            }

            if (!$this->isInfected($file, $signature)) {
                continue;
            }

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

            $this->output->writeln('Total infected files: ' . $infectedCount);

            if ($doDelete) {
                $this->output->writeln('Deleted files: ' . $deletedCount);
                if ($deleteErrorsCount > 0) {
                    $this->output->writeln('Failed to delete: ' . $deleteErrorsCount);
                }
            }
        } else {
            $this->output->writeln('Nothing found!');
        }

        if ($unreadableCount > 0) {
            $this->output->writeln('Non-readable files: ' . $unreadableCount);
        }
        $this->output->writeln('Total analyzed files: ' . $analyzedCount);

        $this->printProfilerOutput();
    }

    /**
     * @return Table
     */
    protected function getTable()
    {
        $table = new Table($this->output);
        $table->setHeaders(['#', 'Path', 'Size']);

        $style = new TableStyle();
        $style->setPadType(STR_PAD_LEFT);

        $table->setColumnStyle(2, $style);

        return $table;
    }

    /**
     * @param $dir
     *
     * @return Finder
     */
    protected function searchFiles($dir)
    {
        $targetSize = (int) $this->input->getOption('size');

        $finder = new Finder();
        $finder->files()->followLinks()->in($dir)->name('*.php');
        if ($targetSize) {
            $finder->size('==' . $targetSize);
        }

        return $finder;
    }

    /**
     * @param SplFileInfo $file
     * @param              $signature
     *
     * @return bool
     */
    protected function isInfected(SplFileInfo $file, $signature)
    {
        if (!$file->isReadable()) {
            return true;
        }

        $content = $file->getContents();
        if (!$content) {
            return false;
        }

        $contains = strpos($content, $signature) !== false;
        return $contains;
    }
}
