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
class ScanCommand extends AbstractCommand
{
    /**
     * @var array
     */
    protected $results = [];

    /**
     * @var string
     */
    protected $dir;

    /**
     * @var string
     */
    protected $signature;

    /**
     * @var boolean
     */
    protected $doDelete;

    /**
     *
     */
    protected function configure()
    {
        $this->setName('scan');
        $this->setDescription('scan directory for infected files');

        $this->configureArguments();
        $this->configureOptions();
    }

    /**
     *
     */
    protected function configureArguments()
    {
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
    }

    /**
     *
     */
    protected function configureOptions()
    {
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
            'If set, only files with specified size will be examined'
        );
    }

    /**
     * @param InputInterface  $input
     * @param OutputInterface $output
     *
     * @throws \Exception
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        set_time_limit(0);

        $this->input = $input;
        $this->output = $output;

        $this->dir = $this->getDir();
        $this->signature = $this->getSignature();
        $this->doDelete = (bool) $this->input->getOption('delete');

        $this->initResults();

        $this->scan();

        $this->deleteInfectedFiles();

        $this->outputInfectedFiles();
        $this->outputScanStats();
    }

    /**
     * @return mixed
     * @throws \Exception
     */
    protected function getDir()
    {
        $dir = $this->input->getArgument('dir');
        if (!is_dir($dir) || !is_readable($dir)) {
            throw new \Exception('Specified directory not exists or is not readable.');
        }

        return $dir;
    }

    /**
     * @return mixed
     * @throws \Exception
     */
    protected function getSignature()
    {
        $signature = $this->input->getArgument('signature');
        if (!$signature) {
            throw new \Exception('Invalid signature.');
        }

        return $signature;
    }

    /**
     *
     */
    protected function initResults()
    {
        $this->results = [
            'analyzed' => 0,
            'unreadable' => 0,
            'infected' => 0,
            'deleted' => 0,
            'deleteErrors' => 0,
            'files' => []
        ];
    }

    /**
     *
     */
    protected function deleteInfectedFiles()
    {
        if (!$this->doDelete) {
            return;
        }

        foreach ($this->results['files'] as $file) {
            if (@unlink($file['path'])) {
                $this->results['deleted']++;
            } else {
                $this->results['deleteErrors']++;
            }
        }
    }

    /**
     *
     */
    protected function outputInfectedFiles()
    {
        if ($this->results['infected'] == 0) {
            return;
        }

        $showFullPaths = (bool) $this->input->getOption('show-full-paths');

        $dirStrLength = strlen($this->dir);

        $table = $this->getTable();
        foreach ($this->results['files'] as $index => $file) {
            $filePath = $file['path'];
            if (!$showFullPaths) {
                $filePath = substr($filePath, $dirStrLength);
            }
            $table->addRow([$index + 1, $filePath, number_format($file['size'], 0, '.', ' ')]);
        }
        $table->render();
    }

    /**
     *
     */
    protected function outputScanStats()
    {
        if ($this->results['infected'] > 0) {
            $this->output->writeln('Total infected files: ' . $this->results['infected']);

            if ($this->doDelete) {
                $this->output->writeln('Deleted files: ' . $this->results['deleted']);
                $this->output->writeln('Failed to delete: ' . $this->results['deleteErrors']);
            }
        } else {
            $this->output->writeln('Nothing found!');
        }

        if ($this->results['unreadable'] > 0) {
            $this->output->writeln('Non-readable files: ' . $this->results['unreadable']);
        }
        $this->output->writeln('Total analyzed files: ' . $this->results['analyzed']);

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
     *
     */
    protected function scan()
    {
        $this->output->writeln("Target signature: {$this->signature}");
        $this->output->writeln("Scanning dir {$this->dir}...");

        $targetSize = (int) $this->input->getOption('size');

        $finder = new Finder();
        $finder->files()->followLinks()->in($this->dir)->name('*.php');
        if ($targetSize) {
            $finder->size('==' . $targetSize);
        }

        foreach ($finder as $file) {
            $this->processFile($file);
        }
    }

    /**
     * @param SplFileInfo $file
     */
    protected function processFile($file)
    {
        $this->results['analyzed']++;

        if (!$file->isReadable()) {
            $this->results['unreadable']++;
            return;
        }

        if (!$this->isInfected($file)) {
            return;
        }

        $this->results['infected']++;
        $this->results['files'][] = [
            'path' => $file->getRealPath(),
            'size' => $file->getSize()
        ];
    }

    /**
     * @param SplFileInfo $file
     *
     * @return bool
     */
    protected function isInfected(SplFileInfo $file)
    {
        if (!$file->isReadable()) {
            return true;
        }

        $content = $file->getContents();
        if (!$content) {
            return false;
        }

        $contains = strpos($content, $this->signature) !== false;
        return $contains;
    }
}
