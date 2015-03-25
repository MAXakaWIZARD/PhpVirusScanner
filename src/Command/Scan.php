<?php
namespace PhpVirusScanner\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Finder\Finder;
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
            $output->writeln('Specify signature.');
            return;
        }

        $doDelete = (bool) $input->getOption('delete');
        $showFullPaths = (bool) $input->getOption('show-full-paths');
        $targetSize = intval($input->getOption('size'));

        $output->writeln("Target signature: {$signature}");
        $output->writeln("Scanning dir {$dir}...");

        $filter = function (\SplFileInfo $file) use ($signature) {
            if (!$file->isReadable()) {
                return false;
            }

            $content = $file->getContents();
            if (!$content) {
                return false;
            }

            $contains = strpos($content, $signature) !== false;
            return $contains;
        };

        $finder = new Finder();
        $finder->files()->followLinks()->in($dir)->name('*.php')->filter($filter);
        if ($targetSize) {
            $finder->size('==' . $targetSize);
        }

        if (count($finder)) {
            $table = new Table($output);
            $table->setHeaders(['#', 'Path', 'Size']);

            $style = new TableStyle();
            $style->setPadType(STR_PAD_LEFT);

            $table->setColumnStyle(2, $style);

            $counter = 0;
            $deletedCounter = 0;
            $deleteErrorsCounter = 0;
            $dirStrLength = strlen($dir);
            foreach ($finder as $file) {
                /** @var \SplFileinfo $file */

                $counter++;
                $filePath = $file->getRealPath();
                if (!$showFullPaths) {
                    $filePath = substr($filePath, $dirStrLength);
                }
                $table->addRow([$counter, $filePath, number_format($file->getSize(), 0, '.', ' ')]);

                if ($doDelete) {
                    if (@unlink($file->getRealPath())) {
                        $deletedCounter++;
                    } else {
                        $deleteErrorsCounter++;
                    }
                }
            }

            $table->render();

            $output->writeln('Total infected files: ' . $counter);

            if ($doDelete) {
                $output->writeln('Deleted files: ' . $deletedCounter);
                if ($deleteErrorsCounter > 0) {
                    $output->writeln('Failed to delete: ' . $deleteErrorsCounter);
                }
            }
        } else {
            $output->writeln('Nothing found!');
        }

        $this->printProfilerOutput($output);
    }
}
