<?php
namespace PhpVirusScanner\Tests;

use Symfony\Component\Process\Process;

/**
 *
 */
class PhpVirusScannerTest extends \PHPUnit_Framework_TestCase
{
    /**
     *
     */
    public function testGeneral()
    {
        $cmd = "php phpvs scan " . TEST_DATA_PATH . " 'REALLY_BAD_SIGNATURE' --show-full-paths";
        $process = new Process($cmd, BASE_PATH);
        $process->run();

        if (!$process->isSuccessful()) {
            throw new \RuntimeException($process->getErrorOutput());
        }

        $output = $process->getOutput();

        $this->assertEquals(true, strpos($output, TEST_DATA_PATH . '/1.php') !== false);
        $this->assertEquals(true, strpos($output, 'Total infected files: 1') !== false);
    }

    /**
     *
     */
    public function testNothingFound()
    {
        $cmd = "php phpvs scan " . TEST_DATA_PATH . " 'UNKNOWN_SIGNATURE' --show-full-paths";
        $process = new Process($cmd, BASE_PATH);
        $process->run();

        if (!$process->isSuccessful()) {
            throw new \RuntimeException($process->getErrorOutput());
        }

        $output = $process->getOutput();

        $this->assertEquals(true, strpos($output, TEST_DATA_PATH . '/1.php') === false);
        $this->assertEquals(true, strpos($output, 'Nothing found!') !== false);
    }
}
