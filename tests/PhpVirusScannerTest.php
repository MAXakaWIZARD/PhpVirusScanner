<?php
namespace PhpVirusScanner\Tests;

use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;
use PhpVirusScanner\Command\Scan as ScanCommand;

/**
 *
 */
class PhpVirusScannerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var Application
     */
    protected $console;

    /**
     * @var ScanCommand
     */
    protected $command;

    /**
     * @var CommandTester
     */
    protected $commandTester;

    /**
     *
     */
    public function setUp()
    {
        $this->console = new Application();
        $this->console->add(new ScanCommand($this->console));

        $this->command = $this->console->find('scan');
        $this->commandTester = new CommandTester($this->command);
    }

    /**
     *
     */
    public function testGeneral()
    {
        $this->commandTester->execute([
            'command' => $this->command->getName(),
            'dir' => TEST_DATA_PATH,
            'signature' => 'REALLY_BAD_SIGNATURE',
            '--show-full-paths' => true
        ]);

        $output = $this->commandTester->getDisplay();

        $this->assertEquals(true, strpos($output, TEST_DATA_PATH . '/1.php') !== false);
        $this->assertEquals(true, strpos($output, 'Total infected files: 1') !== false);
        $this->assertEquals(true, strpos($output, 'Total analyzed files: 2') !== false);
    }

    /**
     *
     */
    public function testNothingFound()
    {
        $this->commandTester->execute([
            'command' => $this->command->getName(),
            'dir' => TEST_DATA_PATH,
            'signature' => 'UNKNOWN_SIGNATURE',
            '--show-full-paths' => true
        ]);

        $output = $this->commandTester->getDisplay();

        $this->assertEquals(true, strpos($output, TEST_DATA_PATH . '/1.php') === false);
        $this->assertEquals(true, strpos($output, 'Nothing found!') !== false);
        $this->assertEquals(true, strpos($output, 'Total analyzed files: 2') !== false);
    }

    /**
     * @dataProvider providerInvalidArguments
     *
     * @param array $args
     * @param string $message
     */
    public function testInvalidArguments(array $args, $message)
    {
        $this->commandTester->execute($args);
        $output = $this->commandTester->getDisplay();

        $this->assertEquals(true, strpos($output, $message) !== false);
    }

    /**
     * @return array
     */
    public function providerInvalidArguments()
    {
        return [
            [
                [
                    'command' => 'scan',
                    'dir' => TEST_DATA_PATH . '_not_exists',
                    'signature' => 'UNKNOWN_SIGNATURE'
                ],
                'Specified directory not exists or is not readable'
            ],
            [
                [
                    'command' => 'scan',
                    'dir' => TEST_DATA_PATH,
                    'signature' => ''
                ],
                'Invalid signature'
            ]
        ];
    }
}
