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
     * @dataProvider providerGeneral
     *
     * @param array $params
     */
    public function testGeneral(array $params)
    {
        $this->commandTester->execute($params['args']);
        $output = $this->commandTester->getDisplay();

        foreach ($params['contains'] as $message) {
            $this->assertNotSame(
                false,
                strpos($output, $message),
                "\"$message\" should be contained in \"$output\""
            );
        }

        foreach ($params['not_contains'] as $message) {
            $this->assertSame(
                false,
                strpos($output, $message),
                "\"$message\" should not be contained in \"$output\""
            );
        }
    }

    /**
     * @return array
     */
    public function providerGeneral()
    {
        return [
            [[
                'args' => [
                    'command' => 'scan',
                    'dir' => TEST_DATA_PATH . '_not_exists',
                    'signature' => 'UNKNOWN_SIGNATURE'
                ],
                'contains' => ['Specified directory not exists or is not readable'],
                'not_contains' => []
            ]],
            [[
                'args' => [
                    'command' => 'scan',
                    'dir' => TEST_DATA_PATH,
                    'signature' => ''
                ],
                'contains' => ['Invalid signature'],
                'not_contains' => []
            ]],
            [[
                'args' => [
                    'command' => 'scan',
                    'dir' => TEST_DATA_PATH,
                    'signature' => 'REALLY_BAD_SIGNATURE',
                    '--show-full-paths' => true
                ],
                'contains' => [
                    TEST_DATA_PATH . '/1.php',
                    'Total infected files: 1',
                    'Total analyzed files: 2'
                ],
                'not_contains' => []
            ]],
            [[
                 'args' => [
                     'command' => 'scan',
                     'dir' => TEST_DATA_PATH,
                     'signature' => 'REALLY_BAD_SIGNATURE',
                     '--show-full-paths' => false,
                     '--size' => '29'
                 ],
                 'contains' => [
                     '1.php',
                     'Total infected files: 1',
                     'Total analyzed files: 1'
                 ],
                 'not_contains' => [TEST_DATA_PATH . '/1.php']
            ]],
            [[
                'args' => [
                    'command' => 'scan',
                    'dir' => TEST_DATA_PATH,
                    'signature' => 'UNKNOWN_SIGNATURE',
                    '--show-full-paths' => true
                ],
                'contains' => [
                    'Nothing found!',
                    'Total analyzed files: 2'
                ],
                'not_contains' => [TEST_DATA_PATH . '/1.php']
            ]]
        ];
    }
}
