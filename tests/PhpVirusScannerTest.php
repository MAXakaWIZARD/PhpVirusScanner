<?php
namespace PhpVirusScanner\Tests;

use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;
use PhpVirusScanner\Command\ScanCommand;

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

    public function tearDown()
    {
        $tmpFiles = [
            TEST_DATA_PATH . '/3_tmp.php',
            TEST_DATA_PATH . '/4_tmp.php'
        ];

        foreach ($tmpFiles as $tmpFile) {
            if (file_exists($tmpFile)) {
                @unlink($tmpFile);
            }
        }
    }

    /**
     * @dataProvider providerGeneral
     *
     * @param array $params
     */
    public function testGeneral(array $params)
    {
        if ($params['exception'] !== '') {
            $this->setExpectedException('\Exception', $params['exception']);
        }

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
     * @dataProvider providerDeleting
     *
     * @param array $params
     */
    public function testDeleting(array $params)
    {
        $infectedFilePath = TEST_DATA_PATH . '/3_tmp.php';
        file_put_contents($infectedFilePath, "<?php \n DEADLY_SIGNATURE");
        $this->assertFileExists($infectedFilePath);

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

        $this->assertFileNotExists($infectedFilePath);
    }

    /**
     * @dataProvider providerUnreadable
     *
     * @param array $params
     */
    public function testUnreadable(array $params)
    {
        $infectedFilePath = TEST_DATA_PATH . '/4_tmp.php';
        file_put_contents($infectedFilePath, "<?php \n UGLY_SIGNATURE");
        $this->assertFileExists($infectedFilePath);
        @chmod($infectedFilePath, 0000);

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

        $this->assertFileExists($infectedFilePath);
        @chmod($infectedFilePath, 0664);
        @unlink($infectedFilePath);
        $this->assertFileNotExists($infectedFilePath);
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
                'exception' => 'Specified directory not exists or is not readable',
                'contains' => [],
                'not_contains' => []
            ]],
            [[
                'args' => [
                    'command' => 'scan',
                    'dir' => TEST_DATA_PATH,
                    'signature' => ''
                ],
                'exception' => 'Invalid signature',
                'contains' => [],
                'not_contains' => []
            ]],
            [[
                'args' => [
                    'command' => 'scan',
                    'dir' => TEST_DATA_PATH,
                    'signature' => 'REALLY_BAD_SIGNATURE',
                    '--show-full-paths' => true
                ],
                'exception' => '',
                'contains' => [
                    TEST_DATA_PATH . '/1.php',
                    'Total infected files: 1',
                    'Total analyzed files: 3'
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
                 'exception' => '',
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
                'exception' => '',
                'contains' => [
                    'Nothing found!',
                    'Total analyzed files: 3'
                ],
                'not_contains' => [TEST_DATA_PATH . '/1.php']
            ]]
        ];
    }

    /**
     * @return array
     */
    public function providerDeleting()
    {
        return [
            [[
                 'args' => [
                     'command' => 'scan',
                     'dir' => TEST_DATA_PATH,
                     'signature' => 'DEADLY_SIGNATURE',
                     '--show-full-paths' => true,
                     '--delete' => true
                 ],
                 'contains' => [
                     TEST_DATA_PATH . '/3_tmp.php',
                     'Total infected files: 1',
                     'Total analyzed files: 4',
                     'Deleted files: 1'
                 ],
                 'not_contains' => [TEST_DATA_PATH . '/1.php']
            ]]
        ];
    }

    /**
     * @return array
     */
    public function providerUnreadable()
    {
        return [
            [[
                 'args' => [
                     'command' => 'scan',
                     'dir' => TEST_DATA_PATH,
                     'signature' => 'UGLY_SIGNATURE',
                     '--show-full-paths' => true,
                     '--delete' => true
                 ],
                 'contains' => [
                     'Nothing found!',
                     'Non-readable files: 1',
                     'Total analyzed files: 4'
                 ],
                 'not_contains' => [
                     TEST_DATA_PATH . '/1.php',
                     TEST_DATA_PATH . '/2.php',
                     TEST_DATA_PATH . '/empty.php',
                 ]
             ]]
        ];
    }
}
