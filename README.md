PHP Virus Scanner
========================
[![Build Status](https://api.travis-ci.org/MAXakaWIZARD/PhpVirusScanner.png?branch=master)](https://travis-ci.org/MAXakaWIZARD/PhpVirusScanner) 
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/MAXakaWIZARD/PhpVirusScanner/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/MAXakaWIZARD/PhpVirusScanner/?branch=master)
[![Coverage Status](https://coveralls.io/repos/MAXakaWIZARD/PhpVirusScanner/badge.svg?branch=master)](https://coveralls.io/r/MAXakaWIZARD/PhpVirusScanner?branch=master)
[![GitHub tag](https://img.shields.io/github/tag/MAXakaWIZARD/PhpVirusScanner.svg?label=latest)](https://packagist.org/packages/maxakawizard/php-virus-scanner) 
[![Minimum PHP Version](http://img.shields.io/badge/php-%3E%3D%205.4-8892BF.svg)](https://php.net/)
[![License](https://img.shields.io/packagist/l/maxakawizard/php-virus-scanner.svg)](https://packagist.org/packages/maxakawizard/php-virus-scanner)

[![SensioLabsInsight](https://insight.sensiolabs.com/projects/5c8c90f2-7397-4bfd-9107-bed3f80643eb/big.png)](https://insight.sensiolabs.com/projects/5c8c90f2-7397-4bfd-9107-bed3f80643eb)

This is a console tool for scanning files for virus signatures.

The code is compliant with [PSR-4](http://www.php-fig.org/psr/4/), [PSR-1](http://www.php-fig.org/psr/1/), and [PSR-2](http://www.php-fig.org/psr/2/).
If you notice compliance oversights, please send a patch via pull request.

Usage
-----------------
For correct signature interpretation, use only single quotes in command line.
If signature contains single code itself, escape it in such way: `'\''`

This will output `*.php` files containing code `eval($_POST['a'])`:
```bash
php phpvs scan /path/to/dir 'eval($_POST['\''a'\''])'
```

This will delete all `*.php` files containing code `eval(base64_decode($abc))`:
```bash
php phpvs scan /path/to/dir 'eval(base64_decode($abc))' --delete
```

License
-----------------
This library is released under [MIT](http://www.tldrlegal.com/license/mit-license) license.
