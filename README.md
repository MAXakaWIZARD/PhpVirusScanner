PHP Virus Scanner
========================
[![Build Status](https://api.travis-ci.org/MAXakaWIZARD/PhpVirusScanner.png?branch=master)](https://travis-ci.org/MAXakaWIZARD/PhpVirusScanner) 
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/MAXakaWIZARD/PhpVirusScanner/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/MAXakaWIZARD/PhpVirusScanner/?branch=master)
[![Coverage Status](https://coveralls.io/repos/MAXakaWIZARD/PhpVirusScanner/badge.svg?branch=master)](https://coveralls.io/r/MAXakaWIZARD/PhpVirusScanner?branch=master)
[![Latest Stable Version](https://poser.pugx.org/maxakawizard/php-virus-scanner/v/stable.svg)](https://packagist.org/packages/maxakawizard/php-virus-scanner) 
[![Total Downloads](https://poser.pugx.org/maxakawizard/php-virus-scanner/downloads.svg)](https://packagist.org/packages/maxakawizard/php-virus-scanner) 
[![License](https://poser.pugx.org/maxakawizard/php-virus-scanner/license.svg)](https://packagist.org/packages/maxakawizard/php-virus-scanner)

This is a console tool for scanning files for virus signatures.

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