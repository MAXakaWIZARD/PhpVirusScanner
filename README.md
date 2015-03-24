PHP Virus Scanner
========================

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