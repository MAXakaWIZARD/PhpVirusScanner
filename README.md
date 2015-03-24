PHP Virus Scanner
========================

This is a console tool for scanning files for virus signatures.

Usage
-----------------
This will output `*.php` files containing specified signature:
```bash
php phpvs scan /path/to/dir "eval($_POST['a'])"
```

This will delete all `*.php` files containing specified signature:
```bash
php phpvs scan /path/to/dir "eval($_POST['a'])" --delete
```