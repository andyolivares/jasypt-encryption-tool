# Jasypt Encryption Tool

Simple CLI to encrypt data using a Jasypt (http://www.jasypt.org) compatible format.

It reads lines from multiple sources or STDIN if no source is specified. Encrypted lines are written back to a file (if specified) or STDOUT.

Jasypt format used is:
* algorithm: PBEWITHHMACSHA256ANDAES_256
* saltGeneratorClassName: org.jasypt.salt.RandomSaltGenerator
* ivGeneratorClassName: org.jasypt.iv.RandomIvGenerator

```
Usage: jasyptenc.exe [OPTIONS] --password <PASSWORD>

Options:
  -d, --data <STRING>
          Data to encrypt

  -i, --input <FILE>
          Input file with data lines to encrypt

  -o, --output <FILE>
          Output file where to write encrypted data to

      --prefix <PREFIX>
          String that will be prefixed to each encrypted line

      --postfix <POSTFIX>
          String that will be postfixed to each encrypted line

  -p, --password <PASSWORD>
          The password used to encrypt data

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```
