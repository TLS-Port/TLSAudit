# TLSAudit

A simple script to check whether your Nginx TLS configuration is secure.

## Usage

Make sure `tlsaudit.sh` is executable:

```bash
chmod 744 tlsaudit.sh
```

and run:

```bash
./tlsaudit.sh <path/to/your/nginx.conf>
```

## Architecture
See [DESIGN.md](DESIGN.md) for more details on architectural drivers, software architecture and implementation.

## Tests

You need [shunit2](https://github.com/kward/shunit2/tree/master) unit test framework for Bash scripts if you want to run the tests. It is available as [Debian package](https://ubuntu.pkgs.org/24.04/ubuntu-universe-arm64/shunit2_2.1.8-4_all.deb.html) under Ubuntu 24.04 LTS and as a [Homebrew package](https://formulae.brew.sh/formula/shunit2) under MacOS.

To run the test, make sure `tlsaudit_test.sh` is executable and simply call it:

```bash
./tlsaudit_test.sh
```
