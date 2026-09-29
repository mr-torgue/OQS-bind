
# Changes
OQS-Bind is currently lacking hybrid signatures, such as p256_falcon512.
Hybrid signatures are supported by oqs-provider https://github.com/open-quantum-safe/oqs-provider.
PQC algorithms might still be vulnerable because of their infancy.
Bringing hybrid signatures to bind9 allows us transition safely to quantum-safe algorithms by combining traditional signature schemes with post-quantum signature schemes.

This version of OQS-bind adds two things:
1. Support for hybrid signature schemes
2. Support for UDP fragmentation

# OQS-Bind
[![CodeQL](https://github.com/Martyrshot/OQS-bind/actions/workflows/codeql.yml/badge.svg)](https://github.com/Martyrshot/OQS-bind/actions/workflows/codeql.yml)

OQS-Bind is a forked version of ISC's [Bind9](https://gitlab.isc.org/isc-projects/bind9) DNS software
which enables PQC DNS. The original Bind9 README can be found [here](ORIGINAL_README.md). This fork
take advantage of [Open Quantum Safe](https://github.com/open-quantum-safe)'s
[liboqs](https://github.com/open-quantum-safe/liboqs) and [oqs-provider](https://github.com/open-quantum-safe/oqs-provider).
**NOTE:** OpenSSL 3.2 is **REQUIRED** to build and use OQS-Bind.

This project is not officially affiliated with Open Quantum Safe.

## Algorithms
Currently only DNSSEC is supported and tested with a small number of algorithms,
but DoT and DoH inprinciple should work. I plan on eventually enabling more DNSSEC PQC algorithms in the
future and automating enabling and disabling them, but for now this must be done by hand. The algorithms
we support in DNSSEC are as follows:

### DNSSEC Algorithms
For an overview of all algorithms supported by oqs-provider, click [here](https://github.com/open-quantum-safe/oqs-provider/blob/main/ALGORITHMS.md).

| Algorithm                     | DNSSEC Algorithm ID | Hybrid | Implemented |
| ----------------------------- | ------------------- | ------ | ----------- |
| mldsa44                       | 18                  | No     | Yes         |
| p256_mldsa44                  | 19                  | Yes    | Yes         |
| rsa3072_mldsa44               | 20                  | Yes    | Yes         |
| mldsa65                       | 21                  | No     | Yes         |
| p384_mldsa65                  | 22                  | Yes    | Yes         |
| mldsa87                       | 23                  | No     | Yes         |
| p521_mldsa87                  | 24                  | Yes    | Yes         |
| falconpadded512               | 25                  | No     | Yes         |
| p256_falconpadded512          | 26                  | Yes    | Yes         |
| rsa3072_falconpadded512       | 27                  | Yes    | Yes         |
| p521_falconpadded1024         | 28                  | Yes    | Yes         |
| falconpadded1024              | 29                  | No     | Yes         |
| sphincssha2128ssimple         | 30                  | No     | Yes         |
| p256_sphincssha2128ssimple    | 31                  | Yes    | Yes         |
| rsa3072_sphincssha2128ssimple | 32                  | Yes    | Yes         |
| mayo1                         | 33                  | No     | Yes         |
| p256_mayo1                    | 34                  | Yes    | Yes         |
| snova2454                     | 35                  | No     | Yes         |
| p256_snova2454                | 36                  | Yes    | Yes         |

We opted to start the algorithm IDs at 17 because of the discussion seen
[here](https://mailarchive.ietf.org/arch/msg/dnsop/2xKvE-g1WU5VozEDN7-h2e5y-MQ/).

### DoT/DoH Algorithms
These have not been tested, but in principle all algorithms supported by
[oqs-proivder](https://github.com/open-quantum-safe/oqs-provider) should work.

## Building

In order to build OQS-Bind, some version of OpenSSL 3.2 must be installed. At the time
of writing Beta1 just was released, so it is recommended to not use OpenSSL 3.2 as your
primary system-wide instalation of OpenSSL. Instead, installed OpenSSL 3.2 in a special
location. You can then specify the location of OpenSSL 3.2 using the `--with-openssl=<OPENSSL3.2DIR>`.
Then simply follow the regular Bind9 build instructions found [here](https://github.com/Martyrshot/OQS-bind/blob/main/doc/arm/build.inc.rst).

# 2.0 release features
- Fully implement and test RAW
- Use `rcodes` and `flags` to indicate fragments
- Remove DNSKEY/RRSIG header duplicates
- Improve render function and don't attach buffer to object
- Add more unit tests
- Improve performance