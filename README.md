# test-certs-site

## Introduction 

This is a purpose-built webserver for hosting the test pages required by the 
CA/Browser forum Baseline Requirements. They contain the following requirement:

> The CA SHALL host test Web pages that allow Application Software Suppliers to
> test their software with Subscriber Certificates that chain up to each
> publicly trusted Root Certificate. At a minimum, the CA SHALL host separate
> Web pages using Subscriber Certificates that are valid, revoked, and expired.
 
It uses the ACME protocol to obtain certificates. It serves a simple website
with some information explaining what the test site is for.


From the CA/Browser Forum TLS Baseline Requirements: 

While this was built for Let's Encrypt, it should be usable by other ACME CAs.

## Running test-certs-site

This is a standalone Go program. Once a 1.0 release is available, we will begin
publishing releases.

```shell
go run ./cmd/ -config config/test.json
```

## Avoiding Incidents

This software was inspired by several incidents we observed from other CAs, as
well as the complexity of our existing solution using off-the-shelf tools.

Some categories of incidents we've observed include:
 
* Allowing certificates to expire incorrectly, for the valid and revoked .
* Serving unrevoked certificates on the revoked demonstration sites.

A server with ACME integration is the most reliable way to ensure certificates
are kept up-to-date, but the unusual requirements of serving revoked and expired
certificates is not a typical feature of other systems. Monitoring systems also
don't typically support ensuring that certificates are revoked or expired.

## ACME challenges

Currently, test-certs-site only supports the TLS-ALPN-01 validation method.
To fulfil this challenge, and to serve the test sites, this program listens
on a configurable port, which should be exposed as the TLS port, :443.

Note that in the test configuration listens on :5001 by default, which matches
[Pebble's](https://github.com/letsencrypt/pebble) default validation port. 

## Key and Certificate Storage

Currently, test-certs-site stores all key material as paths on disk.
To ease running cert-test-program in cloud or ephemeral environments, we will
want to support some mechanism for persisting keys to secrets management.

Other than the key and certificate storage, this program is stateless.

## Observability

There is a configurable debug listener which exposes /debug/pprof and /metrics.
Logs are printed in JSON to stderr.
