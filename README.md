# bonjour-reflector

## About this project

Bonjour-reflector makes Bonjour services discoverable between two Ethernet interfaces, for example across two VLANs. Service connections still require routing and firewall rules that allow them.

## How it works

Bonjour-reflector reflects only mDNS packets addressed to `224.0.0.251:5353` (IPv4) or `[ff02::fb]:5353` (IPv6). It sets the destination MAC to match the multicast IP without changing that IP. Unicast mDNS is not reflected.

Forwarded DNS messages omit all AAAA address records and remove AAAA from NSEC type bitmaps, while preserving NSEC itself and other records. This advertises only IPv4 addresses across VLANs without disabling IPv6 on the host or changing network settings.

Queries and responses captured on either interface are forwarded to the other. Queries request multicast responses so that replies can be reflected back. The reflector uses the outgoing interface's source MAC and excludes its own frames from capture.

## Installation

Go 1.25 or later is required to build bonjour-reflector. Checkout https://golang.org/doc/install for instructions on how to install a recent version of Golang.

To build the binary, run:

```
go build
```

One of the dependencies of the project (gopacket/pcap) also needs the libpcap header files to work properly.
On Linux-based distributions, you can do this by installing the development version of libpcap (package: libpcap-dev).

## App setup

Set the two distinct interface names in `config.toml`:

```toml
interfaces = ["en0", "en6"]
```

Both interfaces must present untagged Ethernet frames to the reflector. Tagged trunk mode, pool IDs, mirror groups and per-device sharing are no longer supported. Old configurations are rejected: migrate only if all devices on both networks should be discoverable on the other.

Invalid configuration stops startup before packet capture. To start the reflector, run

```
./bonjour-reflector -config=./config.toml
```

(you may need to run this line with administrator privileges to listen to your interface).

You may use any configuration file you want (following the same structure as the template `./config.toml` file provided) by specifying its path with the `-config` option.

## Contribution

Help on this project is very welcomed. Before submitting your contribution, please make sure to take a moment and read through the following guidelines:

- The `master` branch contains the latest stable version of the project. All development should be done in dedicated branches.
- Try to name your branch in a clear way, for example by following this pattern: `username/what-i-am-fixing`.
- Do not check in any compiled binaries in the commits.
- It's okay to have multiple small commits as you work on the PR - we will squash them before merging.
- Make sure all test cases pass (using `go test`).
- When fixing a bug:
    - Prefix your PR with `Fix:`, and add references to the issues linked to your PR (if they exist),
    - Add test coverage if applicable.
- When adding a new feature:
    - Prefix your PR with `Feature:`,
    - Add a description of your feature and reasons to add this feature,
    - Add test cases for this feature.

# Debugging & Profiling

A pprof server will listen on port `6060` if the you use the `-debug` flag.

More information on pprof is available [here](https://golang.org/pkg/net/http/pprof/)

Forwarded mDNS queries and service records are logged individually as they are forwarded, with the packet’s source and destination IP addresses and UDP ports. `-mdns-debug` also logs received records, source MACs and DNS details. Logs are written synchronously, so a slow terminal or log file can delay processing the next packet.

To display and save mDNS diagnostics until you press Ctrl+C:

```
./bonjour-reflector -config=./config.toml -mdns-debug 2>&1 | tee bonjour-reflector-mdns.log
```

## License

MIT
