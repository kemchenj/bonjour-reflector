# bonjour-reflector

## About this project

Bonjour-reflector makes Bonjour devices such as printers, Chromecasts or Spotify Connect speakers, discoverable and usable by other devices located on different VLANs.

Compared to other tools such as [avahi-reflector](http://www.avahi.org/), Bonjour-reflector allows a more fine-grained control of how Bonjour traffic is reflected across VLANs. 

## How it works

Bonjour-reflector reflects only mDNS packets addressed to `224.0.0.251:5353` (IPv4) or `[ff02::fb]:5353` (IPv6). It sets the destination MAC to match the multicast IP without changing that IP. Unicast mDNS is not reflected.

Forwarded DNS messages omit all AAAA address records and remove AAAA from NSEC type bitmaps, while preserving NSEC itself and other records. This advertises only IPv4 addresses across VLANs without disabling IPv6 on the host or changing network settings.

A configuration file lists, for each Bonjour device (defined by its MAC address), which VLANs should have access to this device. mDNS packets will only be forwarded if the configuration file says so.

In tagged mode, the capture interface must receive tagged traffic from each VLAN. In mapped mode, the ingress interface determines the pool instead of the packet's VLAN tag.

In tagged mode, a discovery works like this:
- a device searching for Bonjour devices sends mDNS packets on his VLAN.
- bonjour-reflector receives these mDNS packets, tagged with the original VLAN.
- bonjour-reflector looks up in its configuration to which VLANs it should forward the mDNS request, and send new packets tagged with these new VLANs.
- one Bonjour device receives the packet and sends a response which is also intercepted by bonjour-reflector.
- bonjour-reflector reads the source MAC of the mDNS response, looks up in its configuration which VLANs are shared with this Bonjour device, and reflects the mDNS response on each of these VLANs.

## Installation

Go 1.25 or later is required to build bonjour-reflector. Checkout https://golang.org/doc/install for instructions on how to install a recent version of Golang.

To build the binary, run:

```
go build
```

One of the dependencies of the project (gopacket/pcap) also needs the libpcap header files to work properly.
On Linux-based distributions, you can do this by installing the development version of libpcap (package: libpcap-dev).

## App setup

Choose how to identify pools in `config.toml`:

- **Mapped interfaces** (as in the example): set `interfaces` to entries such as `{ name = "en0", pool = 10 }`. Interface names and nonzero pool IDs must be unique. All pools referenced by `mirror_groups` and `devices` must be listed in `interfaces`.
- **Tagged interface**: set `net_interface` and omit `interfaces`. Pool IDs are tagged VLAN IDs from 1 to 4094. If both are set, a nonempty `interfaces` list takes precedence.

`mirror_groups` defines bidirectional forwarding between pools in each group. In `devices`, use a 6-byte MAC address as the key. MAC addresses are normalized at startup, so uppercase and lowercase spellings refer to the same device and cannot both be listed. `origin_pool` controls where queries for that device are forwarded; responses are matched by source MAC, not checked against `origin_pool`, and are forwarded to `shared_pools`.

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

To collect mDNS forwarding diagnostics for five minutes and save them to a file:

```
./bonjour-reflector -config=./config.toml -mdns-debug -run-duration=5m -log-file=/tmp/bonjour-reflector-mdns.log
```

## License

MIT
