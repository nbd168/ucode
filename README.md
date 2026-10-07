# ucode

A small, general-purpose scripting language for Linux systems. Ucode
resembles ECMAScript syntax, runs as a standalone interpreter or embedded
into host applications, supports template mode with Jinja-like markup
blocks, and ships with an embeddable C core.

- [Project page](https://ucode-lang.org/) — overview, quick tour, standard
  library, projects in production.
- [ucode manual](https://ucode-lang.org/manual/) — a comprehensive
  reference for the language, the standard library and the C embedding API.
- [ucode function reference](https://ucode-lang.org/ucode/) — the
  per-function reference for the standard library, generated from the JSDoc
  comments in the sources.
- [Try ucode online](https://try.ucode-lang.org/) — a web playground.

## Installation

The *ucode* package is preinstalled on modern OpenWrt releases. For
building and installing ucode on other systems, see the
[Installing ucode](https://ucode-lang.org/manual/#ch-02-installing) chapter
of the manual.

## Examples

Embedding ucode in C applications is demonstrated by the programs in the
[`examples/` directory](examples/). ucode scripting examples can be found
in the [testcase sources](tests/custom/).

Notable OpenWrt programs *embedding* ucode are the
[ubus rpc daemon](https://github.com/openwrt/rpcd) and the
[uhttpd web server](https://github.com/openwrt/uhttpd). Projects using
ucode scripting include the
[LuCI web interface](https://github.com/openwrt/luci) and the
[firewall4 framework](https://github.com/openwrt/firewall4).

## Building the documentation

The function reference in `docs/` is generated from the JSDoc comments in
the C sources: run `npm install` followed by `npm run doc` in the cloned
repository.
