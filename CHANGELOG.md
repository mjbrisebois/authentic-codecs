# Changelog

## 1.0.0 - 2026-10-04

Runs in Cloudflare Workers and browsers as well as Node.js, with no Node.js compatibility layer
required. This release contains breaking changes; see [Upgrading](#upgrading) below.

### Added
- Support for Cloudflare Workers and other web-standard runtimes. The package only uses web APIs
  (`crypto.getRandomValues`, `Uint8Array`, `TextEncoder`), so Workers do not need the
  `nodejs_compat` flag.
- Named exports `base64`, `digest` and `authentic`, alongside the existing default export.

### Changed
- **Breaking:** published as an ES module. Requires Node.js 20.19+ or 22.12+.
- **Breaking:** decoded bytes are `Uint8Array` instead of `Buffer`.
- **Breaking:** errors are thrown as `Error` instead of Node's `AssertionError`.
- **Breaking:** decoding a `C1`, `K1` or `U1` from a string checks the type prefix and the exact
  byte length.
- **Breaking:** `digest.encode()` outputs URL-safe base64 (`-` and `_`) like the rest of the
  package, instead of standard base64 (`+` and `/`).
- `digest.verify()` compares bytes instead of strings, so digests in either alphabet verify. The
  comparison is constant-time.
- SHA-512 is computed with `@noble/hashes`; multihash framing is done internally.

### Fixed
- Digest decode errors show the multihash code and digest length that were found, instead of the
  literal text `${config.name}` / `${config.length}`.
- `Object.prototype.toString` (and checks built on it, such as chai's `to.be.a("C1")`) reports
  `C1`, `K1` and `U1` even after bundling or minifying renames the classes.

### Removed
- **Breaking:** the `LOG_LEVEL` environment variable no longer enables debug logging.
- Dependencies `multihashes` and `@whi/stdlog`.

## Upgrading

Each item says how to tell whether your code is affected and what to change.

### ES module

**Affected if:** you load the package with `require()`, or run on Node.js older than 20.19.

`import` works as before:

```js
import codecs from '@whi/authentic-codecs';
// or
import { authentic, base64, digest } from '@whi/authentic-codecs';
```

`require()` still works on Node.js 20.19+ and 22.12+. It returns the module namespace, so
`codecs.authentic`, `codecs.base64` and `codecs.digest` keep working through the named exports.
Code that relied on the result being exactly the codecs object (for example, iterating its keys)
will also see `default` and `__esModule`. On older Node.js versions `require()` fails with
`ERR_REQUIRE_ESM`; upgrade Node.js or switch to `import`.

### `Uint8Array` instead of `Buffer`

**Affected if:** you call `Buffer` methods on a value returned by this package, such as
`.toString("base64")`, `.toString("hex")`, `.equals()`, `.readUInt32BE()` or `.slice()` expecting a
`Buffer`.

These return a `Uint8Array` instead of a `Buffer`:

- `base64.decode()`
- `digest.decode()`
- `K1#secret`, whether generated or decoded from an access key

This mostly fails silently: on a `Uint8Array`, `.toString("base64")` returns comma-separated numbers
such as `"1,2,3"` instead of base64, and no error is thrown. Use the package's encoders, or wrap the
value when you need a `Buffer`:

```js
base64.encode( k1.secret );            // URL-safe base64 string
Buffer.from( k1.secret ).toString("hex");
```

`C1`, `K1` and `U1` were already `Uint8Array` subclasses and are unchanged. Inputs still accept a
`Buffer`, because a `Buffer` is a `Uint8Array`.

### Error types

**Affected if:** you catch errors from this package and check `err instanceof AssertionError`,
`err.code === "ERR_ASSERTION"` or `err.name === "AssertionError"`.

All errors are now plain `Error` instances. Error messages for malformed `K1` access keys are
unchanged. Digest decode errors are reworded: see [Fixed](#fixed) above. Other malformed multihashes
now fail with `multihash too short` or `multihash length inconsistent`, and an otherwise well-formed
multihash with an unrecognized code fails with the same `not code 0x…` message as any other
non-SHA-512 code.

### Stricter decoding

**Affected if:** you decode `C1`, `K1` or `U1` values from strings that may be malformed, such as
stored data or user input.

Decoding a string now throws when:

- the type prefix belongs to another type, for example a `K1` string passed to `C1`:
  `expected prefix 'Auth_C1-', found 'Auth_K1-'`
- the value has the wrong number of bytes after the prefix:
  `expected 26 bytes after the prefix, found 24`

Previously the prefix was discarded unchecked, short values were padded with zero bytes, and long
values failed with a `RangeError`. If you may hold values that were accepted before, validate them
before upgrading, or wrap decoding in `try`/`catch`.

### Digest encoding

**Affected if:** you store digests from `digest.encode()` and later compare or look them up as
strings yourself, for example a database query by digest.

New digests use URL-safe base64, so they no longer equal digests stored by 0.1 whenever the encoding
contains `+` or `/`. `digest.verify()` and `digest.decode()` accept both forms, so code that only
uses those keeps working with stored digests. For string lookups, either convert stored digests
once (replace `+` with `-` and `/` with `_`), or look up both forms.

### Logging

**Affected if:** you set `LOG_LEVEL` to see debug output from this package.

The package no longer logs anything.
