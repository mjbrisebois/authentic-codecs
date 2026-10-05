[![](https://img.shields.io/npm/v/@whi/authentic-codecs/latest?style=flat-square)](http://npmjs.com/package/@whi/authentic-codecs)

# Authentic Codecs
Encode/decode tools for `Authentic` style encodings.

![](https://img.shields.io/github/issues-raw/mjbrisebois/authentic-codecs?style=flat-square)
![](https://img.shields.io/github/issues-closed-raw/mjbrisebois/authentic-codecs?style=flat-square)
![](https://img.shields.io/github/issues-pr-raw/mjbrisebois/authentic-codecs?style=flat-square)

## Overview
Authentic values are random identifiers that carry their type in their text form. Each is encoded
as URL-safe base64 of a type prefix followed by random bytes, and the prefix is chosen so that the
encoding begins with a readable tag:

| Type | Purpose       | Random bytes | Example                                         |
|------|---------------|--------------|-------------------------------------------------|
| `C1` | Collection ID | 26           | `Auth_C1-AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBk=`  |
| `K1` | Access key ID | 12           | `Auth_K1-ZGVmZ2hpamtsbW5v`                      |
| `U1` | Credential ID | 26           | `Auth_U1-AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBk=`  |

A `K1` also has a 46-byte secret. Together they form an access key: the ID and the base64 secret
joined by `.`.

The package also includes a URL-safe base64 codec and SHA-512 digests encoded as
[multihashes](https://multiformats.io/multihash/).

It uses only web-standard APIs, so it runs in Node.js 20.19+, Cloudflare Workers (without the
`nodejs_compat` flag) and browsers.

## Install

```
npm install @whi/authentic-codecs
```

## Usage

```js
import { authentic, base64, digest } from '@whi/authentic-codecs';

// Generate a new random ID
const collection = new authentic.C1();
collection.toString();                  // "Auth_C1-..."
JSON.stringify({ collection });         // encodes as the string form

// Decode from the string form; throws if the prefix or length is wrong
const same = new authentic.C1( collection.toString() );

// Access keys
const key = new authentic.K1();
const access_key = key.accessKey();     // "Auth_K1-....<secret>"
const parsed = new authentic.K1( access_key );
parsed.secret;                          // Uint8Array(46)

// URL-safe base64
base64.encode( new Uint8Array([ 251, 255 ]) );   // "-_8="
base64.encode( 32 );                             // 32 random bytes, encoded
base64.decode( "-_8=" );                         // Uint8Array [ 251, 255 ]

// SHA-512 multihash, as standard base64
const hash = digest.encode( key.secret );
digest.verify( key.secret, hash );      // true
digest.decode( hash );                  // Uint8Array(64), the raw digest
```

The codecs are also available as the default export: `codecs.authentic`, `codecs.base64` and
`codecs.digest`.

Decoded bytes are `Uint8Array`, not `Buffer`. See the [changelog](CHANGELOG.md) when upgrading
from 0.1.

## Development

```
npm test
```

Runs the test suite in Node.js, then again inside the Cloudflare Workers runtime (workerd) with no
compatibility flags, so any use of Node-only APIs fails. Run either half with `npm run test:node`
or `npm run test:workerd`; the workerd run requires Node.js 22+.
