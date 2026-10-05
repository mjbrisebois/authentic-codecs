import { sha512 }			from '@noble/hashes/sha2.js';


const BASE64_ALPHABET			= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_LOOKUP			= Object.fromEntries(
    [ ...BASE64_ALPHABET ].map( (c, i) => [ c, i ] )
);
// URL-safe characters are also accepted when decoding
BASE64_LOOKUP["-"]			= 62;
BASE64_LOOKUP["_"]			= 63;

// Max bytes that crypto.getRandomValues will fill in one call
const RANDOM_CHUNK_SIZE			= 65536;

// Multihash code and digest length for sha2-512
const SHA2_512_CODE			= 0x13;
const SHA2_512_LENGTH			= 64;


function randomBytes ( length ) {
    const bytes				= new Uint8Array( length );

    for ( let i = 0; i < length; i += RANDOM_CHUNK_SIZE )
	crypto.getRandomValues( bytes.subarray( i, i + RANDOM_CHUNK_SIZE ) );

    return bytes;
}

function toBytes ( value ) {
    if ( typeof value === "string" )
	return new TextEncoder().encode( value );
    if ( value instanceof ArrayBuffer )
	return new Uint8Array( value );

    return Uint8Array.from( value );
}

function concatBytes ( ...arrays ) {
    const bytes				= new Uint8Array( arrays.reduce( (n, a) => n + a.length, 0 ) );

    let offset				= 0;
    for ( const array of arrays ) {
	bytes.set( array, offset );
	offset			       += array.length;
    }

    return bytes;
}

function base64Encode ( bytes ) {
    let encoding			= "";

    for ( let i = 0; i < bytes.length; i += 3 ) {
	const n				= (bytes[i] << 16) | ((bytes[i+1] ?? 0) << 8) | (bytes[i+2] ?? 0);

	encoding		       += BASE64_ALPHABET[ (n >> 18) & 63 ]
	    + BASE64_ALPHABET[ (n >> 12) & 63 ]
	    + ( i + 1 < bytes.length ? BASE64_ALPHABET[ (n >> 6) & 63 ] : "=" )
	    + ( i + 2 < bytes.length ? BASE64_ALPHABET[ n & 63 ] : "=" );
    }

    return encoding;
}

// Lenient like Node's Buffer: accepts either alphabet, stops at padding, and skips unknown
// characters
function base64Decode ( encoding ) {
    const values			= [];

    for ( const c of encoding ) {
	if ( c === "=" )
	    break;
	if ( c in BASE64_LOOKUP )
	    values.push( BASE64_LOOKUP[c] );
    }

    const bytes				= new Uint8Array( Math.floor( values.length * 3 / 4 ) );

    let bits				= 0;
    let count				= 0;
    let index				= 0;
    for ( const value of values ) {
	bits				= (bits << 6) | value;
	count			       += 6;

	if ( count >= 8 ) {
	    count			       -= 8;
	    bytes[index++]		= (bits >> count) & 255;
	}
    }

    return bytes;
}

function readVarint ( bytes, offset ) {
    let value				= 0;
    let shift				= 0;

    while ( true ) {
	if ( offset >= bytes.length )
	    throw new Error("multihash too short");

	const byte			= bytes[offset++];
	value			       += (byte & 127) * 2 ** shift;
	shift			       += 7;

	if ( (byte & 128) === 0 )
	    return [ value, offset ];
    }
}


const Authentic_prefixes		= {
    CollectionID: {
	"v1": base64Decode("Auth/C1+"),		// [ 2, 235, 97, 252, 45, 126 ]
    },
    AccessKeyID: {
	"v1": base64Decode("Auth/K1+"),		// [ 2, 235, 97, 252, 173, 126 ]
    },
    CredentialID: {
	"v1": base64Decode("Auth/U1+"),		// [ 2, 235, 97, 253, 77, 126 ]
    },
};


class Authentic extends Uint8Array {
    [Symbol.toStringTag]		= Authentic.name;

    constructor ( length, bytes ) {
	super( length );

	if ( bytes === undefined )
	    bytes			= randomBytes( length );
	else if ( typeof bytes === "string" ) {
	    const decoded		= codecs.base64.decode( bytes );
	    const expected		= this.constructor.prefix;
	    const prefix		= decoded.subarray( 0, expected.length );

	    if ( !prefix.every( (byte, i) => byte === expected[i] ) || prefix.length !== expected.length )
		throw new Error(`expected prefix '${codecs.base64.encode( expected )}', found '${codecs.base64.encode( prefix )}'`);

	    bytes			= decoded.slice( expected.length );
	}

	this.set( bytes, 0 );
    }

    toString () {
	return codecs.base64.encode( concatBytes( this.constructor.prefix, this ) );
    }

    toJSON () {
	return this.toString();
    }
}

class C1 extends Authentic {
    [Symbol.toStringTag]		= C1.name;

    static prefix			= Authentic_prefixes.CollectionID.v1;
    static length			= 26;

    constructor ( bytes ) {
	super( C1.length, bytes );
    }
}

class K1 extends Authentic {
    [Symbol.toStringTag]		= K1.name;

    static prefix			= Authentic_prefixes.AccessKeyID.v1;
    static length			= 12;

    constructor( bytes, secret ) {
	if ( typeof bytes === "string" ) {
	    let pair			= bytes.split(".");

	    if ( pair.length !== 2 )
		throw new Error(`encoding expects 2 parts separated by '.', found ${pair.length} part(s)`);
	    if ( secret !== undefined )
		throw new Error(`Cannot specify argument[1] (secret) when decoding K1`);

	    bytes			= pair[0];
	    secret			= pair[1];
	}
	else if ( secret === undefined )
	    secret			= randomBytes( 46 );

	if ( typeof secret === "string" )
	    secret			= codecs.base64.decode( secret );

	super( K1.length, bytes );

	this.secret			= secret;
    }

    accessKey () {
	return [ this.toString(), codecs.base64.encode( this.secret ) ].join(".");
    }
}

class U1 extends Authentic {
    [Symbol.toStringTag]		= U1.name;

    static prefix			= Authentic_prefixes.CredentialID.v1;
    static length			= 26;

    constructor( bytes ) {
	super( U1.length, bytes );
    }
}


export const base64			= {
    encode ( bytes ) {
	if ( typeof bytes === "number" )
	    bytes			= randomBytes( bytes );

	return base64Encode( toBytes( bytes ) )
	    .replace(/\//g, "_")
	    .replace(/\+/g, "-");
    },
    decode ( encoding ) {
	return base64Decode( encoding );
    },
};

export const digest			= {
    encode ( bytes ) {
	const hash			= sha512( toBytes( bytes ) );
	return base64Encode( concatBytes( [ SHA2_512_CODE, hash.length ], hash ) );
    },
    decode ( encoding ) {
	const bytes			= base64Decode( encoding );
	const [ code, i ]		= readVarint( bytes, 0 );
	const [ length, start ]		= readVarint( bytes, i );

	if ( bytes.length - start !== length )
	    throw new Error("multihash length inconsistent");

	// Messages kept as-is from the previous implementation (placeholders are not filled)
	if ( code !== SHA2_512_CODE )
	    throw new Error("Multihash is expected to be 'sha2-512', not ${config.name}");
	if ( length !== SHA2_512_LENGTH )
	    throw new Error("sha2-512 digest should be 64 bytes, not ${config.length}");

	return bytes.slice( start );
    },
    verify ( bytes, digest ) {
	if ( typeof bytes === "string" )
	    bytes			= base64Decode( bytes );

	if ( typeof digest !== "string" )
	    digest			= base64Encode( toBytes( digest ) );

	return this.encode( bytes ) === digest;
    },
};

export const authentic			= {
    C1,
    K1,
    U1,
};

const codecs				= {
    base64,
    digest,
    authentic,
};

export default codecs;
