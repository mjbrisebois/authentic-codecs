const path				= require('path');
const log				= require('@whi/stdlog')(path.basename( __filename ), {
    level: process.env.LOG_LEVEL || 'fatal',
});

const crypto				= require('crypto');
const multihash				= require('multihashes');
const assert				= require('assert');

const Authentic_prefixes		= {
    CollectionID: {
	"v1": Buffer.from("Auth/C1+", "base64"),	// [ 2, 235, 97, 252, 45, 126 ]
    },
    AccessKeyID: {
	"v1": Buffer.from("Auth/K1+", "base64"),	// [ 2, 235, 97, 252, 173, 126 ]
    },
    CredentialID: {
	"v1": Buffer.from("Auth/U1+", "base64"),	// [ 2, 235, 97, 253, 77, 126 ]
    },
};

const code_type_map			= {
    "C1": {
	"prefix": Authentic_prefixes.CollectionID.v1,
	"length": 26, // 32 total
    },
    "K1": {
	"prefix": Authentic_prefixes.AccessKeyID.v1,
	"length": 12, // 16 total
    },
};

const prefix_code_map			= Object.entries( code_type_map )
      .reduce((o, [code,type]) => {
	  o[type.prefix] = code;
	  return o;
      }, {});


class Authentic extends Uint8Array {
    [Symbol.toStringTag]		= Authentic.name;

    constructor ( length, bytes ) {
	super( length );

	if ( bytes === undefined )
	    bytes			= crypto.randomBytes( length );
	else if ( typeof bytes === "string" )
	    bytes			= codecs.base64.decode( bytes ).slice(6);

	this.set( bytes, 0 );
	log.silly("New value for Authentic encoding %s: %s", this.constructor.name, this.toString() );
    }

    toString () {
	return codecs.base64.encode( Buffer.concat([ this.constructor.prefix, this ]) );
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

	    assert( pair.length === 2, `encoding expects 2 parts separated by '.', found ${pair.length} part(s)` );
	    assert( secret === undefined, `Cannot specify argument[1] (secret) when decoding K1` );

	    bytes			= pair[0];
	    secret			= pair[1];
	}
	else if ( secret === undefined )
	    secret			= crypto.randomBytes( 46 );

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

const authentic_codecs			= [C1, K1, U1];


const codecs				= {
    base64: {
	encode ( bytes ) {
	    if ( typeof bytes === "number" )
		bytes			= crypto.randomBytes( bytes );

	    return Buffer.from(bytes).toString("base64")
		.replace(/\//g, "_")
		.replace(/\+/g, "-");
	},
	decode ( encoding ) {
	    return Buffer.from(
		encoding
		    .replace(/\_/g, "/")
		    .replace(/\-/g, "+"),
		"base64"
	    );
	},
    },
    digest: {
	encode ( bytes ) {
	    const hash			= crypto.createHash("sha512");
	    hash.update( Buffer.from(bytes) );
	    return multihash.encode( hash.digest(), "sha2-512" ).toString("base64");
	},
	decode ( encoding ) {
	    const config		= multihash.decode( Buffer.from( encoding, "base64" ) );

	    assert( config.code === 19, "Multihash is expected to be 'sha2-512', not ${config.name}" );
	    assert( config.length === 64, "sha2-512 digest should be 64 bytes, not ${config.length}" );

	    return config.digest;
	},
	verify ( bytes, digest ) {
	    if ( typeof bytes === "string" )
		bytes			= Buffer.from( bytes, "base64" );

	    if ( typeof digest !== "string" )
		digest			= digest.toString("base64");

	    return this.encode( bytes ) === digest;
	},
    },
    authentic: {
	C1,
	K1,
	U1,
    },
};

module.exports				= codecs;
