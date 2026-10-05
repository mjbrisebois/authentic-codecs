import { expect }			from 'chai';

import codecs			from '../../src/index.js';

// Fixed inputs so that encodings can be compared against known values
const BYTES_26				= Uint8Array.from( { length: 26 }, (_, i) => i );
const BYTES_12				= Uint8Array.from( { length: 12 }, (_, i) => i + 100 );
const SECRET_46				= Uint8Array.from( { length: 46 }, (_, i) => 255 - i );

const C1_ENCODED			= "Auth_C1-AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBk=";
const U1_ENCODED			= "Auth_U1-AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBk=";
const K1_ENCODED			= "Auth_K1-ZGVmZ2hpamtsbW5v";
const K1_ACCESS_KEY			= K1_ENCODED + ".__79_Pv6-fj39vX08_Lx8O_u7ezr6uno5-bl5OPi4eDf3t3c29rZ2NfW1dTT0g==";

// sha2-512 multihash of "hello" (standard base64)
const HELLO_BYTES			= Uint8Array.from( [ 104, 101, 108, 108, 111 ] );
const HELLO_DIGEST			= "E0CbcdIkvWLzeF2W1GrT6j1zMZv7wokMqtri3/clGWc8pyMjw9mbpcEdfHrMbhS4xdoMRmNHXC5cOt70b3O83sBD";

function bytes ( value ) {
    return Array.from( value );
}

function c1_tests () {
    it("should create Authentic.C1 object", async () => {
	const resp			= new codecs.authentic.C1();

	expect( resp			).to.be.a("C1");
	expect( resp			).to.have.length( 26 );
    });

    it("should JSON stringify embeded Authentic.C1 object as a string", async () => {
	const resp			= JSON.parse( JSON.stringify({
	    "collection":	new codecs.authentic.C1(),
	}) );

	expect( resp.collection		).to.be.a("string");
	expect( resp.collection		).to.have.length( 44 );
    });

    it("should encode known bytes to a known string", async () => {
	const resp			= new codecs.authentic.C1( BYTES_26 );

	expect( resp.toString()		).to.equal( C1_ENCODED );
	expect( resp.toJSON()		).to.equal( C1_ENCODED );
	expect( bytes( resp )		).to.deep.equal( bytes( BYTES_26 ) );
    });

    it("should decode a known string to known bytes", async () => {
	const resp			= new codecs.authentic.C1( C1_ENCODED );

	expect( resp			).to.be.a("C1");
	expect( bytes( resp )		).to.deep.equal( bytes( BYTES_26 ) );
	expect( resp.toString()		).to.equal( C1_ENCODED );
    });

    it("should round-trip a random value", async () => {
	const original			= new codecs.authentic.C1();
	const resp			= new codecs.authentic.C1( original.toString() );

	expect( bytes( resp )		).to.deep.equal( bytes( original ) );
    });

    it("should fail to decode a string with another type's prefix", async () => {
	expect( () => new codecs.authentic.C1( K1_ENCODED ) ).to.throw( "expected prefix 'Auth_C1-', found 'Auth_K1-'" );
	expect( () => new codecs.authentic.C1( U1_ENCODED ) ).to.throw( "expected prefix 'Auth_C1-', found 'Auth_U1-'" );
    });

    it("should fail to decode a string that is too short", async () => {
	const truncated			= C1_ENCODED.slice( 0, -4 );

	expect( () => new codecs.authentic.C1( truncated ) ).to.throw( "expected 26 bytes after the prefix, found 24" );
    });

    it("should fail to decode a string that is too long", async () => {
	const extended			= codecs.base64.encode([ ...codecs.base64.decode( C1_ENCODED ), 0 ]);

	expect( () => new codecs.authentic.C1( extended ) ).to.throw( "expected 26 bytes after the prefix, found 27" );
    });
}

function k1_tests () {
    it("should create Authentic.K1 object", async () => {
	const resp			= new codecs.authentic.K1();

	expect( resp			).to.be.a("K1");
	expect( resp			).to.have.length( 12 );
	expect( resp.secret		).to.have.length( 46 );
    });

    it("should JSON stringify embeded Authentic.K1 object as a string", async () => {
	const resp			= JSON.parse( JSON.stringify({
	    "collection":	new codecs.authentic.K1(),
	}) );

	expect( resp.collection		).to.be.a("string");
	expect( resp.collection		).to.have.length( 24 );
    });

    it("should encode known bytes and secret to a known access key", async () => {
	const resp			= new codecs.authentic.K1( BYTES_12, SECRET_46 );

	expect( resp.toString()		).to.equal( K1_ENCODED );
	expect( resp.accessKey()	).to.equal( K1_ACCESS_KEY );
	expect( JSON.stringify( resp )	).to.equal( JSON.stringify( K1_ENCODED ) );
    });

    it("should decode a known access key to known bytes and secret", async () => {
	const resp			= new codecs.authentic.K1( K1_ACCESS_KEY );

	expect( resp			).to.be.a("K1");
	expect( bytes( resp )		).to.deep.equal( bytes( BYTES_12 ) );
	expect( bytes( resp.secret )	).to.deep.equal( bytes( SECRET_46 ) );
	expect( resp.accessKey()	).to.equal( K1_ACCESS_KEY );
    });

    it("should accept the secret as an encoded string", async () => {
	const secret			= K1_ACCESS_KEY.split(".")[1];
	const resp			= new codecs.authentic.K1( BYTES_12, secret );

	expect( bytes( resp.secret )	).to.deep.equal( bytes( SECRET_46 ) );
    });

    it("should round-trip a random access key", async () => {
	const original			= new codecs.authentic.K1();
	const resp			= new codecs.authentic.K1( original.accessKey() );

	expect( bytes( resp )		).to.deep.equal( bytes( original ) );
	expect( bytes( resp.secret )	).to.deep.equal( bytes( original.secret ) );
    });

    it("should fail to decode a string without a secret part", async () => {
	expect( () => new codecs.authentic.K1( K1_ENCODED ) ).to.throw( "encoding expects 2 parts separated by '.', found 1 part(s)" );
    });

    it("should fail to decode an access key with another type's prefix", async () => {
	const secret			= K1_ACCESS_KEY.split(".")[1];

	expect( () => new codecs.authentic.K1( C1_ENCODED + "." + secret ) ).to.throw( "expected prefix 'Auth_K1-', found 'Auth_C1-'" );
    });

    it("should fail to decode an access key whose ID is too short", async () => {
	const secret			= K1_ACCESS_KEY.split(".")[1];

	expect( () => new codecs.authentic.K1( K1_ENCODED.slice( 0, -4 ) + "." + secret ) ).to.throw( "expected 12 bytes after the prefix, found 9" );
    });

    it("should fail to decode a string when a secret argument is also given", async () => {
	expect( () => new codecs.authentic.K1( K1_ACCESS_KEY, SECRET_46 ) ).to.throw( "Cannot specify argument[1] (secret) when decoding K1" );
    });
}

function u1_tests () {
    it("should create Authentic.U1 object", async () => {
	const resp			= new codecs.authentic.U1();

	expect( resp			).to.be.a("U1");
	expect( resp			).to.have.length( 26 );
	expect( resp.toString()		).to.have.length( 44 );
    });

    it("should encode and decode known values", async () => {
	expect( new codecs.authentic.U1( BYTES_26 ).toString()		).to.equal( U1_ENCODED );
	expect( bytes( new codecs.authentic.U1( U1_ENCODED ) )		).to.deep.equal( bytes( BYTES_26 ) );
    });

    it("should fail to decode a string with another type's prefix", async () => {
	expect( () => new codecs.authentic.U1( C1_ENCODED ) ).to.throw( "expected prefix 'Auth_U1-', found 'Auth_C1-'" );
    });
}

function base64_tests () {
    it("should encode using the URL-safe alphabet", async () => {
	const resp			= codecs.base64.encode( Uint8Array.from([ 251, 255, 191, 0, 1 ]) );

	expect( resp			).to.equal( "-_-_AAE=" );
    });

    it("should decode the URL-safe alphabet", async () => {
	const resp			= codecs.base64.decode( "-_-_AAE=" );

	expect( bytes( resp )		).to.deep.equal( [ 251, 255, 191, 0, 1 ] );
    });

    it("should encode random bytes when given a number", async () => {
	const resp			= codecs.base64.encode( 5 );

	expect( resp			).to.have.length( 8 );
	expect( bytes( codecs.base64.decode( resp ) ) ).to.have.length( 5 );
    });
}

function digest_tests () {
    it("should encode a known sha2-512 multihash", async () => {
	expect( codecs.digest.encode( HELLO_BYTES ) ).to.equal( HELLO_DIGEST );
    });

    it("should decode a multihash to the 64 byte digest", async () => {
	const resp			= codecs.digest.decode( HELLO_DIGEST );

	expect( resp			).to.have.length( 64 );
	expect( bytes( resp )		).to.deep.equal( bytes( codecs.base64.decode( HELLO_DIGEST ) ).slice(2) );
    });

    it("should fail to decode a multihash that is not sha2-512", async () => {
	const sha256_multihash		= codecs.base64.encode( Uint8Array.from([ 0x12, 0x20, ...new Array(32).fill(0) ]) );

	expect( () => codecs.digest.decode( sha256_multihash ) ).to.throw( "Multihash is expected to be 'sha2-512', not code 0x12" );
    });

    it("should fail to decode a sha2-512 multihash with the wrong digest length", async () => {
	const short_multihash		= codecs.base64.encode( Uint8Array.from([ 0x13, 0x20, ...new Array(32).fill(0) ]) );

	expect( () => codecs.digest.decode( short_multihash ) ).to.throw( "sha2-512 digest should be 64 bytes, not 32" );
    });

    it("should verify bytes given as a base64 string against a string digest", async () => {
	expect( codecs.digest.verify( "aGVsbG8=", HELLO_DIGEST )	).to.be.true;
	expect( codecs.digest.verify( "aGVsbHg=", HELLO_DIGEST )	).to.be.false;
    });

    it("should verify bytes against a digest given as bytes", async () => {
	const digest			= codecs.base64.decode( HELLO_DIGEST );

	expect( codecs.digest.verify( HELLO_BYTES, digest )	).to.be.true;
    });
}

describe("Codecs", () => {

    describe("Authentic.C1", c1_tests );
    describe("Authentic.K1", k1_tests );
    describe("Authentic.U1", u1_tests );
    describe("base64", base64_tests );
    describe("digest", digest_tests );

});
