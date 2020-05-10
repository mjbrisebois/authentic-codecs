const path				= require('path');
const log				= require('@whi/stdlog')(path.basename( __filename ), {
    level: process.env.LOG_LEVEL || 'fatal',
});

const expect				= require('chai').expect;

const codecs				= require('../../src/index.js');

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
}

describe("Codecs", () => {

    describe("Authentic.C1", c1_tests );
    describe("Authentic.K1", k1_tests );

});
