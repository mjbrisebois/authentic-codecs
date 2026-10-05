// Runs the mocha test suite inside the Cloudflare Workers runtime (workerd) with no
// compatibility flags, so any use of Node-only APIs fails the same way it would in a Worker
// that has not enabled Node.js compatibility.
//
//     node scripts/test-workerd.js
//
import { readdirSync }			from 'node:fs';
import path				from 'node:path';
import { fileURLToPath }		from 'node:url';
import * as esbuild			from 'esbuild';
import { Miniflare }			from 'miniflare';

const ROOT				= path.resolve( path.dirname( fileURLToPath( import.meta.url ) ), ".." );
const TESTS_DIR				= path.join( ROOT, "tests" );

// Must not be later than the workerd release bundled with miniflare
const COMPATIBILITY_DATE		= "2026-07-30";

const test_files			= readdirSync( TESTS_DIR, { recursive: true } )
      .filter( file => /(^|\/)test_[^/]*\.js$/.test( file ) )
      .sort()
      .map( file => "./" + file );

// Mocha's browser build defines the describe/it globals during setup. Imports are evaluated
// before the importing module's body, so setup lives in its own module imported ahead of the
// test files.
const setup				= `
import "mocha/mocha.js";
const mocha = globalThis.mocha;
// mocha.run() reads URL query options from the page location, which a Worker does not have
globalThis.location ??= { search: "" };
mocha.setup({ ui: "bdd", reporter: function () {} });
export default mocha;
`;

// A fetch handler runs the suite and returns the results
const entry				= `
import mocha from "workerd-setup";
${ test_files.map( file => `import ${JSON.stringify( file )};` ).join("\n") }

export default {
    async fetch () {
	const results		= [];
	await new Promise( resolve => {
	    const runner	= mocha.run( resolve );
	    runner.on( "pass", test => results.push({ title: test.fullTitle(), passed: true }) );
	    runner.on( "fail", (test, err) => results.push({
		title: test.fullTitle(),
		passed: false,
		error: String( err && err.stack || err ),
	    }) );
	});
	return Response.json( results );
    },
};
`;

const bundle				= await esbuild.build({
    stdin: {
	contents:	entry,
	resolveDir:	TESTS_DIR,
	sourcefile:	"workerd-entry.js",
    },
    bundle:		true,
    format:		"esm",
    platform:		"neutral",
    mainFields:		[ "browser", "module", "main" ],
    conditions:		[ "workerd", "worker", "browser" ],
    plugins:		[{
	name: "workerd-setup",
	setup ( build ) {
	    build.onResolve( { filter: /^workerd-setup$/ }, args => ({ path: args.path, namespace: "workerd-setup" }) );
	    build.onLoad( { filter: /.*/, namespace: "workerd-setup" }, () => ({ contents: setup, resolveDir: TESTS_DIR }) );
	},
    }],
    write:		false,
    logLevel:		"warning",
});

const mf				= new Miniflare({
    modules:		true,
    script:		bundle.outputFiles[0].text,
    compatibilityDate:	COMPATIBILITY_DATE,
});

let results;
try {
    const response			= await mf.dispatchFetch("http://localhost/");

    if ( !response.ok )
	throw new Error(`Test worker failed (${response.status}):\n${await response.text()}`);

    results				= await response.json();
} finally {
    await mf.dispose();
}

for ( const result of results ) {
    console.log( `${result.passed ? "  ✓" : "  ✗"} ${result.title}` );
    if ( !result.passed )
	console.log( result.error.replace( /^/gm, "      " ) );
}

const failed				= results.filter( result => !result.passed ).length;

console.log(`\n  workerd: ${results.length - failed} passing, ${failed} failing`);

if ( failed > 0 || results.length === 0 )
    process.exitCode			= 1;
