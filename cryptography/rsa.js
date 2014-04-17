var bignum = require('bignum');

var generate_keys = function(key_length, useDemoNumbers)
{
	var get_primes = function()
	{
		if (useDemoNumbers)
			return [bignum(13), bignum(11)];

		var p, q, safe=100;

		p = bignum.prime(key_length);
		while ((!q || !p.cmp(q)) && safe)
		{
			q = bignum.prime(key_length);
			safe--;
		}

		return [p, q];
	};

	var get_public_exponent = function(totient)
	{
		if (useDemoNumbers)
			return bignum(7);

		var key;
		while (!key || totient.gcd(key) != 1)
		{
			key = bignum.prime(key_length);
		}
		return key;
	};

	var get_private_exponent = function(public_exponent, totient)
	{
		return public_exponent.invertm(totient);
	};

	var primes = get_primes();
	var modulus = primes[0].mul(primes[1]);
	var totient = (primes[0].sub(1)).mul((primes[1]).sub(1));
	var public_exponent = get_public_exponent(totient);
	var private_exponent = get_private_exponent(public_exponent, totient);

	return {
		p: primes[0],
		q: primes[1],
		n: modulus,
		totient: totient,
		e: public_exponent,
		d: private_exponent
	};

};

var max_size = function(key_bit_length)
{
	return ((key_length * 2) / 8);
};

var encrypt = function(keys, buffer)
{
	// buffer -> hex -> bignum
	var num = bignum(buffer.toString('hex'), 16);

	// perform encryption
	var enc = num.powm(keys.e, keys.n);

	// bignum -> hex -> buffer
	var enc_buffer = new Buffer(enc.toString(16), 'hex');

	return enc_buffer;
};

var decrypt = function(keys, buffer)
{
	// buffer -> hex -> bignum
	var num = bignum(buffer.toString('hex'), 16);

	// perform decryption
	var dec = num.powm(keys.d, keys.n);

	// bignum -> hex -> buffer
	var dec_buffer = new Buffer(dec.toString(16), 'hex');

	return dec_buffer;

};

// show usage if no args are given
if (process.argv.length <= 2)
{
	console.log('Demonstrates the basics of how to perform RSA encryption and decryption');
	console.log('USAGE: node app.js <key length> <message>');
	return;
}

var key_length = parseInt(process.argv[2]);
var cleartext = process.argv[3];

// describe the relationship between our "key" size and the max input size
// and fail if too much input is given
var byteLength = Buffer.byteLength(cleartext);
console.log('                 SIZE DETAILS');
console.log('                 ============');
console.log('     key length:', key_length + ' bits');
console.log('     max length:', max_size(key_length) + ' bytes');
console.log('   input length:', byteLength*8 + ' bits (' + byteLength + ' bytes)');
console.log();
if (Buffer.byteLength(cleartext) * 8 > key_length * 2)
{
	console.log('          ERROR: A ' + key_length + '-bit key limits input to ' + max_size(key_length) + ' bytes, but more input was given');
	return;
}

// generate our keys
var keys = generate_keys(key_length, false);

// use our keys to encrypt a message
var encoded = new Buffer(cleartext);
var ciphertext = encrypt(keys, encoded);

// use our keys to decrypt the message
var decrypted = decrypt(keys, ciphertext);
var decoded = decrypted.toString();

// describe the results
console.log('                 KEY DETAILS');
console.log('                 ===========');
console.log('    prime1    p:', keys.p);
console.log('    prime2    q:', keys.q);
console.log('   modulus    n:', keys.n);
console.log('   totient ϕ(n):', keys.totient);
console.log('    public    e:', keys.e);
console.log('    private   d:', keys.d);
console.log('    coefficient:', keys.q.powm(-1, keys.p));
console.log();

console.log('                 MESSAGE');
console.log('                 =======');
console.log('        message:', cleartext);
console.log('        encoded:', encoded.toString('base64'));
console.log('         length:', encoded.length + ' bytes');
console.log('      encrypted:', ciphertext.toString('base64'));
console.log('      decrypted:', decrypted.toString('base64'));
console.log('        decoded:', decoded);
