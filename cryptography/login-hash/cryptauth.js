var crypto = require('crypto');

var HASH_ITERATIONS = 25000,
	// HASH_STRATEGY = 'PBKDF2';
	HASH_STRATEGY = 'sha512';

var users = {};

var salty = function(bits)
{
	return crypto.randomBytes(bits / 8).toString('base64');
};

var hashify = function(salt, cleartext)
{
	var clear = salt + ':' + cleartext;

	var start = new Date().getTime();

	switch (HASH_STRATEGY)
	{
		case 'PBKDF2':
			var hash = crypto.pbkdf2Sync(cleartext, salt, HASH_ITERATIONS, 64).toString('base64');
			break;

		case 'SHA512-RSA':
			for (var i=0; i<HASH_ITERATIONS; ++i)
			{
				// create SHA512 hash
				var hashMaker = crypto.createHash('sha512WithRSAEncryption');
				hashMaker.update(clear);
				var hash = hashMaker.digest('base64');
			}
			break;

		case 'SHA512':
		default:
			for (var i=0; i<HASH_ITERATIONS; ++i)
			{
				// create SHA512 hash
				var hashMaker = crypto.createHash('sha512');
				hashMaker.update(clear);
				var hash = hashMaker.digest('base64');
			}
			break;
	}

	console.log('                 HASH COMPLETE');
	console.log('                 =============');
	console.log('      strategy:  ' + HASH_STRATEGY);
	console.log('    iterations:  ' + HASH_ITERATIONS);
	// console.log('          salt:  ' + salt);
	// console.log('     cleartext:  ' + cleartext);
	console.log('        string:  ' + clear);
	console.log('          hash:  ' + hash);
	console.log('   hash length:  ' + (new Buffer(hash, 'base64').toString('ascii').length) * 8 + ' bits');
	console.log('      duration:  ' + (new Date().getTime() - start) + ' ms');

	return hash;
};

var slow_compare = function(a, b)
{
	var ba = new Buffer(a, 'hex');
	var bb = new Buffer(b, 'hex');

	// constant-time comparator equals
	var diff = ba.length ^ bb.length;
	for (var i=0; i<ba.length && i<bb.length; ++i)
		diff |= ba[i] ^ bb[i];

	return (diff == 0);
	
};

exports.users = function()
{
	return users;
}

exports.register = function(username, password)
{
	var salt = salty(512);

	users[username] = {
		salt: salt,
		hash: hashify(salt, password)
	};
};

exports.authenticate = function(username, password)
{
	if (!users[username])
		return false;

	var userdata = users[username];

	var authenticated = slow_compare(users[username].hash, hashify(users[username].salt, password));

	// update some login stats
	if (authenticated)
	{
		users[username].total = (users[username].total || 0) + 1;
		users[username].dates = users[username].dates || [];
		users[username].dates.push(new Date());
	}

	return authenticated;
};