import * as assert from 'assert'
import { Wallet, PrivateKeySizeBytes } from './index'

describe('Wallet', () => {
	it('errors when constructed with invalid private key', () => {
		assert.throws(() => {new Wallet(new Buffer('abcd', 'hex'));});
	});

	it('sets private key when constructed with valid private key', () => {
		assert.doesNotThrow(() => {new Wallet(new Buffer('3aab1f76070347d7fadb2d3335ed2801ea8e12c3a5ad91b4310ef7a4cac56976', 'hex'));});
	});

	it('generates a wallet with a private key set', () => {
		let wallet: WalletTestHarness = new WalletTestHarness();

		wallet.generate();

		assert.equal(wallet.privateKey.length, PrivateKeySizeBytes);
	});

	it('frombrainseed deterministically generates wallet private key', (done) => {
		var seed = 'password123';
		var salt = 'user123';

		let wallet1: WalletTestHarness = new WalletTestHarness();
		let wallet2: WalletTestHarness = new WalletTestHarness();

		wallet1.fromBrainSeed(seed, salt);
		wallet2.fromBrainSeed(seed, salt);

		assert.equal(wallet1.privateKey.toString('hex'), wallet2.privateKey.toString('hex'));
		done();
	}).timeout(3500);

	it('generates public key from existing private key', () => {
		let wallet: WalletTestHarness = new WalletTestHarness();

		wallet.generate();

		assert.ok(wallet.publicKey);
	});

	it('converts a mneomic to private key', () => {
		let wallet: WalletTestHarness = new WalletTestHarness();
		var mneomic = 'basket rival lemon';
		var expectedPrivateKey = 'ebf53ff3af1617e4f42d6857fab2040fbc12decbdfae0a4ab3bb5e5e1910cfca';

		wallet.fromMneomic(mneomic);

		assert.equal(wallet.privateKey.toString('hex'), expectedPrivateKey);
	});

	it('frommneomic deterministically generates wallet private key', () => {
		var mneomic = 'basket rival lemon';

		let wallet1: WalletTestHarness = new WalletTestHarness();
		let wallet2: WalletTestHarness = new WalletTestHarness();

		wallet1.fromMneomic(mneomic);
		wallet2.fromMneomic(mneomic);

		assert.equal(wallet1.privateKey.toString('hex'), wallet2.privateKey.toString('hex'));
	});

	it('returns address from public key', () => {
		let wallet: Wallet = new Wallet();
		var mneomic = 'basket rival lemon';
		var expectedAddress = "0x28337258df6a190b2adf666c0b3b7ae57667adcd";

		wallet.fromMneomic(mneomic);

		assert.equal(wallet.getAddressString(), expectedAddress);
	});

	it('returns checksumed address from public key', () => {
		let wallet: Wallet = new Wallet();
		var mneomic = 'basket rival lemon';
		var expectedAddress = "0x28337258dF6a190b2adf666c0B3b7Ae57667AdCd";

		wallet.fromMneomic(mneomic);

		assert.equal(wallet.getChecksumAddressString(), expectedAddress);
	});
});

class WalletTestHarness extends Wallet {
	get privateKey(): Buffer {
		return this._privateKey;
	}
}
