import * as crypto from 'crypto'
const bip39 = require('bip39');
const scrypt = require('scrypt');
const ethUtil = require('ethereumjs-util');

export const PrivateKeySizeBytes = 32;

// Memory required = OutputSize * WorkFactor_N * Blocksize_r
// 	(64*(2^17)*16) = 134217728 == 128MB
//
// Ran on a 2.3GHz Intel Core i7 / 16GB RAM
//  t = 0.95sec
//
// See: http://stackoverflow.com/a/30308723 for more details
const ScryptWorkFactor_N = Math.pow(2,17);
const ScryptBlocksize_r = 16;
const ScryptParallelization_p = 1;
const ScryptOutputSize = 64;

// As defined here: https://github.com/ethereum/wiki/wiki/Brain-Wallet
const BrainWalletRepetitions = 16384;

export interface WalletGenerator {
	generate(): WalletInterface;
	fromMneomic(mneomic: string): WalletInterface;
	fromBrainSeed(seed: string, salt: string): WalletInterface;
}

export interface WalletInterface {
	getAddress(): Buffer;
	getAddressString(): string;
	getChecksumAddressString(): string;
}

export class Wallet implements WalletGenerator, WalletInterface {

	protected _privateKey: Buffer;
	public _publicKey: Buffer;

	get publicKey(): Buffer {
		if (this._privateKey && !this._publicKey) {
			this._publicKey = ethUtil.privateToPublic(this._privateKey);
		}
		return this._publicKey;
	}

	constructor(privateKey?: Buffer) {
		if (privateKey && !ethUtil.isValidPrivate(privateKey)) {
			throw new Error('Invalid private key supplied');
		}
		this._privateKey = privateKey;
	}

	// Generates a new private key from random bytes
	public generate(): Wallet {
		this._privateKey = crypto.randomBytes(PrivateKeySizeBytes);

		return this;
	}

	// Takes a mneomic string and converts it into a wallet private key as defined in BIP39:
	//
	// 	https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
	//
	// Additionally cuts the key down to size (from 64 bytes to 32) to work nicely with private key validators
	public fromMneomic(mneomic: string): Wallet {
		let largeSeed: Buffer = bip39.mnemonicToSeed(mneomic);
		this._privateKey = largeSeed.slice(0,PrivateKeySizeBytes);

		return this;
	}

	// Takes a user created seed and a salt (suggestion: username, or user identifier) and generates a deterministic
	// wallet, aka Brain Wallet.
	//
	// Spec: https://github.com/ethereum/wiki/wiki/Brain-Wallet
	//
	// Added an additional KDF function using scrypt as suggested
	// in the notes
	public fromBrainSeed(seed: string, salt: string): Wallet {
		let strectchedSeed: Buffer = scrypt.hashSync(seed, {
				"N": ScryptWorkFactor_N,
				"r": ScryptBlocksize_r,
				"p": ScryptParallelization_p
			}, ScryptOutputSize, salt);

		let hashedSeed: Buffer = ethUtil.sha3(strectchedSeed);
		for (var i = 1; i <= BrainWalletRepetitions; i++) {
			hashedSeed = ethUtil.sha3(hashedSeed);
		}

		while (ethUtil.privateToAddress(hashedSeed)[0] !== 0) {
			hashedSeed = ethUtil.sha3(hashedSeed)
		}

		this._privateKey = hashedSeed;

		return this;
	}

	public getAddress(): Buffer {
		return ethUtil.pubToAddress(this.publicKey);
	}

	public getAddressString(): string {
		return ethUtil.bufferToHex(this.getAddress());
	}

	// Returns wallet address in checksum format
	public getChecksumAddressString(): string {
		return ethUtil.toChecksumAddress(this.getAddressString());
	}
}

