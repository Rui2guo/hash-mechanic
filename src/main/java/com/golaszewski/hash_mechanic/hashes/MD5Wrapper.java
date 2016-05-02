package com.golaszewski.hash_mechanic.hashes;

import org.bouncycastle.crypto.Digest;

import com.golaszewski.hash_mechanic.hashes.thirdparty.MD5;

/**
 * Implements an MD5 digest compatible with the bouncycastle API by wrapping an
 * existing MD5 implementation.
 * 
 * @author Ennis Golaszewski
 */
public class MD5Wrapper implements Digest {
	public static final int DIGEST_SIZE = 16;
	public static final String DIGEST_NAME = "MD5";

	private MD5 digest;

	// We can optionally specify the number of rounds to hash.
	double nRounds = 0;

	/**
	 * Creates and initializes a new MD5 digest.
	 */
	public MD5Wrapper() {
		digest = new MD5();
	}

	/**
	 * Creates and initalizes an MD5 digest that runs only the specified number
	 * of rounds.
	 * 
	 * For MD5, this is any number in the set {1,2,3,4}.
	 * 
	 * @param nRounds
	 *            - the number of rounds. Invalid round numbers for this
	 *            algorithm are discarded.
	 */
	public MD5Wrapper(double nRounds) {
		digest = new MD5(nRounds);
		this.nRounds = nRounds;
	}

	/**
	 * Extracts and returns the hash.
	 * 
	 * @param out
	 *            - the array to write the hash bits to. Should have enough
	 *            space to hold the hash.
	 * 
	 * @param outOff
	 *            - the offset into the output array.
	 */
	public int doFinal(byte[] out, int outOff) {
		byte[] hash = digest.Final();
		System.arraycopy(hash, 0, out, outOff, DIGEST_SIZE);
		return DIGEST_SIZE;
	}

	public String getAlgorithmName() {
		return DIGEST_NAME;
	}

	public int getDigestSize() {
		return DIGEST_SIZE;
	}

	public void reset() {
		if (nRounds == 0) {
			digest = new MD5();
		} else {
			digest = new MD5(nRounds);
		}
	}

	public void update(byte in) {
		digest.Update(in);
	}

	public void update(byte[] in, int inOff, int inLen) {
		digest.Update(in, inOff, inLen);
	}

}
