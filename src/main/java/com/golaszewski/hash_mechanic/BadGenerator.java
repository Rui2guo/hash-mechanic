package com.golaszewski.hash_mechanic;

import java.util.Random;

import org.bouncycastle.crypto.Digest;

/**
 * This data generator intentionally creates output to be as un-random as
 * possible.
 * 
 * @author Ennis Golaszewski
 */
public class BadGenerator {
	public static final int BLOCK_SIZE = 128;
	private Random random;

	/**
	 * Creates an instance of this generator with the specified random seed.
	 * 
	 * @param seed
	 *            - the random seed.
	 */
	public BadGenerator(long seed) {
		random = new Random(seed);
	}

	/**
	 * Generates an array of bytes for the purpose of testing a hash function.
	 * 
	 * @param digest
	 *            - the hash function to generate the bytes from.
	 * @param blocks
	 *            - the number of blocks to generate. See BLOCK_SIZE constant.
	 * @return an array of bytes.
	 */
	public byte[] generateBytes(Digest digest, int blocks) {
		return null;
	}
}
