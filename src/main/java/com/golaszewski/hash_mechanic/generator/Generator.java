package com.golaszewski.hash_mechanic.generator;

import org.bouncycastle.crypto.Digest;

public abstract class Generator {
	/**
	 * Generates an array of bytes for the purpose of testing a hash function.
	 * 
	 * @param digest
	 *            - the hash function to generate the bytes from.
	 * @return an array of bytes.
	 */
	public abstract byte[] generateBytes(Digest digest);
	
	public abstract String getName();
	
	/**
	 * Toggles a bit in a byte array.
	 * 
	 * @param bytes
	 *            - the array of bytes. This input is not modified.
	 * @param position
	 *            - the index of the bit to flip.
	 * @return a new array reflecting the flipped bit.
	 */
	public static byte[] toggleBit(byte[] bytes, int position) {
		byte[] result = new byte[bytes.length];

		for (int i = 0; i < bytes.length; i++) {
			result[i] = bytes[i];
		}

		int byteIndex = position / Byte.SIZE;
		result[byteIndex] ^= 1 << (Byte.SIZE - (position % Byte.SIZE) - 1);
		return result;
	}
}
