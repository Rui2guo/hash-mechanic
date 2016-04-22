package com.golaszewski.hash_mechanic;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.math3.util.ArithmeticUtils;
import org.bouncycastle.crypto.Digest;

/**
 * This data generator TODO
 * 
 * @author Ennis Golaszewski
 */
public class HighDensityGenerator {
	/**
	 * Generates an array of bytes for the purpose of testing a hash function.
	 * 
	 * @param digest
	 *            - the hash function to generate the bytes from.
	 * @param blocks
	 *            - the number of blocks to generate. See BLOCK_SIZE constant.
	 * @return an array of bytes.
	 */
	public byte[] generateBytes(Digest digest) {
		final int inputBytes = digest.getDigestSize() * 4;
		final int inputBits = inputBytes * Byte.SIZE;

		int outputOffset = 0;

		byte[] output = new byte[digest.getDigestSize() + (inputBits * digest.getDigestSize())
				+ (int) (ArithmeticUtils.binomialCoefficient(inputBits, 2) * digest.getDigestSize())];
		byte[] hash = new byte[digest.getDigestSize()];
		byte[] bits = new byte[inputBytes];
		byte[] oneOff = new byte[inputBytes];
		byte[] twoOff = new byte[inputBytes];

		for (int i = 0; i < bits.length; i++) {
			bits[i] = (byte) 0xFF;
		}

		System.out.println("Generating " + output.length + " bytes.");

		digest.update(bits, 0, bits.length);
		digest.doFinal(hash, 0);
		digest.reset();
		System.arraycopy(hash, 0, output, outputOffset, hash.length);
		outputOffset += digest.getDigestSize();

		for (int i = 0; i < inputBits; i++) {
			oneOff = toggleBit(bits, i);
			digest.update(oneOff, 0, oneOff.length);
			digest.doFinal(hash, 0);
			digest.reset();
			System.arraycopy(hash, 0, output, outputOffset, hash.length);
			outputOffset += digest.getDigestSize();
		}

		// We don't want to double up on hashes here.
		Set<BigInteger> existingHashes = new HashSet<BigInteger>();

		for (int i = 0; i < inputBits; i++) {
			oneOff = toggleBit(bits, i);
			for (int j = 0; j < inputBits; j++) {
				if (i != j) {
					twoOff = oneOff;
					twoOff = toggleBit(twoOff, j);
					digest.update(twoOff, 0, twoOff.length);
					digest.doFinal(hash, 0);
					digest.reset();

					// Write a hash only if we haven't already written it to the
					// output.
					if (!existingHashes.contains(new BigInteger(hash))) {
						existingHashes.add(new BigInteger(hash));
						System.arraycopy(hash, 0, output, outputOffset, hash.length);
						outputOffset += digest.getDigestSize();
					}
				}
			}
		}

		return output;
	}

	/**
	 * Toggles a bit in a byte array.
	 * 
	 * @param bytes
	 *            - the array of bytes. This input is not modified.
	 * @param position
	 *            - the index of the bit to flip.
	 * @return a new array reflecting the flipped bit.
	 */
	private byte[] toggleBit(byte[] bytes, int position) {
		byte[] result = new byte[bytes.length];

		for (int i = 0; i < bytes.length; i++) {
			result[i] = bytes[i];
		}

		int byteIndex = position / Byte.SIZE;
		result[byteIndex] ^= 1 << (Byte.SIZE - (position % Byte.SIZE) - 1);
		return result;
	}
}
