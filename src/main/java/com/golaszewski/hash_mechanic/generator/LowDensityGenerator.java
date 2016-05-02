package com.golaszewski.hash_mechanic.generator;

import org.apache.commons.math3.util.ArithmeticUtils;
import org.bouncycastle.crypto.Digest;

/**
 * This data generator TODO
 * 
 * @author Ennis Golaszewski
 */
public class LowDensityGenerator extends Generator {

	@Override
	public byte[] generateBytes(Digest digest) {
		// We can multiply the input bytes to increase our message space for the
		// test.
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
			bits[i] = (byte) 0x00;
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

		boolean[][] hashed = new boolean[inputBits][inputBits];

		for (int i = 0; i < inputBits; i++) {
			for (int j = 0; j < inputBits; j++) {
				hashed[i][j] = false;
			}
		}

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
					if (!hashed[i][j]) {
						hashed[i][j] = true;
						hashed[j][i] = true;
						System.arraycopy(hash, 0, output, outputOffset, hash.length);
						outputOffset += digest.getDigestSize();
					}
				}
			}
		}

		return output;
	}

	@Override
	public String getName() {
		return "lowdensity";
	}
}
