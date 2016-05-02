package com.golaszewski.hash_mechanic.generator;

import org.bouncycastle.crypto.Digest;

public class TestGenerator extends Generator {

	@Override
	public byte[] generateBytes(Digest digest) {
		// We can multiply the input bytes to increase our message space for the
		// test.
		final int inputBytes = digest.getDigestSize();
		final int inputBits = inputBytes * Byte.SIZE;
		final int outputLength = inputBits;
		int outputOffset = 0;
		
		byte[] output = new byte[outputLength];
		byte[] hash = new byte[digest.getDigestSize()];
				
		System.out.println("Generating " + output.length + " bytes.");

		// Create all zero initialization vector.
		for (int i = 0; i < hash.length; i++) {
			hash[i] = (byte) 0x00;
		}
		
		// Chain as many hashes as needed and concatenate their bits.
		for (int i = 0; i < outputLength; i = i + inputBytes) {
			digest.update(hash, 0, hash.length);
			digest.doFinal(hash, 0);
			digest.reset();
			System.arraycopy(hash, 0, output, outputOffset, hash.length);
			outputOffset += digest.getDigestSize();
		}
		
		return output;
	}

	@Override
	public String getName() {
		return "test";
	}

}
