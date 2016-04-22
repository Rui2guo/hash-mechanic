package com.golaszewski.hash_mechanic;

import java.io.File;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Arrays;

import com.golaszewski.hash_mechanic.hashes.BLAKE256Digest;
import com.golaszewski.hash_mechanic.hashes.BRAKE256Digest;
import com.google.common.io.Files;

public class Driver {

	/**
	 * Runs this generator.
	 * 
	 * @param args
	 *            - not used, there are no command line arguments at this time.
	 */
	public static void main(String[] args) {
		doHighDensityTest(new BLAKE256Digest());
		doHighDensityTest(new BRAKE256Digest());
	}

	public static void doHighDensityTest(Digest digest) {
		try {
			byte[] output;
			output = new HighDensityGenerator().generateBytes(digest);
			// printResult(output, digest.getDigestSize());
			Files.write(output, new File(digest.getAlgorithmName() + ".dat"));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Prints out the resulting binary data.
	 * 
	 * @param result
	 *            - the hashed bits being generated.
	 */
	public static void printResult(byte[] result, int blockSize) {
		for (int i = 0; i < result.length; i += blockSize) {
			byte[] block = Arrays.copyOfRange(result, i, i + blockSize);
			System.out.println(Hex.encodeHexString(block));
		}
	}
}
