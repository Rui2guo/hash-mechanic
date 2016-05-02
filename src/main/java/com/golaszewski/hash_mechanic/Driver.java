package com.golaszewski.hash_mechanic;

import java.io.File;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Arrays;

import com.golaszewski.hash_mechanic.generator.Generator;
import com.golaszewski.hash_mechanic.generator.HashChainGenerator;
import com.golaszewski.hash_mechanic.generator.HighDensityGenerator;
import com.golaszewski.hash_mechanic.generator.LowDensityGenerator;
import com.golaszewski.hash_mechanic.hashes.MD5Wrapper;
import com.google.common.io.Files;

public class Driver {

	/**
	 * Runs this generator.
	 * 
	 * @param args
	 *            - not used, there are no command line arguments at this time.
	 */
	public static void main(String[] args) {
		for (double i = 0.5; i <= 4; i += 0.5) {
			doTest(new LowDensityGenerator(), new MD5Wrapper(i), i);
			doTest(new HighDensityGenerator(), new MD5Wrapper(i), i);
			doTest(new HashChainGenerator(), new MD5Wrapper(i), i);
		}
	}

	public static byte[] doTest(Generator generator, Digest digest, double nRounds) {
		try {
			byte[] output;
			output = generator.generateBytes(digest);
			// printResult(output, digest.getDigestSize());
			Files.write(output, generateFile(digest.getAlgorithmName(), generator.getName(), nRounds));
			return output;
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException("Error in writing file!");
		}
	}

	public static File generateFile(String algorithm, String testName, double nRounds) {
		String path = algorithm + "." + testName + "." + nRounds + ".dat";
		return new File(path);
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
