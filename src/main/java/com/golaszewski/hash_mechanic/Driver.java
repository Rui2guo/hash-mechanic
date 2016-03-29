package com.golaszewski.hash_mechanic;

import java.io.DataOutputStream;
import java.io.FileOutputStream;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.util.Arrays;

public class Driver {

	/**
	 * Runs this generator.
	 * 
	 * @param args
	 *            - not used, there are no command line arguments at this time.
	 */
	public static void main(String[] args) {
		try {
			byte[] output;
			Digest digest = new MD5Digest();
			DataOutputStream ostream = new DataOutputStream(new FileOutputStream(digest.getAlgorithmName() + ".dat"));
			output = new HighDensityGenerator().generateBytes(digest);

			System.out.println(output.length / digest.getDigestSize());
			printResult(output, digest.getDigestSize());

			ostream.write(output);
			ostream.close();
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
	private static void printResult(byte[] result, int blockSize) {
		for (int i = 0; i < result.length; i += blockSize) {
			byte[] block = Arrays.copyOfRange(result, i, i + blockSize);
			System.out.println(Hex.encodeHexString(block));
		}
	}
}
