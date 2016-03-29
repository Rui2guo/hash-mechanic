package com.golaszewski.hash_mechanic;

import java.io.DataOutputStream;
import java.io.FileOutputStream;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.RIPEMD256Digest;
import org.bouncycastle.util.Arrays;

import com.golaszewski.hash_mechanic.hashes.BLAKE256Digest;

/**
 * This data generator TODO
 * 
 * @author Ennis Golaszewski
 */
public class HighDensityGenerator {
	public static final int BLOCK_SIZE = 256;

	/**
	 * Runs this generator.
	 * 
	 * @param args
	 *            - not used, there are no command line arguments at this time.
	 */
	public static void main(String[] args) {
		try {
			byte[] output;
			DataOutputStream ostream = new DataOutputStream(new FileOutputStream("output.dat"));
			output = new HighDensityGenerator().generateBytes(new BLAKE256Digest());

			System.out.println(output.length / 32);
			printResult(output);

			ostream.write(output);
			ostream.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
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
	public byte[] generateBytes(Digest digest) {
		final int blockBytes = BLOCK_SIZE / Byte.SIZE;
		int outputOffset = 0;
		byte[] output = new byte[blockBytes + (BLOCK_SIZE * BLOCK_SIZE * blockBytes)];
		byte[] hash = new byte[digest.getDigestSize()];
		byte[] bits = new byte[blockBytes];
		byte[] oneOff = new byte[blockBytes];
		byte[] twoOff = new byte[blockBytes];

		for (int i = 0; i < bits.length; i++) {
			bits[i] = (byte) 0xFF;
		}

		digest.update(bits, 0, bits.length);
		digest.doFinal(hash, 0);
		digest.reset();
		System.arraycopy(hash, 0, output, outputOffset, hash.length);
		outputOffset += blockBytes;

		for (int i = 0; i < BLOCK_SIZE; i++) {
			oneOff = toggleBit(bits, i);
			digest.update(oneOff, 0, oneOff.length);
			digest.doFinal(hash, 0);
			digest.reset();
			System.arraycopy(hash, 0, output, outputOffset, hash.length);
			outputOffset += blockBytes;
		}

		for (int i = 0; i < BLOCK_SIZE; i++) {
			oneOff = toggleBit(bits, i);
			for (int j = 0; j < BLOCK_SIZE; j++) {
				if (i != j) {
					twoOff = oneOff;
					twoOff = toggleBit(twoOff, j);
					digest.update(twoOff, 0, twoOff.length);
					digest.doFinal(hash, 0);
					digest.reset();
					System.arraycopy(hash, 0, output, outputOffset, hash.length);
					outputOffset += blockBytes;
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

	/**
	 * Prints out the resulting binary data.
	 * 
	 * @param result
	 *            - the hashed bits being generated.
	 */
	private static void printResult(byte[] result) {
		for (int i = 0; i < result.length; i += (BLOCK_SIZE / Byte.SIZE)) {
			byte[] block = Arrays.copyOfRange(result, i, i + 32);
			System.out.println(Hex.encodeHexString(block));
		}
	}
}
