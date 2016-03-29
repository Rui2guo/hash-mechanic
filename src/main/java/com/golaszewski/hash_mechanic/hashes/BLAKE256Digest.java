package com.golaszewski.hash_mechanic.hashes;

import java.nio.ByteBuffer;
import java.util.Arrays;

import org.bouncycastle.crypto.Digest;

/**
 * Implementation of BLAKE-256 hash function.
 * 
 * WARNING: This implementation does not currently support hashing over 2^32
 * bits.
 * 
 * @author Ennis Golaszewski
 */
public class BLAKE256Digest implements Digest {
	public static final int NUM_ROUNDS = 14;

	/**
	 * Provides a name-string for the algorithm.
	 */
	public static final String ALGORITHM_NAME = "BLAKE-256";

	/**
	 * The size of the digest in bytes.
	 */
	public static final int DIGEST_SIZE = 256 / Byte.SIZE;

	/**
	 * Array of initial hashing values. These are identical to the ones used in
	 * SHA-256.
	 */
	public static final int[] IV = { 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
			0x5BE0CD19 };

	/**
	 * Array of constant values. These are specified in the BLAKE-256
	 * specification.
	 */
	public static final int[] C = { 0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 0xA4093822, 0x299F31D0, 0x082EFA98,
			0xEC4E6C89, 0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C, 0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5,
			0xB5470917 };

	/**
	 * Represents the table of {0, ... , 15} permutations used by BLAKE
	 * functions.
	 */
	public static final int[][] S = { { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
			{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
			{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
			{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
			{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
			{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
			{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
			{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
			{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
			{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 } };

	/**
	 * Indicates the size of the message block in bits.
	 */
	public static final int MESSAGE_BLOCK_BITS = 512;

	private static final byte SINGLE_BYTE_PADDING = (byte) 0x81;
	private static final byte FINAL_BYTE_PADDING = (byte) 0x01;
	private static final byte[] PADDING = { (byte) 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	// Digest state variables.
	private int[] h;
	private int[] s;
	private int[] t;
	private int bufferLength;
	private byte[] buffer;
	private boolean paddingBlock;

	public BLAKE256Digest() {
		reset();
	}

	public int doFinal(byte[] out, int outOff) {
		if (outOff != 0) {
			throw new RuntimeException("Output offsets are not supported!");
		}

		int low = t[0] + bufferLength * Byte.SIZE;
		int high = t[1];

		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putInt(high);
		buffer.putInt(low);

		// TODO omitting step to handle hashing more than 2^32 bits. This isn't
		// necessary for our current use case.

		// If we just need to add one padding byte, we update with a single byte
		// padding.
		if (bufferLength == 55) {
			t[0] -= 8;
			update(new byte[] { SINGLE_BYTE_PADDING }, 0, 1);
		} else {
			// We have enough space to fill the block with the padding.
			if (bufferLength < 55) {
				// If the buffer is empty, we're dealing with a padding only
				// block.
				if (bufferLength == 0) {
					paddingBlock = true;
				}
				t[0] -= 440 - (bufferLength * Byte.SIZE);
				update(PADDING, 0, 55 - bufferLength);
				// If we do not have enough space, we will need to update twice.
			} else {
				t[0] -= 512 - (bufferLength * Byte.SIZE);
				update(PADDING, 0, 64 - bufferLength);
				t[0] -= 440;
				update(Arrays.copyOfRange(PADDING, 1, PADDING.length), 0, 55);
				paddingBlock = true;
			}

			update(new byte[] { FINAL_BYTE_PADDING }, 0, 1);
			t[0] -= 8;
		}

		t[0] -= 64;
		update(buffer.array(), 0, Long.BYTES);

		System.arraycopy(ByteBuffer.allocate(Integer.BYTES).putInt(h[0]).array(), 0, out, 0, 4);
		System.arraycopy(ByteBuffer.allocate(Integer.BYTES).putInt(h[1]).array(), 0, out, 4, 4);
		System.arraycopy(ByteBuffer.allocate(Integer.BYTES).putInt(h[2]).array(), 0, out, 8, 4);
		System.arraycopy(ByteBuffer.allocate(Integer.BYTES).putInt(h[3]).array(), 0, out, 12, 4);
		System.arraycopy(ByteBuffer.allocate(Integer.BYTES).putInt(h[4]).array(), 0, out, 16, 4);
		System.arraycopy(ByteBuffer.allocate(Integer.BYTES).putInt(h[5]).array(), 0, out, 20, 4);
		System.arraycopy(ByteBuffer.allocate(Integer.BYTES).putInt(h[6]).array(), 0, out, 24, 4);
		System.arraycopy(ByteBuffer.allocate(Integer.BYTES).putInt(h[7]).array(), 0, out, 28, 4);

		return DIGEST_SIZE;
	}

	public String getAlgorithmName() {
		return ALGORITHM_NAME;
	}

	public int getDigestSize() {
		return DIGEST_SIZE;
	}

	public void reset() {
		h = new int[8];
		s = new int[4];
		t = new int[2];
		buffer = new byte[64];

		// Update state with initialization vectors.
		h[0] = IV[0];
		h[1] = IV[1];
		h[2] = IV[2];
		h[3] = IV[3];
		h[4] = IV[4];
		h[5] = IV[5];
		h[6] = IV[6];
		h[7] = IV[7];

		// Reset counters.
		t[0] = 0;
		t[1] = 0;
		bufferLength = 0;

		// Reset the seed.
		s[0] = 0;
		s[1] = 0;
		s[2] = 0;
		s[3] = 0;

		paddingBlock = false;
	}

	public void update(byte in) {
		update(new byte[] { in }, 0, 1);
	}

	public void update(byte[] in, int inOff, int inLen) {
		int left = bufferLength;
		int fill = 64 - left;

		// There is data remaining and we have enough to fill a block.
		if (left != 0 && (inLen >= fill)) {
			System.arraycopy(in, inOff, buffer, left, fill);

			t[0] += MESSAGE_BLOCK_BITS;
			// If t[0] has overflowed, we increment t[1].
			if (t[0] <= 0) {
				t[1]++;
			}

			compress(buffer);
			inOff += fill;
			inLen -= fill;
			left = 0;
		}

		// Compress data block-by-block
		while (inLen >= 64) {
			t[0] += MESSAGE_BLOCK_BITS;

			// If t[0] has overflowed, we increment t[1].
			if (t[0] <= 0) {
				t[1]++;
			}

			byte[] bits = Arrays.copyOfRange(in, inOff, inOff + MESSAGE_BLOCK_BITS / Byte.SIZE);
			compress(bits);

			inOff += 64;
			inLen -= 64;
		}

		if (inLen > 0) {
			System.arraycopy(in, inOff, buffer, left, inLen);
			bufferLength = left + inLen;
		} else {
			bufferLength = 0;
		}
	}

	private void compress(byte[] in) {
		int[] m = convertMessage(in);
		int[] v = new int[16];

		// Initialize v, the 16-word state that will be mutated by the round
		// function G. The initialization process is
		// taken directly from the BLAKE-256 specification.
		v[0] = h[0];
		v[1] = h[1];
		v[2] = h[2];
		v[3] = h[3];
		v[4] = h[4];
		v[5] = h[5];
		v[6] = h[6];
		v[7] = h[7];
		v[8] = s[0] ^ C[0];
		v[9] = s[1] ^ C[1];
		v[10] = s[2] ^ C[2];
		v[11] = s[3] ^ C[3];
		v[12] = C[4];
		v[13] = C[5];
		v[14] = C[6];
		v[15] = C[7];

		if (!paddingBlock) {
			v[12] ^= t[0];
			v[13] ^= t[0];
			v[14] ^= t[1];
			v[15] ^= t[1];
		}

		// Iterate a series of 14 rounds, each round consisting of eight calls
		// to the transformation function g of i,
		// represented by G().
		for (int r = 0; r < NUM_ROUNDS; r++) {
			G(v, m, 0, 4, 8, 12, 0, r);
			G(v, m, 1, 5, 9, 13, 1, r);
			G(v, m, 2, 6, 10, 14, 2, r);
			G(v, m, 3, 7, 11, 15, 3, r);
			G(v, m, 0, 5, 10, 15, 4, r);
			G(v, m, 1, 6, 11, 12, 5, r);
			G(v, m, 2, 7, 8, 13, 6, r);
			G(v, m, 3, 4, 9, 14, 7, r);
		}

		// Finalize the process by updating our chain value H.
		updateChainValue(v);
	}

	/**
	 * Updates the chain value as the last step of the compression function.
	 */
	protected void updateChainValue(int[] v) {
		h[0] = h[0] ^ s[0] ^ v[0] ^ v[8];
		h[1] = h[1] ^ s[1] ^ v[1] ^ v[9];
		h[2] = h[2] ^ s[2] ^ v[2] ^ v[10];
		h[3] = h[3] ^ s[3] ^ v[3] ^ v[11];
		h[4] = h[4] ^ s[0] ^ v[4] ^ v[12];
		h[5] = h[5] ^ s[1] ^ v[5] ^ v[13];
		h[6] = h[6] ^ s[2] ^ v[6] ^ v[14];
		h[7] = h[7] ^ s[3] ^ v[7] ^ v[15];
	}

	/**
	 * Applies the round function G to the state.
	 */
	protected void G(int[] v, int[] m, int a, int b, int c, int d, int i, int r) {
		// We only have 10 permutations of {1, ..., 15}. We always want to index
		// one of them.
		r = r % 10;
		// Every operation here will multiply i * 2, so we simply do this up
		// front.
		i = i * 2;

		v[a] = v[a] + v[b] + (m[S[r][i]] ^ C[S[r][i + 1]]);
		v[d] = rot(v[d] ^ v[a], 16);
		v[c] = v[c] + v[d];
		v[b] = rot(v[b] ^ v[c], 12);
		v[a] = v[a] + v[b] + (m[S[r][i + 1]] ^ C[S[r][i]]);
		v[d] = rot(v[d] ^ v[a], 8);
		v[c] = v[c] + v[d];
		v[b] = rot(v[b] ^ v[c], 7);
	}

	/**
	 * Performs an unsigned circular rotation of an integer.
	 * 
	 * @param x
	 *            - the integer to rotate.
	 * @param n
	 *            - the number of bits for the rotation.
	 */
	private int rot(int x, int n) {
		return (x >>> n) | (x << (Integer.SIZE - n));
	}

	/**
	 * Converts a message buffer representation from bytes to integers.
	 * 
	 * @param in
	 *            - a byte buffer.
	 * @return an integer buffer with bitwise equivalence to the byte buffer.
	 */
	private int[] convertMessage(byte[] in) {
		int[] m = new int[16];
		ByteBuffer buffer = ByteBuffer.wrap(in);

		for (int j = 0; j < m.length; j++) {
			m[j] = buffer.getInt();
		}

		return m;
	}
}
