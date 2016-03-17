package com.golaszewski.hash_mechanic.hashes;

import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

public class BLAKE256Test {
	public static final String SINGLE_BLOCK_EXPECTED_HASH = "0CE8D4EF4DD7CD8D62DFDED9D4EDB0A774AE6A41929A74DA23109E8F11139C87";
	public static final String DOUBLE_BLOCK_EXPECTED_HASH = "D419BAD32D504FB7D44D460C42C5593FE544FA4C135DEC31E21BD9ABDCC22D41";

	public static final String INPUT_0_BITS = "";
	public static final String INPUT_24_BITS = "abc";
	public static final String INPUT_448_BITS = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	public static final String INPUT_896_BITS = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
	public static final String INPUT_1M_BITS = new String(new char[1000000]).replace('\0', 'a');

	// These expected hashes were calculated using the BLAKE256 reference
	// implementation.
	public static final String B_0_EXPECTED_HASH = "716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a";
	public static final String B_24_EXPECTED_HASH = "1833a9fa7cf4086bd5fda73da32e5a1d75b4c3f89d5c436369f9d78bb2da5c28";
	public static final String B_448_EXPECTED_HASH = "adb13cb0da78463d36fcf40def3f291b3f0673e78127bdb70942cdd640b907b4";
	public static final String B_896_EXPECTED_HASH = "8f69d890786569cc878e9995a0ebf5e319746482ab56b8184fec5267190e6ade";
	public static final String B_1M_EXPECTED_HASH = "22be6de4aa4214c9403f10598f0a6b0e834570251a13bc27589437f7139a5d44";

	@Test
	public void singleBlockTestVector() throws DecoderException {
		final byte[] expected = Hex.decodeHex(SINGLE_BLOCK_EXPECTED_HASH.toCharArray());
		final int inLen = 1;

		BLAKE256 blake = new BLAKE256();
		byte[] in = new byte[inLen];
		byte[] out = new byte[blake.getDigestSize()];
		blake.update(in, 0, inLen);
		blake.doFinal(out, 0);
		assertTrue(Arrays.equals(out, expected));
	}

	@Test
	public void doubleBlockTestVector() throws DecoderException {
		final byte[] expected = Hex.decodeHex(DOUBLE_BLOCK_EXPECTED_HASH.toCharArray());
		final int inLen = 72;

		BLAKE256 blake = new BLAKE256();
		byte[] in = new byte[inLen];
		byte[] out = new byte[blake.getDigestSize()];
		blake.update(in, 0, inLen);
		blake.doFinal(out, 0);
		assertTrue(Arrays.equals(out, expected));
	}

	@Test
	public void BitCount0() throws DecoderException {
		doTest(INPUT_0_BITS, B_0_EXPECTED_HASH);
	}

	@Test
	public void BitCount24() throws DecoderException {
		doTest(INPUT_24_BITS, B_24_EXPECTED_HASH);
	}
	
	@Test
	public void BitCount448() throws DecoderException {
		doTest(INPUT_448_BITS, B_448_EXPECTED_HASH);
	}
	
	@Test
	public void BitCount896() throws DecoderException {
		doTest(INPUT_896_BITS, B_896_EXPECTED_HASH);
	}
	
	@Test
	public void BitCount1M() throws DecoderException {
		doTest(INPUT_1M_BITS, B_1M_EXPECTED_HASH);
	}

	private void doTest(String input, String expectedHash) throws DecoderException {
		final byte[] expected = Hex.decodeHex(expectedHash.toCharArray());
		final int inLen = input.length();

		BLAKE256 blake = new BLAKE256();
		byte[] in = input.getBytes();
		byte[] out = new byte[blake.getDigestSize()];
		blake.update(in, 0, inLen);
		blake.doFinal(out, 0);
		assertTrue(Arrays.equals(out, expected));
	}
}
