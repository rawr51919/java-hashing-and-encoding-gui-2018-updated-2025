/*
 * Copyright (c) 1997 Systemics Ltd
 * on behalf of the Cryptix Development Team.  All rights reserved.
 */

package jcifs.util;

import java.security.MessageDigest;

/**
 * Implements the MD4 message digest algorithm in Java.
 * <p>
 * <b>References:</b>
 * <ol>
 * <li>Ronald L. Rivest,
 * "<a href="http://www.roxen.com/rfc/rfc1320.html">
 * The MD4 Message-Digest Algorithm</a>",
 * IETF RFC-1320 (informational).
 * </ol>
 *
 * <p>
 * <b>$Revision: 1.2 $</b>
 *
 * @author Raif S. Naffah
 */
public class MD4 extends MessageDigest implements Cloneable {
	// MD4 specific object variables
	// ...........................................................................

	private static final int BLOCK_LENGTH = 64; // = 512 / 8

	private int[] context = new int[4];

	private long count;

	private byte[] buffer = new byte[BLOCK_LENGTH];

	private int[] wordBuffer = new int[16];

	public MD4() {
		super("MD4");
		engineReset();
	}

	public MD4(MD4 md) {
		super("MD4");
		context = md.context.clone();
		buffer = md.buffer.clone();
		wordBuffer = md.wordBuffer.clone();
		count = md.count;
	}

	@Override
	@SuppressWarnings("squid:S2975")
	public Object clone() {
		try {
			MD4 cloned = (MD4) super.clone();
			cloned.context = context.clone();
			cloned.buffer = buffer.clone();
			cloned.wordBuffer = wordBuffer.clone();
			return cloned;
		} catch (CloneNotSupportedException e) {
			throw new AssertionError("MD4 should be cloneable", e);
		}
	}

	public void engineReset() {
		context[0] = 0x67452301;
		context[1] = 0xEFCDAB89;
		context[2] = 0x98BADCFE;
		context[3] = 0x10325476;
		count = 0L;
		for (int i = 0; i < BLOCK_LENGTH; i++)
			buffer[i] = 0;
	}

	public void engineUpdate(byte b) {
		int i = (int) (count % BLOCK_LENGTH);
		count++;
		buffer[i] = b;
		if (i == BLOCK_LENGTH - 1)
			transform(buffer, 0);
	}

	public void engineUpdate(byte[] input, int offset, int len) {
		if (offset < 0 || len < 0 || (long) offset + len > input.length)
			throw new ArrayIndexOutOfBoundsException();

		int bufferNdx = (int) (count % BLOCK_LENGTH);
		count += len;
		int partLen = BLOCK_LENGTH - bufferNdx;
		int i = 0;
		if (len >= partLen) {
			System.arraycopy(input, offset, buffer, bufferNdx, partLen);

			transform(buffer, 0);

			for (i = partLen; i + BLOCK_LENGTH - 1 < len; i += BLOCK_LENGTH)
				transform(input, offset + i);
			bufferNdx = 0;
		}
		if (i < len)
			System.arraycopy(input, offset + i, buffer, bufferNdx, len - i);
	}

	public byte[] engineDigest() {
		int bufferNdx = (int) (count % BLOCK_LENGTH);
		int padLen = (bufferNdx < 56) ? (56 - bufferNdx) : (120 - bufferNdx);

		byte[] tail = new byte[padLen + 8];
		tail[0] = (byte) 0x80;

		for (int i = 0; i < 8; i++)
			tail[padLen + i] = (byte) ((count * 8) >>> (8 * i));

		engineUpdate(tail, 0, tail.length);

		byte[] result = new byte[16];
		for (int i = 0; i < 4; i++)
			for (int j = 0; j < 4; j++)
				result[i * 4 + j] = (byte) (context[i] >>> (8 * j));

		engineReset();
		return result;
	}

	private void transform(byte[] block, int offset) {
		for (int i = 0; i < 16; i++)
			wordBuffer[i] = (block[offset++] & 0xFF) |
					(block[offset++] & 0xFF) << 8 |
					(block[offset++] & 0xFF) << 16 |
					(block[offset++] & 0xFF) << 24;

		int a = context[0];
		int b = context[1];
		int c = context[2];
		int d = context[3];

		a = ff(a, b, c, d, wordBuffer[0], 3);
		d = ff(d, a, b, c, wordBuffer[1], 7);
		c = ff(c, d, a, b, wordBuffer[2], 11);
		b = ff(b, c, d, a, wordBuffer[3], 19);
		a = ff(a, b, c, d, wordBuffer[4], 3);
		d = ff(d, a, b, c, wordBuffer[5], 7);
		c = ff(c, d, a, b, wordBuffer[6], 11);
		b = ff(b, c, d, a, wordBuffer[7], 19);
		a = ff(a, b, c, d, wordBuffer[8], 3);
		d = ff(d, a, b, c, wordBuffer[9], 7);
		c = ff(c, d, a, b, wordBuffer[10], 11);
		b = ff(b, c, d, a, wordBuffer[11], 19);
		a = ff(a, b, c, d, wordBuffer[12], 3);
		d = ff(d, a, b, c, wordBuffer[13], 7);
		c = ff(c, d, a, b, wordBuffer[14], 11);
		b = ff(b, c, d, a, wordBuffer[15], 19);

		a = gg(a, b, c, d, wordBuffer[0], 3);
		d = gg(d, a, b, c, wordBuffer[4], 5);
		c = gg(c, d, a, b, wordBuffer[8], 9);
		b = gg(b, c, d, a, wordBuffer[12], 13);
		a = gg(a, b, c, d, wordBuffer[1], 3);
		d = gg(d, a, b, c, wordBuffer[5], 5);
		c = gg(c, d, a, b, wordBuffer[9], 9);
		b = gg(b, c, d, a, wordBuffer[13], 13);
		a = gg(a, b, c, d, wordBuffer[2], 3);
		d = gg(d, a, b, c, wordBuffer[6], 5);
		c = gg(c, d, a, b, wordBuffer[10], 9);
		b = gg(b, c, d, a, wordBuffer[14], 13);
		a = gg(a, b, c, d, wordBuffer[3], 3);
		d = gg(d, a, b, c, wordBuffer[7], 5);
		c = gg(c, d, a, b, wordBuffer[11], 9);
		b = gg(b, c, d, a, wordBuffer[15], 13);

		a = hh(a, b, c, d, wordBuffer[0], 3);
		d = hh(d, a, b, c, wordBuffer[8], 9);
		c = hh(c, d, a, b, wordBuffer[4], 11);
		b = hh(b, c, d, a, wordBuffer[12], 15);
		a = hh(a, b, c, d, wordBuffer[2], 3);
		d = hh(d, a, b, c, wordBuffer[10], 9);
		c = hh(c, d, a, b, wordBuffer[6], 11);
		b = hh(b, c, d, a, wordBuffer[14], 15);
		a = hh(a, b, c, d, wordBuffer[1], 3);
		d = hh(d, a, b, c, wordBuffer[9], 9);
		c = hh(c, d, a, b, wordBuffer[5], 11);
		b = hh(b, c, d, a, wordBuffer[13], 15);
		a = hh(a, b, c, d, wordBuffer[3], 3);
		d = hh(d, a, b, c, wordBuffer[11], 9);
		c = hh(c, d, a, b, wordBuffer[7], 11);
		b = hh(b, c, d, a, wordBuffer[15], 15);

		context[0] += a;
		context[1] += b;
		context[2] += c;
		context[3] += d;
	}

	private int ff(int p1, int p2, int p3, int p4, int x, int s) {
		int t = p1 + ((p2 & p3) | (~p2 & p4)) + x;
		return (t << s) | (t >>> (32 - s));
	}

	private int gg(int p1, int p2, int p3, int p4, int x, int s) {
		int t = p1 + ((p2 & (p3 | p4)) | (p3 & p4)) + x + 0x5A827999;
		return (t << s) | (t >>> (32 - s));
	}

	private int hh(int p1, int p2, int p3, int p4, int x, int s) {
		int t = p1 + (p2 ^ p3 ^ p4) + x + 0x6ED9EBA1;
		return (t << s) | (t >>> (32 - s));
	}
}
