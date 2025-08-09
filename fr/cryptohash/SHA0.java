// $Id: SHA0.java 214 2010-06-03 17:25:08Z tp $

package fr.cryptohash;

/**
 * <p>
 * This class implements the SHA-0 digest algorithm under the {@link
 * Digest} API. SHA-0 was defined by FIPS 180 (the original standard,
 * now obsolete).
 * </p>
 *
 * <pre>
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 * </pre>
 *
 * @version $Revision: 214 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

public class SHA0 extends MDHelper {

	/**
	 * Build the object.
	 */
	public SHA0() {
		super(false, 8);
	}

	private int[] currentVal;

	/** @see Digest */
	public Digest copy() {
		SHA0 d = new SHA0();
		System.arraycopy(currentVal, 0, d.currentVal, 0,
				currentVal.length);
		return copyState(d);
	}

	/** @see Digest */
	public int getDigestLength() {
		return 20;
	}

	/** @see Digest */
	public int getBlockLength() {
		return 64;
	}

	/** @see DigestEngine */
	protected void engineReset() {
		currentVal[0] = 0x67452301;
		currentVal[1] = 0xEFCDAB89;
		currentVal[2] = 0x98BADCFE;
		currentVal[3] = 0x10325476;
		currentVal[4] = 0xC3D2E1F0;
	}

	/** @see DigestEngine */
	protected void doPadding(byte[] output, int outputOffset) {
		makeMDPadding();
		for (int i = 0; i < 5; i++)
			encodeBEInt(currentVal[i],
					output, outputOffset + 4 * i);
	}

	/** @see DigestEngine */
	protected void doInit() {
		currentVal = new int[5];
		engineReset();
	}

	/**
	 * Encode the 32-bit word {@code val} into the array
	 * {@code buf} at offset {@code off}, in big-endian
	 * convention (most significant byte first).
	 *
	 * @param val the value to encode
	 * @param buf the destination buffer
	 * @param off the destination offset
	 */
	private static final void encodeBEInt(int val, byte[] buf, int off) {
		buf[off + 0] = (byte) (val >>> 24);
		buf[off + 1] = (byte) (val >>> 16);
		buf[off + 2] = (byte) (val >>> 8);
		buf[off + 3] = (byte) val;
	}

	/**
	 * Decode a 32-bit big-endian word from the array {@code buf}
	 * at offset {@code off}.
	 *
	 * @param buf the source buffer
	 * @param off the source offset
	 * @return the decoded value
	 */
	private static final int decodeBEInt(byte[] buf, int off) {
		return ((buf[off] & 0xFF) << 24)
				| ((buf[off + 1] & 0xFF) << 16)
				| ((buf[off + 2] & 0xFF) << 8)
				| (buf[off + 3] & 0xFF);
	}

	protected void processBlock(byte[] data) {
		int a = currentVal[0];
		int b = currentVal[1];
		int c = currentVal[2];
		int d = currentVal[3];
		int e = currentVal[4];

		int w0 = decodeBEInt(data, 0);
		e = ((a << 5) | (a >>> 27)) + ((b & c) | (~b & d))
				+ e + w0 + 0x5A827999;
		b = (b << 30) | (b >>> 2);
		int w1 = decodeBEInt(data, 4);
		d = ((e << 5) | (e >>> 27)) + ((a & b) | (~a & c))
				+ d + w1 + 0x5A827999;
		a = (a << 30) | (a >>> 2);
		int w2 = decodeBEInt(data, 8);
		c = ((d << 5) | (d >>> 27)) + ((e & a) | (~e & b))
				+ c + w2 + 0x5A827999;
		e = (e << 30) | (e >>> 2);
		int w3 = decodeBEInt(data, 12);
		b = ((c << 5) | (c >>> 27)) + ((d & e) | (~d & a))
				+ b + w3 + 0x5A827999;
		d = (d << 30) | (d >>> 2);
		int w4 = decodeBEInt(data, 16);
		a = ((b << 5) | (b >>> 27)) + ((c & d) | (~c & e))
				+ a + w4 + 0x5A827999;
		c = (c << 30) | (c >>> 2);
		int w5 = decodeBEInt(data, 20);
		e = ((a << 5) | (a >>> 27)) + ((b & c) | (~b & d))
				+ e + w5 + 0x5A827999;
		b = (b << 30) | (b >>> 2);
		int w6 = decodeBEInt(data, 24);
		d = ((e << 5) | (e >>> 27)) + ((a & b) | (~a & c))
				+ d + w6 + 0x5A827999;
		a = (a << 30) | (a >>> 2);
		int w7 = decodeBEInt(data, 28);
		c = ((d << 5) | (d >>> 27)) + ((e & a) | (~e & b))
				+ c + w7 + 0x5A827999;
		e = (e << 30) | (e >>> 2);
		int w8 = decodeBEInt(data, 32);
		b = ((c << 5) | (c >>> 27)) + ((d & e) | (~d & a))
				+ b + w8 + 0x5A827999;
		d = (d << 30) | (d >>> 2);
		int w9 = decodeBEInt(data, 36);
		a = ((b << 5) | (b >>> 27)) + ((c & d) | (~c & e))
				+ a + w9 + 0x5A827999;
		c = (c << 30) | (c >>> 2);
		int w10 = decodeBEInt(data, 40);
		e = ((a << 5) | (a >>> 27)) + ((b & c) | (~b & d))
				+ e + w10 + 0x5A827999;
		b = (b << 30) | (b >>> 2);
		int w11 = decodeBEInt(data, 44);
		d = ((e << 5) | (e >>> 27)) + ((a & b) | (~a & c))
				+ d + w11 + 0x5A827999;
		a = (a << 30) | (a >>> 2);
		int w12 = decodeBEInt(data, 48);
		c = ((d << 5) | (d >>> 27)) + ((e & a) | (~e & b))
				+ c + w12 + 0x5A827999;
		e = (e << 30) | (e >>> 2);
		int w13 = decodeBEInt(data, 52);
		b = ((c << 5) | (c >>> 27)) + ((d & e) | (~d & a))
				+ b + w13 + 0x5A827999;
		d = (d << 30) | (d >>> 2);
		int w14 = decodeBEInt(data, 56);
		a = ((b << 5) | (b >>> 27)) + ((c & d) | (~c & e))
				+ a + w14 + 0x5A827999;
		c = (c << 30) | (c >>> 2);
		int w15 = decodeBEInt(data, 60);
		e = ((a << 5) | (a >>> 27)) + ((b & c) | (~b & d))
				+ e + w15 + 0x5A827999;
		b = (b << 30) | (b >>> 2);

		w0 = w13 ^ w8 ^ w2 ^ w0;
		d = ((e << 5) | (e >>> 27)) + ((a & b) | (~a & c))
				+ d + w0 + 0x5A827999;
		a = (a << 30) | (a >>> 2);
		w1 = w14 ^ w9 ^ w3 ^ w1;
		c = ((d << 5) | (d >>> 27)) + ((e & a) | (~e & b))
				+ c + w1 + 0x5A827999;
		e = (e << 30) | (e >>> 2);
		w2 = w15 ^ w10 ^ w4 ^ w2;
		b = ((c << 5) | (c >>> 27)) + ((d & e) | (~d & a))
				+ b + w2 + 0x5A827999;
		d = (d << 30) | (d >>> 2);
		w3 = w0 ^ w11 ^ w5 ^ w3;
		a = ((b << 5) | (b >>> 27)) + ((c & d) | (~c & e))
				+ a + w3 + 0x5A827999;
		c = (c << 30) | (c >>> 2);
		w4 = w1 ^ w12 ^ w6 ^ w4;
		e = ((a << 5) | (a >>> 27)) + (b ^ c ^ d)
				+ e + w4 + 0x6ED9EBA1;
		b = (b << 30) | (b >>> 2);
		w5 = w2 ^ w13 ^ w7 ^ w5;
		d = ((e << 5) | (e >>> 27)) + (a ^ b ^ c)
				+ d + w5 + 0x6ED9EBA1;
		a = (a << 30) | (a >>> 2);
		w6 = w3 ^ w14 ^ w8 ^ w6;
		c = ((d << 5) | (d >>> 27)) + (e ^ a ^ b)
				+ c + w6 + 0x6ED9EBA1;
		e = (e << 30) | (e >>> 2);
		w7 = w4 ^ w15 ^ w9 ^ w7;
		b = ((c << 5) | (c >>> 27)) + (d ^ e ^ a)
				+ b + w7 + 0x6ED9EBA1;
		d = (d << 30) | (d >>> 2);
		w8 = w5 ^ w0 ^ w10 ^ w8;
		a = ((b << 5) | (b >>> 27)) + (c ^ d ^ e)
				+ a + w8 + 0x6ED9EBA1;
		c = (c << 30) | (c >>> 2);
		w9 = w6 ^ w1 ^ w11 ^ w9;
		e = ((a << 5) | (a >>> 27)) + (b ^ c ^ d)
				+ e + w9 + 0x6ED9EBA1;
		b = (b << 30) | (b >>> 2);
		w10 = w7 ^ w2 ^ w12 ^ w10;
		d = ((e << 5) | (e >>> 27)) + (a ^ b ^ c)
				+ d + w10 + 0x6ED9EBA1;
		a = (a << 30) | (a >>> 2);
		w11 = w8 ^ w3 ^ w13 ^ w11;
		c = ((d << 5) | (d >>> 27)) + (e ^ a ^ b)
				+ c + w11 + 0x6ED9EBA1;
		e = (e << 30) | (e >>> 2);
		w12 = w9 ^ w4 ^ w14 ^ w12;
		b = ((c << 5) | (c >>> 27)) + (d ^ e ^ a)
				+ b + w12 + 0x6ED9EBA1;
		d = (d << 30) | (d >>> 2);
		w13 = w10 ^ w5 ^ w15 ^ w13;
		a = ((b << 5) | (b >>> 27)) + (c ^ d ^ e)
				+ a + w13 + 0x6ED9EBA1;
		c = (c << 30) | (c >>> 2);
		w14 = w11 ^ w6 ^ w0 ^ w14;
		e = ((a << 5) | (a >>> 27)) + (b ^ c ^ d)
				+ e + w14 + 0x6ED9EBA1;
		b = (b << 30) | (b >>> 2);
		w15 = w12 ^ w7 ^ w1 ^ w15;
		d = ((e << 5) | (e >>> 27)) + ((a & b) | (a & c) | (b & c))
				+ d + w15 + 0x8F1BBCDC;
		a = (a << 30) | (a >>> 2);
		w0 = w13 ^ w8 ^ w2 ^ w0;
		c = ((d << 5) | (d >>> 27)) + ((e & a) | (e & b) | (a & b))
				+ c + w0 + 0x8F1BBCDC;
		e = (e << 30) | (e >>> 2);
		w1 = w14 ^ w9 ^ w3 ^ w1;
		b = ((c << 5) | (c >>> 27)) + ((d & e) | (d & a) | (e & a))
				+ b + w1 + 0x8F1BBCDC;
		d = (d << 30) | (d >>> 2);
		w2 = w15 ^ w10 ^ w4 ^ w2;
		a = ((b << 5) | (b >>> 27)) + ((c & d) | (c & e) | (d & e))
				+ a + w2 + 0x8F1BBCDC;
		c = (c << 30) | (c >>> 2);
		w3 = w0 ^ w11 ^ w5 ^ w3;
		e = ((a << 5) | (a >>> 27)) + ((b & c) | (b & d) | (c & d))
				+ e + w3 + 0x8F1BBCDC;
		b = (b << 30) | (b >>> 2);
		w4 = w1 ^ w12 ^ w6 ^ w4;
		d = ((e << 5) | (e >>> 27)) + ((a & b) | (a & c) | (b & c))
				+ d + w4 + 0x8F1BBCDC;
		a = (a << 30) | (a >>> 2);
		w5 = w2 ^ w13 ^ w7 ^ w5;
		c = ((d << 5) | (d >>> 27)) + ((e & a) | (e & b) | (a & b))
				+ c + w5 + 0x8F1BBCDC;
		e = (e << 30) | (e >>> 2);
		w6 = w3 ^ w14 ^ w8 ^ w6;
		b = ((c << 5) | (c >>> 27)) + ((d & e) | (d & a) | (e & a))
				+ b + w6 + 0x8F1BBCDC;
		d = (d << 30) | (d >>> 2);
		w7 = w4 ^ w15 ^ w9 ^ w7;
		a = ((b << 5) | (b >>> 27)) + ((c & d) | (c & e) | (d & e))
				+ a + w7 + 0x8F1BBCDC;
		c = (c << 30) | (c >>> 2);
		w8 = w5 ^ w0 ^ w10 ^ w8;
		e = ((a << 5) | (a >>> 27)) + (b ^ c ^ d)
				+ e + w8 + 0xCA62C1D6;
		b = (b << 30) | (b >>> 2);
		w9 = w6 ^ w1 ^ w11 ^ w9;
		d = ((e << 5) | (e >>> 27)) + (a ^ b ^ c)
				+ d + w9 + 0xCA62C1D6;
		a = (a << 30) | (a >>> 2);
		w10 = w7 ^ w2 ^ w12 ^ w10;
		c = ((d << 5) | (d >>> 27)) + (e ^ a ^ b)
				+ c + w10 + 0xCA62C1D6;
		e = (e << 30) | (e >>> 2);
		w11 = w8 ^ w3 ^ w13 ^ w11;
		b = ((c << 5) | (c >>> 27)) + (d ^ e ^ a)
				+ b + w11 + 0xCA62C1D6;
		d = (d << 30) | (d >>> 2);
		w12 = w9 ^ w4 ^ w14 ^ w12;
		a = ((b << 5) | (b >>> 27)) + (c ^ d ^ e)
				+ a + w12 + 0xCA62C1D6;
		c = (c << 30) | (c >>> 2);
		w13 = w10 ^ w5 ^ w15 ^ w13;
		e = ((a << 5) | (a >>> 27)) + (b ^ c ^ d)
				+ e + w13 + 0xCA62C1D6;
		b = (b << 30) | (b >>> 2);
		w14 = w11 ^ w6 ^ w0 ^ w14;
		d = ((e << 5) | (e >>> 27)) + (a ^ b ^ c)
				+ d + w14 + 0xCA62C1D6;
		a = (a << 30) | (a >>> 2);
		w15 = w12 ^ w7 ^ w1 ^ w15;
		c = ((d << 5) | (d >>> 27)) + (e ^ a ^ b)
				+ c + w15 + 0xCA62C1D6;
		e = (e << 30) | (e >>> 2);

		currentVal[0] += a;
		currentVal[1] += b;
		currentVal[2] += c;
		currentVal[3] += d;
		currentVal[4] += e;
	}

	/** @see Digest */
	public String toString() {
		return "SHA-0";
	}
}
