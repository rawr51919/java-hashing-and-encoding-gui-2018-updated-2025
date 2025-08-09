// $Id: RIPEMD.java 214 2010-06-03 17:25:08Z tp $

package fr.cryptohash;

/**
 * <p>
 * This class implements the RIPEMD digest algorithm under the {@link
 * Digest} API. This is the original RIPEMD, <strong>not</strong> the
 * strengthened variants RIPEMD-128 or RIPEMD-160. A collision for this
 * RIPEMD has been published in 2004.
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

public class RIPEMD extends MDHelper {

  private int[] currentVal;
  private int[] x;  // Renamed from X

  public RIPEMD() {
    super(true, 8);
  }

  /** @see Digest */
  public Digest copy() {
    RIPEMD d = new RIPEMD();
    System.arraycopy(currentVal, 0, d.currentVal, 0, currentVal.length);
    return copyState(d);
  }

  /** @see Digest */
  public int getDigestLength() {
    return 16;
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
  }

  /** @see DigestEngine */
  protected void doPadding(byte[] output, int outputOffset) {
    makeMDPadding();
    for (int i = 0; i < 4; i++)
      encodeLEInt(currentVal[i], output, outputOffset + 4 * i);
  }

  /** @see DigestEngine */
  protected void doInit() {
    currentVal = new int[4];
    x = new int[16];
    engineReset();
  }

  private static final void encodeLEInt(int val, byte[] buf, int off) {
    buf[off + 0] = (byte) val;
    buf[off + 1] = (byte) (val >>> 8);
    buf[off + 2] = (byte) (val >>> 16);
    buf[off + 3] = (byte) (val >>> 24);
  }

  private static final int decodeLEInt(byte[] buf, int off) {
    return (buf[off + 0] & 0xFF)
        | ((buf[off + 1] & 0xFF) << 8)
        | ((buf[off + 2] & 0xFF) << 16)
        | ((buf[off + 3] & 0xFF) << 24);
  }

  /** @see DigestEngine */
  protected void processBlock(byte[] data) {
    int a1;
	int b1;
	int c1;
	int d1;
    int a2;
	int b2;
	int c2;
	int d2;
    int tmp;

    a1 = a2 = currentVal[0];
    b1 = b2 = currentVal[1];
    c1 = c2 = currentVal[2];
    d1 = d2 = currentVal[3];

    for (int i = 0, j = 0; i < 16; i++, j += 4)
      x[i] = decodeLEInt(data, j);

    tmp = a1 + (((c1 ^ d1) & b1) ^ d1) + x[0];
    a1 = (tmp << 11) | (tmp >>> (32 - 11));
    tmp = d1 + (((b1 ^ c1) & a1) ^ c1) + x[1];
    d1 = (tmp << 14) | (tmp >>> (32 - 14));
    tmp = c1 + (((a1 ^ b1) & d1) ^ b1) + x[2];
    c1 = (tmp << 15) | (tmp >>> (32 - 15));
    tmp = b1 + (((d1 ^ a1) & c1) ^ a1) + x[3];
    b1 = (tmp << 12) | (tmp >>> (32 - 12));
    tmp = a1 + (((c1 ^ d1) & b1) ^ d1) + x[4];
    a1 = (tmp << 5) | (tmp >>> (32 - 5));
    tmp = d1 + (((b1 ^ c1) & a1) ^ c1) + x[5];
    d1 = (tmp << 8) | (tmp >>> (32 - 8));
    tmp = c1 + (((a1 ^ b1) & d1) ^ b1) + x[6];
    c1 = (tmp << 7) | (tmp >>> (32 - 7));
    tmp = b1 + (((d1 ^ a1) & c1) ^ a1) + x[7];
    b1 = (tmp << 9) | (tmp >>> (32 - 9));
    tmp = a1 + (((c1 ^ d1) & b1) ^ d1) + x[8];
    a1 = (tmp << 11) | (tmp >>> (32 - 11));
    tmp = d1 + (((b1 ^ c1) & a1) ^ c1) + x[9];
    d1 = (tmp << 13) | (tmp >>> (32 - 13));
    tmp = c1 + (((a1 ^ b1) & d1) ^ b1) + x[10];
    c1 = (tmp << 14) | (tmp >>> (32 - 14));
    tmp = b1 + (((d1 ^ a1) & c1) ^ a1) + x[11];
    b1 = (tmp << 15) | (tmp >>> (32 - 15));
    tmp = a1 + (((c1 ^ d1) & b1) ^ d1) + x[12];
    a1 = (tmp << 6) | (tmp >>> (32 - 6));
    tmp = d1 + (((b1 ^ c1) & a1) ^ c1) + x[13];
    d1 = (tmp << 7) | (tmp >>> (32 - 7));
    tmp = c1 + (((a1 ^ b1) & d1) ^ b1) + x[14];
    c1 = (tmp << 9) | (tmp >>> (32 - 9));
    tmp = b1 + (((d1 ^ a1) & c1) ^ a1) + x[15];
    b1 = (tmp << 8) | (tmp >>> (32 - 8));

    tmp = a1 + ((b1 & c1) | ((b1 | c1) & d1)) + x[7] + 0x5A827999;
    a1 = (tmp << 7) | (tmp >>> (32 - 7));
    tmp = d1 + ((a1 & b1) | ((a1 | b1) & c1)) + x[4] + 0x5A827999;
    d1 = (tmp << 6) | (tmp >>> (32 - 6));
    tmp = c1 + ((d1 & a1) | ((d1 | a1) & b1)) + x[13] + 0x5A827999;
    c1 = (tmp << 8) | (tmp >>> (32 - 8));
    tmp = b1 + ((c1 & d1) | ((c1 | d1) & a1)) + x[1] + 0x5A827999;
    b1 = (tmp << 13) | (tmp >>> (32 - 13));
    tmp = a1 + ((b1 & c1) | ((b1 | c1) & d1)) + x[10] + 0x5A827999;
    a1 = (tmp << 11) | (tmp >>> (32 - 11));
    tmp = d1 + ((a1 & b1) | ((a1 | b1) & c1)) + x[6] + 0x5A827999;
    d1 = (tmp << 9) | (tmp >>> (32 - 9));
    tmp = c1 + ((d1 & a1) | ((d1 | a1) & b1)) + x[15] + 0x5A827999;
    c1 = (tmp << 7) | (tmp >>> (32 - 7));
    tmp = b1 + ((c1 & d1) | ((c1 | d1) & a1)) + x[3] + 0x5A827999;
    b1 = (tmp << 15) | (tmp >>> (32 - 15));
    tmp = a1 + ((b1 & c1) | ((b1 | c1) & d1)) + x[12] + 0x5A827999;
    a1 = (tmp << 7) | (tmp >>> (32 - 7));
    tmp = d1 + ((a1 & b1) | ((a1 | b1) & c1)) + x[0] + 0x5A827999;
    d1 = (tmp << 12) | (tmp >>> (32 - 12));
    tmp = c1 + ((d1 & a1) | ((d1 | a1) & b1)) + x[9] + 0x5A827999;
    c1 = (tmp << 15) | (tmp >>> (32 - 15));
    tmp = b1 + ((c1 & d1) | ((c1 | d1) & a1)) + x[5] + 0x5A827999;
    b1 = (tmp << 9) | (tmp >>> (32 - 9));
    tmp = a1 + ((b1 & c1) | ((b1 | c1) & d1)) + x[14] + 0x5A827999;
    a1 = (tmp << 7) | (tmp >>> (32 - 7));
    tmp = d1 + ((a1 & b1) | ((a1 | b1) & c1)) + x[2] + 0x5A827999;
    d1 = (tmp << 11) | (tmp >>> (32 - 11));
    tmp = c1 + ((d1 & a1) | ((d1 | a1) & b1)) + x[11] + 0x5A827999;
    c1 = (tmp << 13) | (tmp >>> (32 - 13));
    tmp = b1 + ((c1 & d1) | ((c1 | d1) & a1)) + x[8] + 0x5A827999;
    b1 = (tmp << 12) | (tmp >>> (32 - 12));

    tmp = a1 + (b1 ^ c1 ^ d1) + x[3] + 0x6ED9EBA1;
    a1 = (tmp << 11) | (tmp >>> (32 - 11));
    tmp = d1 + (a1 ^ b1 ^ c1) + x[10] + 0x6ED9EBA1;
    d1 = (tmp << 13) | (tmp >>> (32 - 13));
    tmp = c1 + (d1 ^ a1 ^ b1) + x[2] + 0x6ED9EBA1;
    c1 = (tmp << 14) | (tmp >>> (32 - 14));
    tmp = b1 + (c1 ^ d1 ^ a1) + x[4] + 0x6ED9EBA1;
    b1 = (tmp << 7) | (tmp >>> (32 - 7));
    tmp = a1 + (b1 ^ c1 ^ d1) + x[9] + 0x6ED9EBA1;
    a1 = (tmp << 14) | (tmp >>> (32 - 14));
    tmp = d1 + (a1 ^ b1 ^ c1) + x[15] + 0x6ED9EBA1;
    d1 = (tmp << 9) | (tmp >>> (32 - 9));
    tmp = c1 + (d1 ^ a1 ^ b1) + x[8] + 0x6ED9EBA1;
    c1 = (tmp << 13) | (tmp >>> (32 - 13));
    tmp = b1 + (c1 ^ d1 ^ a1) + x[1] + 0x6ED9EBA1;
    b1 = (tmp << 15) | (tmp >>> (32 - 15));
    tmp = a1 + (b1 ^ c1 ^ d1) + x[14] + 0x6ED9EBA1;
    a1 = (tmp << 6) | (tmp >>> (32 - 6));
    tmp = d1 + (a1 ^ b1 ^ c1) + x[7] + 0x6ED9EBA1;
    d1 = (tmp << 8) | (tmp >>> (32 - 8));
    tmp = c1 + (d1 ^ a1 ^ b1) + x[0] + 0x6ED9EBA1;
    c1 = (tmp << 13) | (tmp >>> (32 - 13));
    tmp = b1 + (c1 ^ d1 ^ a1) + x[6] + 0x6ED9EBA1;
    b1 = (tmp << 6) | (tmp >>> (32 - 6));
    tmp = a1 + (b1 ^ c1 ^ d1) + x[11] + 0x6ED9EBA1;
    a1 = (tmp << 12) | (tmp >>> (32 - 12));
    tmp = d1 + (a1 ^ b1 ^ c1) + x[13] + 0x6ED9EBA1;
    d1 = (tmp << 5) | (tmp >>> (32 - 5));
    tmp = c1 + (d1 ^ a1 ^ b1) + x[5] + 0x6ED9EBA1;
    c1 = (tmp << 7) | (tmp >>> (32 - 7));
    tmp = b1 + (c1 ^ d1 ^ a1) + x[12] + 0x6ED9EBA1;
    b1 = (tmp << 5) | (tmp >>> (32 - 5));

    tmp = a2 + (((c2 ^ d2) & b2) ^ d2) + x[0] + 0x50A28BE6;
    a2 = (tmp << 11) | (tmp >>> (32 - 11));
    tmp = d2 + (((b2 ^ c2) & a2) ^ c2) + x[1] + 0x50A28BE6;
    d2 = (tmp << 14) | (tmp >>> (32 - 14));
    tmp = c2 + (((a2 ^ b2) & d2) ^ b2) + x[2] + 0x50A28BE6;
    c2 = (tmp << 15) | (tmp >>> (32 - 15));
    tmp = b2 + (((d2 ^ a2) & c2) ^ a2) + x[3] + 0x50A28BE6;
    b2 = (tmp << 12) | (tmp >>> (32 - 12));
    tmp = a2 + (((c2 ^ d2) & b2) ^ d2) + x[4] + 0x50A28BE6;
    a2 = (tmp << 5) | (tmp >>> (32 - 5));
    tmp = d2 + (((b2 ^ c2) & a2) ^ c2) + x[5] + 0x50A28BE6;
    d2 = (tmp << 8) | (tmp >>> (32 - 8));
    tmp = c2 + (((a2 ^ b2) & d2) ^ b2) + x[6] + 0x50A28BE6;
    c2 = (tmp << 7) | (tmp >>> (32 - 7));
    tmp = b2 + (((d2 ^ a2) & c2) ^ a2) + x[7] + 0x50A28BE6;
    b2 = (tmp << 9) | (tmp >>> (32 - 9));
    tmp = a2 + (((c2 ^ d2) & b2) ^ d2) + x[8] + 0x50A28BE6;
    a2 = (tmp << 11) | (tmp >>> (32 - 11));
    tmp = d2 + (((b2 ^ c2) & a2) ^ c2) + x[9] + 0x50A28BE6;
    d2 = (tmp << 13) | (tmp >>> (32 - 13));
    tmp = c2 + (((a2 ^ b2) & d2) ^ b2) + x[10] + 0x50A28BE6;
    c2 = (tmp << 14) | (tmp >>> (32 - 14));
    tmp = b2 + (((d2 ^ a2) & c2) ^ a2) + x[11] + 0x50A28BE6;
    b2 = (tmp << 15) | (tmp >>> (32 - 15));
    tmp = a2 + (((c2 ^ d2) & b2) ^ d2) + x[12] + 0x50A28BE6;
    a2 = (tmp << 6) | (tmp >>> (32 - 6));
    tmp = d2 + (((b2 ^ c2) & a2) ^ c2) + x[13] + 0x50A28BE6;
    d2 = (tmp << 7) | (tmp >>> (32 - 7));
    tmp = c2 + (((a2 ^ b2) & d2) ^ b2) + x[14] + 0x50A28BE6;
    c2 = (tmp << 9) | (tmp >>> (32 - 9));
    tmp = b2 + (((d2 ^ a2) & c2) ^ a2) + x[15] + 0x50A28BE6;
    b2 = (tmp << 8) | (tmp >>> (32 - 8));

    tmp = a2 + ((b2 & d2) | (c2 & ~d2)) + x[7] + 0x5C4DD124;
    a2 = (tmp << 7) | (tmp >>> (32 - 7));
    tmp = d2 + ((a2 & c2) | (b2 & ~c2)) + x[4] + 0x5C4DD124;
    d2 = (tmp << 6) | (tmp >>> (32 - 6));
    tmp = c2 + ((d2 & b2) | (a2 & ~b2)) + x[13] + 0x5C4DD124;
    c2 = (tmp << 8) | (tmp >>> (32 - 8));
    tmp = b2 + ((c2 & a2) | (d2 & ~a2)) + x[1] + 0x5C4DD124;
    b2 = (tmp << 13) | (tmp >>> (32 - 13));
    tmp = a2 + ((b2 & d2) | (c2 & ~d2)) + x[10] + 0x5C4DD124;
    a2 = (tmp << 11) | (tmp >>> (32 - 11));
    tmp = d2 + ((a2 & c2) | (b2 & ~c2)) + x[6] + 0x5C4DD124;
    d2 = (tmp << 9) | (tmp >>> (32 - 9));
    tmp = c2 + ((d2 & b2) | (a2 & ~b2)) + x[15] + 0x5C4DD124;
    c2 = (tmp << 7) | (tmp >>> (32 - 7));
    tmp = b2 + ((c2 & a2) | (d2 & ~a2)) + x[3] + 0x5C4DD124;
    b2 = (tmp << 15) | (tmp >>> (32 - 15));
    tmp = a2 + ((b2 & d2) | (c2 & ~d2)) + x[12] + 0x5C4DD124;
    a2 = (tmp << 7) | (tmp >>> (32 - 7));
    tmp = d2 + ((a2 & c2) | (b2 & ~c2)) + x[0] + 0x5C4DD124;
    d2 = (tmp << 12) | (tmp >>> (32 - 12));
    tmp = c2 + ((d2 & b2) | (a2 & ~b2)) + x[9] + 0x5C4DD124;
    c2 = (tmp << 15) | (tmp >>> (32 - 15));
    tmp = b2 + ((c2 & a2) | (d2 & ~a2)) + x[5] + 0x5C4DD124;
    b2 = (tmp << 9) | (tmp >>> (32 - 9));
    tmp = a2 + ((b2 & d2) | (c2 & ~d2)) + x[14] + 0x5C4DD124;
    a2 = (tmp << 7) | (tmp >>> (32 - 7));
    tmp = d2 + ((a2 & c2) | (b2 & ~c2)) + x[2] + 0x5C4DD124;
    d2 = (tmp << 11) | (tmp >>> (32 - 11));
    tmp = c2 + ((d2 & b2) | (a2 & ~b2)) + x[11] + 0x5C4DD124;
    c2 = (tmp << 13) | (tmp >>> (32 - 13));
    tmp = b2 + ((c2 & a2) | (d2 & ~a2)) + x[8] + 0x5C4DD124;
    b2 = (tmp << 12) | (tmp >>> (32 - 12));

    tmp = a2 + (b2 ^ (c2 | ~d2)) + x[3] + 0x6D703EF3;
    a2 = (tmp << 11) | (tmp >>> (32 - 11));
    tmp = d2 + (a2 ^ (b2 | ~c2)) + x[10] + 0x6D703EF3;
    d2 = (tmp << 13) | (tmp >>> (32 - 13));
    tmp = c2 + (d2 ^ (a2 | ~b2)) + x[2] + 0x6D703EF3;
    c2 = (tmp << 14) | (tmp >>> (32 - 14));
    tmp = b2 + (c2 ^ (d2 | ~a2)) + x[4] + 0x6D703EF3;
    b2 = (tmp << 7) | (tmp >>> (32 - 7));
    tmp = a2 + (b2 ^ (c2 | ~d2)) + x[9] + 0x6D703EF3;
    a2 = (tmp << 14) | (tmp >>> (32 - 14));
    tmp = d2 + (a2 ^ (b2 | ~c2)) + x[15] + 0x6D703EF3;
    d2 = (tmp << 9) | (tmp >>> (32 - 9));
    tmp = c2 + (d2 ^ (a2 | ~b2)) + x[8] + 0x6D703EF3;
    c2 = (tmp << 13) | (tmp >>> (32 - 13));
    tmp = b2 + (c2 ^ (d2 | ~a2)) + x[1] + 0x6D703EF3;
    b2 = (tmp << 15) | (tmp >>> (32 - 15));
    tmp = a2 + (b2 ^ (c2 | ~d2)) + x[14] + 0x6D703EF3;
    a2 = (tmp << 6) | (tmp >>> (32 - 6));
    tmp = d2 + (a2 ^ (b2 | ~c2)) + x[7] + 0x6D703EF3;
    d2 = (tmp << 8) | (tmp >>> (32 - 8));
    tmp = c2 + (d2 ^ (a2 | ~b2)) + x[0] + 0x6D703EF3;
    c2 = (tmp << 13) | (tmp >>> (32 - 13));
    tmp = b2 + (c2 ^ (d2 | ~a2)) + x[6] + 0x6D703EF3;
    b2 = (tmp << 6) | (tmp >>> (32 - 6));
    tmp = a2 + (b2 ^ (c2 | ~d2)) + x[11] + 0x6D703EF3;
    a2 = (tmp << 12) | (tmp >>> (32 - 12));
    tmp = d2 + (a2 ^ (b2 | ~c2)) + x[13] + 0x6D703EF3;
    d2 = (tmp << 5) | (tmp >>> (32 - 5));
    tmp = c2 + (d2 ^ (a2 | ~b2)) + x[5] + 0x6D703EF3;
    c2 = (tmp << 7) | (tmp >>> (32 - 7));
    tmp = b2 + (c2 ^ (d2 | ~a2)) + x[12] + 0x6D703EF3;
    b2 = (tmp << 5) | (tmp >>> (32 - 5));

    tmp = currentVal[1] + c1 + d2;
    currentVal[1] = currentVal[2] + d1 + a2;
    currentVal[2] = currentVal[3] + a1 + b2;
    currentVal[3] = currentVal[0] + b1 + c2;
    currentVal[0] = tmp;
  }
}
