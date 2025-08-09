// $Id: WhirlpoolCore.java 214 2010-06-03 17:25:08Z tp $

package fr.cryptohash;

/**
 * <p>
 * This class implements the core operations for the Whirlpool digest
 * algorithm family. The three variants differ only in the tables of
 * constants which are provided to this implementation in the constructor.
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

abstract class WhirlpoolCore extends MDHelper {

	/**
     * Create the object.
     *
     * @param tables        the grouped tables object holding all 8 tables
     * @param roundConstants the round constants array
     */
    WhirlpoolCore(WhirlpoolTables tables, long[] roundConstants) {
        super(false, 32);
        this.table0 = tables.table0;
        this.table1 = tables.table1;
        this.table2 = tables.table2;
        this.table3 = tables.table3;
        this.table4 = tables.table4;
        this.table5 = tables.table5;
        this.table6 = tables.table6;
        this.table7 = tables.table7;
        this.roundConstants = roundConstants;
    }

	private final long[] table0;
	private final long[] table1;
	private final long[] table2;
	private final long[] table3;
	private final long[] table4;
	private final long[] table5;
	private final long[] table6;
	private final long[] table7;
	private final long[] roundConstants;

	private long state0;
	private long state1;
	private long state2;
	private long state3;
	private long state4;
	private long state5;
	private long state6;
	private long state7;

	/** @see DigestEngine */
	protected Digest copyState(WhirlpoolCore dest) {
		dest.state0 = state0;
		dest.state1 = state1;
		dest.state2 = state2;
		dest.state3 = state3;
		dest.state4 = state4;
		dest.state5 = state5;
		dest.state6 = state6;
		dest.state7 = state7;
		return super.copyState(dest);
	}

	/** @see Digest */
	public int getDigestLength() {
		return 64;
	}

	/** @see Digest */
	public int getBlockLength() {
		return 64;
	}

	/** @see DigestEngine */
	@Override
	protected void engineReset() {
		state0 = state1 = state2 = state3 = state4 = state5 = state6 = state7 = 0L;
	}

	/** @see DigestEngine */
	protected void doPadding(byte[] output, int outputOffset) {
		makeMDPadding();
		encodeLELong(state0, output, outputOffset);
		encodeLELong(state1, output, outputOffset + 8);
		encodeLELong(state2, output, outputOffset + 16);
		encodeLELong(state3, output, outputOffset + 24);
		encodeLELong(state4, output, outputOffset + 32);
		encodeLELong(state5, output, outputOffset + 40);
		encodeLELong(state6, output, outputOffset + 48);
		encodeLELong(state7, output, outputOffset + 56);
	}

	/** @see DigestEngine */
	protected void doInit() {
		engineReset();
	}

	/**
	 * Decode a 64-bit little-endian integer.
	 *
	 * @param buf the source buffer
	 * @param off the source offset
	 * @return the decoded integer
	 */
	private static final long decodeLELong(byte[] buf, int off) {
		return (buf[off + 0] & 0xFF)
				| ((long) (buf[off + 1] & 0xFF) << 8)
				| ((long) (buf[off + 2] & 0xFF) << 16)
				| ((long) (buf[off + 3] & 0xFF) << 24)
				| ((long) (buf[off + 4] & 0xFF) << 32)
				| ((long) (buf[off + 5] & 0xFF) << 40)
				| ((long) (buf[off + 6] & 0xFF) << 48)
				| ((long) (buf[off + 7] & 0xFF) << 56);
	}

	/**
	 * Encode a 64-bit integer with little-endian convention.
	 *
	 * @param val the integer to encode
	 * @param dst the destination buffer
	 * @param off the destination offset
	 */
	private static final void encodeLELong(long val, byte[] dst, int off) {
		dst[off + 0] = (byte) val;
		dst[off + 1] = (byte) ((int) val >>> 8);
		dst[off + 2] = (byte) ((int) val >>> 16);
		dst[off + 3] = (byte) ((int) val >>> 24);
		dst[off + 4] = (byte) (val >>> 32);
		dst[off + 5] = (byte) (val >>> 40);
		dst[off + 6] = (byte) (val >>> 48);
		dst[off + 7] = (byte) (val >>> 56);
	}

	/** @see DigestEngine */
	@Override
	protected void processBlock(byte[] buffer) {
		long message0 = decodeLELong(buffer, 0);
		long message1 = decodeLELong(buffer, 8);
		long message2 = decodeLELong(buffer, 16);
		long message3 = decodeLELong(buffer, 24);
		long message4 = decodeLELong(buffer, 32);
		long message5 = decodeLELong(buffer, 40);
		long message6 = decodeLELong(buffer, 48);
		long message7 = decodeLELong(buffer, 56);

		long savedMessage0 = message0;
		long savedMessage1 = message1;
		long savedMessage2 = message2;
		long savedMessage3 = message3;
		long savedMessage4 = message4;
		long savedMessage5 = message5;
		long savedMessage6 = message6;
		long savedMessage7 = message7;

		long hash0 = message0 ^= state0;
		long hash1 = message1 ^= state1;
		long hash2 = message2 ^= state2;
		long hash3 = message3 ^= state3;
		long hash4 = message4 ^= state4;
		long hash5 = message5 ^= state5;
		long hash6 = message6 ^= state6;
		long hash7 = message7 ^= state7;

		for (int round = 0; round < 10; round++) {
			long temp0 = table0[(int) (message0 >>> 56) & 0xFF]
					^ table1[(int) (message7 >>> 48) & 0xFF]
					^ table2[(int) (message6 >>> 40) & 0xFF]
					^ table3[(int) (message5 >>> 32) & 0xFF]
					^ table4[(int) (message4 >>> 24) & 0xFF]
					^ table5[(int) (message3 >>> 16) & 0xFF]
					^ table6[(int) (message2 >>> 8) & 0xFF]
					^ table7[(int) (message1) & 0xFF]
					^ roundConstants[round];

			long temp1 = table0[(int) (message1 >>> 56) & 0xFF]
					^ table1[(int) (message0 >>> 48) & 0xFF]
					^ table2[(int) (message7 >>> 40) & 0xFF]
					^ table3[(int) (message6 >>> 32) & 0xFF]
					^ table4[(int) (message5 >>> 24) & 0xFF]
					^ table5[(int) (message4 >>> 16) & 0xFF]
					^ table6[(int) (message3 >>> 8) & 0xFF]
					^ table7[(int) (message2) & 0xFF];

			long temp2 = table0[(int) (message2 >>> 56) & 0xFF]
					^ table1[(int) (message1 >>> 48) & 0xFF]
					^ table2[(int) (message0 >>> 40) & 0xFF]
					^ table3[(int) (message7 >>> 32) & 0xFF]
					^ table4[(int) (message6 >>> 24) & 0xFF]
					^ table5[(int) (message5 >>> 16) & 0xFF]
					^ table6[(int) (message4 >>> 8) & 0xFF]
					^ table7[(int) (message3) & 0xFF];

			long temp3 = table0[(int) (message3 >>> 56) & 0xFF]
					^ table1[(int) (message2 >>> 48) & 0xFF]
					^ table2[(int) (message1 >>> 40) & 0xFF]
					^ table3[(int) (message0 >>> 32) & 0xFF]
					^ table4[(int) (message7 >>> 24) & 0xFF]
					^ table5[(int) (message6 >>> 16) & 0xFF]
					^ table6[(int) (message5 >>> 8) & 0xFF]
					^ table7[(int) (message4) & 0xFF];

			long temp4 = table0[(int) (message4 >>> 56) & 0xFF]
					^ table1[(int) (message3 >>> 48) & 0xFF]
					^ table2[(int) (message2 >>> 40) & 0xFF]
					^ table3[(int) (message1 >>> 32) & 0xFF]
					^ table4[(int) (message0 >>> 24) & 0xFF]
					^ table5[(int) (message7 >>> 16) & 0xFF]
					^ table6[(int) (message6 >>> 8) & 0xFF]
					^ table7[(int) (message5) & 0xFF];

			long temp5 = table0[(int) (message5 >>> 56) & 0xFF]
					^ table1[(int) (message4 >>> 48) & 0xFF]
					^ table2[(int) (message3 >>> 40) & 0xFF]
					^ table3[(int) (message2 >>> 32) & 0xFF]
					^ table4[(int) (message1 >>> 24) & 0xFF]
					^ table5[(int) (message0 >>> 16) & 0xFF]
					^ table6[(int) (message7 >>> 8) & 0xFF]
					^ table7[(int) (message6) & 0xFF];

			long temp6 = table0[(int) (message6 >>> 56) & 0xFF]
					^ table1[(int) (message5 >>> 48) & 0xFF]
					^ table2[(int) (message4 >>> 40) & 0xFF]
					^ table3[(int) (message3 >>> 32) & 0xFF]
					^ table4[(int) (message2 >>> 24) & 0xFF]
					^ table5[(int) (message1 >>> 16) & 0xFF]
					^ table6[(int) (message0 >>> 8) & 0xFF]
					^ table7[(int) (message7) & 0xFF];

			long temp7 = table0[(int) (message7 >>> 56) & 0xFF]
					^ table1[(int) (message6 >>> 48) & 0xFF]
					^ table2[(int) (message5 >>> 40) & 0xFF]
					^ table3[(int) (message4 >>> 32) & 0xFF]
					^ table4[(int) (message3 >>> 24) & 0xFF]
					^ table5[(int) (message2 >>> 16) & 0xFF]
					^ table6[(int) (message1 >>> 8) & 0xFF]
					^ table7[(int) (message0) & 0xFF];

			message0 = temp0;
			message1 = temp1;
			message2 = temp2;
			message3 = temp3;
			message4 = temp4;
			message5 = temp5;
			message6 = temp6;
			message7 = temp7;
		}

		state0 ^= message0 ^ hash0 ^ savedMessage0;
		state1 ^= message1 ^ hash1 ^ savedMessage1;
		state2 ^= message2 ^ hash2 ^ savedMessage2;
		state3 ^= message3 ^ hash3 ^ savedMessage3;
		state4 ^= message4 ^ hash4 ^ savedMessage4;
		state5 ^= message5 ^ hash5 ^ savedMessage5;
		state6 ^= message6 ^ hash6 ^ savedMessage6;
		state7 ^= message7 ^ hash7 ^ savedMessage7;
	}
}
