/**
 * Orwell -- A security library for the pathologically paranoid
 *
 * Copyright (C) 2013, Jonathan Gillett, All rights reserved.
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library. If not, see <http://www.gnu.org/licenses/>.
 */
package com.orwell.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * Provides support for encoding and decoding using the ASCII85 (Base85)
 * encoding
 * scheme, which encodes date using radix-85 to encode data as 85 of the
 * possible
 * ASCII printable characters. The main advantages of Base85 to Base64 is that
 * it
 * results in less overhead by encoding every 4 bytes into 5 bytes in comparison
 * to Base64 which encodes every 3 bytes into 4 bytes.
 *
 * @see <a href="http://en.wikipedia.org/wiki/Binary-to-text_encoding"></a>
 * @see <a href="http://en.wikipedia.org/wiki/Ascii85"></a>
 */
public abstract class Ascii85 {

	private Ascii85() {
		// Prevent instantiation
	}

	/**
	 * Encodes input data in bytes into Ascii85 encoded data, and
	 * returns the encoded data in bytes. The Ascii85 information can
	 * easily be transmitted and stored, similarly to Base64 encoded
	 * data.
	 *
	 * @param input The input to encode as Ascii85 in bytes
	 * @return A byte array of the encoded data
	 */
	public static byte[] encode(byte[] input) {
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		Ascii85OutputStream ascii85 = new Ascii85OutputStream(buffer);

		try {
			ascii85.write(input);
			ascii85.flush();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				ascii85.close();
			} catch (IOException ex) {
				ex.printStackTrace();
			}
		}

		return removeIdentifiers(buffer.toByteArray());
	}

	/**
	 * Encodes input data in bytes into Ascii85 encoded data, and
	 * returns the encoded data in bytes. The Ascii85 information can
	 * easily be transmitted and stored, similarly to Base64 encoded
	 * data.
	 *
	 * @param input The input to encode as Ascii85 in bytes
	 * @return A String representation of the encoded data
	 */
	public static String encodeToString(byte[] input) {
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		Ascii85OutputStream ascii85 = new Ascii85OutputStream(buffer);
		String output = "";

		try {
			ascii85.write(input);
			ascii85.flush();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				ascii85.close();
			} catch (IOException ex) {
				ex.printStackTrace();
			}
		}

		output = removeIdentifiers(buffer.toString(StandardCharsets.US_ASCII));

		return output;
	}

	/**
	 * Decodes the Ascii85 encoded input into bytes, and returns the
	 * original data in bytes.
	 *
	 * @param input The encode as Ascii85 data in bytes
	 * @return A byte array of the original decoded data
	 */
	public static byte[] decode(byte[] input) {
		ByteArrayInputStream inputStream = new ByteArrayInputStream(addIdentifiers(input));
		Ascii85InputStream ascii85 = new Ascii85InputStream(inputStream);
		ArrayList<Byte> bytes = new ArrayList<>();

		try {
			int b = ascii85.read();

			while (b != -1000) {
				bytes.add(Byte.valueOf((byte) b));
				b = ascii85.read();
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				ascii85.close();
			} catch (IOException ex) {
				ex.printStackTrace();
			}
		}

		/* Convert the Ascii85 Byte representation to byte */
		byte[] output = new byte[bytes.size()];
		for (int i = 0; i < output.length; ++i) {
			output[i] = bytes.get(i).byteValue();
		}

		return output;
	}

	/**
	 * Decodes the Ascii85 encoded input as a String, and returns the
	 * original data in bytes.
	 *
	 * @param input The encode as Ascii85 data in bytes
	 * @return A byte array of the original decoded data
	 */
	public static byte[] decode(String input) {
		ByteArrayInputStream inputStream = null;
		Ascii85InputStream ascii85 = null;
		ArrayList<Byte> bytes = new ArrayList<>();

		/* Initialize the streams used */
		inputStream = new ByteArrayInputStream(addIdentifiers(input.getBytes(StandardCharsets.US_ASCII)));

		ascii85 = new Ascii85InputStream(inputStream);

		try {
			int b = ascii85.read();

			while (b != -1000) {
				bytes.add(Byte.valueOf((byte) b));
				b = ascii85.read();
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				ascii85.close();
			} catch (IOException ex) {
				ex.printStackTrace();
			}
		}

		/* Convert the Ascii85 Byte representation to byte */
		byte[] output = new byte[bytes.size()];
		for (int i = 0; i < output.length; ++i) {
			output[i] = bytes.get(i).byteValue();
		}

		return output;
	}

	/**
	 * Adds back the redundant <~ and ~>, which are part of the Ascii85
	 * encoding scheme so that it can be properly decoded.
	 *
	 * @param input The Ascii85 input to add the redundant encoding to
	 * @return The input with the redundant encoding added back
	 */
	public static byte[] addIdentifiers(byte[] input) {
		byte[] output = new byte[input.length + 4];
		output[0] = (byte) '<';
		output[1] = (byte) '~';
		output[output.length - 2] = (byte) '~';
		output[output.length - 1] = (byte) '>';

		System.arraycopy(input, 0, output, 2, input.length);

		return output;
	}

	/**
	 * Removes the redundant <~ and ~>, which are part of the Ascii85
	 * encoding scheme, I know this breaks the standard, but to hell with
	 * standards!
	 *
	 * @param input The Ascii85 input to remove the redundant encoding from
	 * @return The input with the redundant encoding removed
	 */
	public static byte[] removeIdentifiers(byte[] input) {
		if (input == null
				|| input.length <= 4
				|| input[0] != '<'
				|| input[input.length - 1] != '>'
				|| !(input[1] == '~' && input[input.length - 2] == '~')) {
			return input;
		}
		return Arrays.copyOfRange(input, 2, input.length - 2);
	}

	/**
	 * Removes the redundant <~ and ~>, which are part of the Ascii85
	 * encoding scheme, I know this breaks the standard, but to hell with
	 * standards!
	 *
	 * @param input The Ascii85 input to remove the redundant encoding from
	 * @return The input with the redundant encoding removed
	 */
	public static String removeIdentifiers(String input) {
		return input.replaceAll("(^<~)|(\\~>$)", "");
	}
}
