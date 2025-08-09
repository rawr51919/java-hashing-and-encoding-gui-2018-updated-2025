package rawr.util;

public class HexagramEncode {

	private HexagramEncode() {
		// Prevent instantiation
	}

	private static final String HEXAGRAM_CHARS = "�?䷗䷆䷒䷎䷣䷭䷊�?䷲䷧䷵䷽䷶䷟䷡䷇䷂䷜䷻䷦䷾䷯䷄䷬�?䷮䷹䷞䷰䷛䷪䷖䷚䷃䷨䷳䷕䷑䷙䷢䷔䷿䷥䷷�?䷱�?䷓䷩䷺䷼䷴䷤䷸䷈䷋䷘䷅䷉䷠䷌䷫䷀";

	public static String encode(String s) {

		// The result/encoded string, the padding string, and the pad count
		String r = "";
		String p = "";
		int c = s.length() % 3;

		// Convert the strings to StringBuilder first
		StringBuilder pBuilder = new StringBuilder(p);
		StringBuilder sBuilder = new StringBuilder(s);

		// Add a right zero pad to make this string a multiple of 3 characters
		if (c > 0) {
			for (; c < 3; c++) {
				pBuilder.append("☯");
				sBuilder.append('\0');
			}
		}

		// After modifications, convert back to strings
		p = pBuilder.toString();
		s = sBuilder.toString();

		// Increment over the length of the string, three characters at a time
		for (c = 0; c < s.length(); c += 3) {

			// Convert r to StringBuilder first
			StringBuilder rBuilder = new StringBuilder(r);

			// We add newlines after every 76 output characters, according to the MIME specs
			if (c > 0 && (c / 3 * 4) % 76 == 0) {
				rBuilder.append("\r\n");
			}

			// After modifications, convert r back to string
			r = rBuilder.toString();

			// These three 8-bit characters become one 24-bit number
			int n = (s.charAt(c) << 16) + (s.charAt(c + 1) << 8)
					+ (s.charAt(c + 2));

			// This 24-bit number gets separated into four 6-bit numbers
			int n1 = (n >> 18) & 63;
			int n2 = (n >> 12) & 63;
			int n3 = (n >> 6) & 63;
			int n4 = n & 63;

			// Convert r BACK to StringBuilder to add more to the string
			rBuilder = new StringBuilder(r);

			// Those four 6-bit numbers are used as indices into the I Ching
			// hexagram character list
			rBuilder.append(HEXAGRAM_CHARS.charAt(n1))
					.append(HEXAGRAM_CHARS.charAt(n2))
					.append(HEXAGRAM_CHARS.charAt(n3))
					.append(HEXAGRAM_CHARS.charAt(n4));

			// Convert r back to string again
			r = rBuilder.toString();
		}

		return r.substring(0, r.length() - p.length()) + p;
	}
}
