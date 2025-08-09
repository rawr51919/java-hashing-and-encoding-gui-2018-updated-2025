/*
 * CRC64
 *
 * Author: Lasse Collin <lasse.collin@tukaani.org>
 *
 * This file has been put into the public domain.
 * You can do whatever you want with this file.
 */

// This file has been slightly modified, but is otherwise as originally written by Lasse Collin
package byte_transforms;

public class CRC64 {
	
    private static final long POLY = 0xC96C5795D7870F42L;
    private static final long[] crcTable = new long[256];

    private long crc = -1;

    static {
        for (int b = 0; b < crcTable.length; ++b) {
                long r = b;
                for (int i = 0; i < 8; ++i) {
                        if ((r & 1) == 1)
                                r = (r >>> 1) ^ POLY;
                        else
                                r >>>= 1;
                }

                crcTable[b] = r;
        }
    }

    public CRC64() {
    	// prevent instantiation	
    }

    public void update(byte b) {
        reset();
        crc = crcTable[(b ^ (int)crc) & 0xFF] ^ (crc >>> 8);
    }

    public void update(byte[] buf) {
        reset();
        update(buf, 0, buf.length);
    }

    public void update(byte[] buf, int off, int len) {
        reset();
        int end = off + len;

        while (off < end)
            crc = crcTable[(buf[off++] ^ (int)crc) & 0xFF] ^ (crc >>> 8);
    }

    public void reset() {
        crc = -1;
    }

    public long getValue() {
        return ~crc;
    }
}
