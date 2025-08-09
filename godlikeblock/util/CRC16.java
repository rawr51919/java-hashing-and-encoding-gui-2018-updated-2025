package godlikeblock.util;
public class CRC16 {
	public int update(byte[] bArr) {
		int crc = 0;
		for (byte b : bArr) {
			crc ^= b;
			for (int i = 8; i != 0; i--) {
				if ((crc & 1) != 0) {
					crc >>= 1;
					crc ^= 0xA001;
				} else {
					crc >>= 1;
				}
			}
		}
		crc &= 0xffff;
		return crc;
	}
}
