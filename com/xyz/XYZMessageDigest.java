package com.xyz;

import java.security.*;

public class XYZMessageDigest extends MessageDigest implements Cloneable {
	private int hash;
	private int store;
	private int nBytes;

	public XYZMessageDigest() {
		super("XYZ");
		engineReset();
	}

    // Copy constructor
    public XYZMessageDigest(XYZMessageDigest original) {
        super("XYZ");
        this.hash = original.hash;
        this.store = original.store;
        this.nBytes = original.nBytes;
    }

	// Clone functionality
	@Override
	@SuppressWarnings("squid:S2975")
	public XYZMessageDigest clone() {
		try {
			return (XYZMessageDigest) super.clone();
		} catch (CloneNotSupportedException e) {
			// This shouldn't happen because we implement Cloneable
			throw new AssertionError("Cloning not supported", e);
		}
	}

	public void engineUpdate(byte b) {
		switch (nBytes) {
			case 0:
				store = (b << 24) & 0xff000000;
				break;
			case 1:
				store |= (b << 16) & 0x00ff0000;
				break;
			case 2:
				store |= (b << 8) & 0x0000ff00;
				break;
			case 3:
				store |= 0x000000ff; // Same as store |= (b << 0) & 0x000000ff
				break;
			default:
				break;
		}
		nBytes++;
		if (nBytes == 4) {
			hash = hash ^ store;
			nBytes = 0;
			store = 0;
		}
	}

	public void engineUpdate(byte[] b, int offset, int length) {
		for (int i = 0; i < length; i++)
			engineUpdate(b[i + offset]);
	}

	public void engineReset() {
		hash = 0;
		store = 0;
		nBytes = 0;
	}

	public byte[] engineDigest() {
		while (nBytes != 0)
			engineUpdate((byte) 0);
		byte[] b = new byte[4];
		b[0] = (byte) (hash >>> 24);
		b[1] = (byte) (hash >>> 16);
		b[2] = (byte) (hash >>> 8);
		b[3] = (byte) (hash >>> 0);
		engineReset();
		return b;
	}
}
