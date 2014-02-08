package com.palominolabs.ssh.auth.publickey.rfc4253;

import java.math.BigInteger;

class AbstractSshPublicKeyParser {
    protected final byte[] bytes;
    private int pos;

    AbstractSshPublicKeyParser(byte[] bytes) {
        this.bytes = bytes;
    }

    protected String decodeType() {
        int len = decodeInt();
        String type = new String(bytes, pos, len);
        pos += len;
        return type;
    }

    private int decodeInt() {
        return ((bytes[pos++] & 0xFF) << 24) | ((bytes[pos++] & 0xFF) << 16)
            | ((bytes[pos++] & 0xFF) << 8) | (bytes[pos++] & 0xFF);
    }

    protected BigInteger decodeBigInt() {
        int len = decodeInt();
        byte[] bigIntBytes = new byte[len];
        System.arraycopy(bytes, pos, bigIntBytes, 0, len);
        pos += len;
        return new BigInteger(bigIntBytes);
    }
}
