package com.palominolabs.ssh.auth.publickey.rfc4253;

import javax.annotation.concurrent.NotThreadSafe;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * Provides helper methods for RFC 4253 parsing. Each instance should be used once.
 *
 * In addition, see http://stackoverflow.com/questions/3531506/using-public-key-from-authorized-keys-with-java-security
 * and http://stackoverflow.com/questions/12749858/rsa-public-key-format and http://blog.oddbit.com/2011/05/08/converting-openssh-public-keys/
 */
@NotThreadSafe
abstract class AbstractSshPublicKeyParser {
    private final byte[] bytes;
    private int pos;

    AbstractSshPublicKeyParser(byte[] bytes) {
        this.bytes = bytes;
    }

    /**
     * Decode a length prefix and subsequent bytes as a string.
     *
     * @return the decoded string
     */
    protected String decodeString() {
        int len = decodeInt();
        String type = new String(bytes, pos, len, StandardCharsets.US_ASCII);
        pos += len;
        return type;
    }

    /**
     * Decode a big endian ent from the next 4 bytes.
     *
     * @return the decoded int
     */
    private int decodeInt() {
        return ((bytes[pos++] & 0xFF) << 24) | ((bytes[pos++] & 0xFF) << 16)
            | ((bytes[pos++] & 0xFF) << 8) | (bytes[pos++] & 0xFF);
    }

    /**
     * Decode a length prefix and following BigInteger bytes.
     *
     * @return the decoded BigInteger
     */
    protected BigInteger decodeBigInt() {
        int len = decodeInt();
        byte[] bigIntBytes = new byte[len];
        System.arraycopy(bytes, pos, bigIntBytes, 0, len);
        pos += len;
        return new BigInteger(bigIntBytes);
    }
}
