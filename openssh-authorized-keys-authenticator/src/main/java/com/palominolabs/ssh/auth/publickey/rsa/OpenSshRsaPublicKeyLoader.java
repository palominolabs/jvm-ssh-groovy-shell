package com.palominolabs.ssh.auth.publickey.rsa;

import com.palominolabs.ssh.auth.publickey.PublicKeyMatcher;
import com.palominolabs.ssh.auth.publickey.PublicKeyLoader;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

/**
 * OpenSSH RSA key parser, guided by http://stackoverflow.com/questions/3531506/using-public-key-from-authorized-keys-with-java-security
 * and http://stackoverflow.com/questions/12749858/rsa-public-key-format and http://blog.oddbit.com/2011/05/08/converting-openssh-public-keys/
 */
@Immutable
class OpenSshRsaPublicKeyLoader implements PublicKeyLoader {

    static final String SSH_KEY_TYPE = "ssh-rsa";

    @Nonnull
    @Override
    public String getKeyType() {
        return SSH_KEY_TYPE;
    }

    @Nonnull
    @Override
    public PublicKeyMatcher buildMatcher(byte[] data, String comment) {
        return new RsaPublicKeyMatcher((RSAPublicKey) new StatefulParser(data).getKey(), comment);
    }

    @NotThreadSafe
    private static class StatefulParser {
        private final byte[] bytes;

        private int pos;

        private StatefulParser(byte[] bytes) {
            this.bytes = bytes;
        }

        private PublicKey getKey() {
            String type = decodeType();
            if (!type.equals(SSH_KEY_TYPE)) {
                throw new IllegalArgumentException("Key data has invalid type: " + type);
            }
            BigInteger e = decodeBigInt();
            BigInteger m = decodeBigInt();
            RSAPublicKeySpec spec = new RSAPublicKeySpec(m, e);
            try {
                return KeyFactory.getInstance("RSA").generatePublic(spec);
            } catch (InvalidKeySpecException | NoSuchAlgorithmException ex) {
                throw new RuntimeException("Could not build public key", ex);
            }
        }

        private String decodeType() {
            int len = decodeInt();
            String type = new String(bytes, pos, len);
            pos += len;
            return type;
        }

        private int decodeInt() {
            return ((bytes[pos++] & 0xFF) << 24) | ((bytes[pos++] & 0xFF) << 16)
                | ((bytes[pos++] & 0xFF) << 8) | (bytes[pos++] & 0xFF);
        }

        private BigInteger decodeBigInt() {
            int len = decodeInt();
            byte[] bigIntBytes = new byte[len];
            System.arraycopy(bytes, pos, bigIntBytes, 0, len);
            pos += len;
            return new BigInteger(bigIntBytes);
        }
    }
}
