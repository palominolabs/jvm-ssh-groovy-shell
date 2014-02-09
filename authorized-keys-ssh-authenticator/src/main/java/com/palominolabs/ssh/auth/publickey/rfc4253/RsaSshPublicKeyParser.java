package com.palominolabs.ssh.auth.publickey.rfc4253;

import javax.annotation.concurrent.NotThreadSafe;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

/**
 * Parses RFC 4253 RSA public keys. Instances should be used once.
 */
@NotThreadSafe
public class RsaSshPublicKeyParser extends AbstractSshPublicKeyParser {

    /**
     * @param bytes RSA key bytes in RFC 4253 format
     */
    public RsaSshPublicKeyParser(byte[] bytes) {
        super(bytes);
    }

    /**
     * @return the public key
     * @throws IllegalArgumentException if key type code is incorrect
     * @throws InvalidKeySpecException  if the decoded key cannot be assembled into a RSAPublicKey
     */
    public RSAPublicKey getKey() throws InvalidKeySpecException {
        String type = decodeString();
        if (!type.equals("ssh-rsa")) {
            throw new IllegalArgumentException("Key data has invalid type: " + type);
        }
        BigInteger e = decodeBigInt();
        BigInteger m = decodeBigInt();
        RSAPublicKeySpec spec = new RSAPublicKeySpec(m, e);
        try {
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("Could not get RSA key factory", ex);
        }
    }
}
