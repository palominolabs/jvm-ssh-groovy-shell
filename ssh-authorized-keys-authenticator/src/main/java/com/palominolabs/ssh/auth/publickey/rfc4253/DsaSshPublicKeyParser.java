package com.palominolabs.ssh.auth.publickey.rfc4253;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

public final class DsaSshPublicKeyParser extends AbstractSshPublicKeyParser {

    /**
     * @param bytes DSA key bytes in RFC 4253 format
     */
    public DsaSshPublicKeyParser(byte[] bytes) {
        super(bytes);
    }

    /**
     * @return the public key
     * @throws IllegalArgumentException if key type code is incorrect
     * @throws InvalidKeySpecException  if the decoded key cannot be assembled into a DSAPublicKey
     */
    public DSAPublicKey getKey() throws InvalidKeySpecException {
        String type = decodeType();
        if (!type.equals("ssh-dss")) {
            throw new IllegalArgumentException("Key data has invalid type: " + type);
        }
        BigInteger p = decodeBigInt();
        BigInteger q = decodeBigInt();
        BigInteger g = decodeBigInt();
        BigInteger y = decodeBigInt();
        DSAPublicKeySpec spec = new DSAPublicKeySpec(y, p, q, g);
        try {
            return (DSAPublicKey) KeyFactory.getInstance("DSA").generatePublic(spec);
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("Could not get DSA key factory", ex);
        }
    }
}
