package com.palominolabs.ssh.auth.publickey.rfc4253;

import javax.annotation.concurrent.NotThreadSafe;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

@NotThreadSafe
public class SshRsaPublicKeyParser extends AbstractSshPublicKeyParser {

    /**
     * @param bytes Key bytes in RFC 4353 format
     */
    public SshRsaPublicKeyParser(byte[] bytes) {
        super(bytes);
    }

    /**
     * @return the public key
     * @throws IllegalArgumentException if key type code is incorrect
     * @throws InvalidKeySpecException  if the decoded key cannot be assembled into a RSAPublicKey
     */
    public RSAPublicKey getKey() throws InvalidKeySpecException {
        String type = decodeType();
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
