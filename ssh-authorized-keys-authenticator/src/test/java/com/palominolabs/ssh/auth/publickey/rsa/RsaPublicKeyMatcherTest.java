package com.palominolabs.ssh.auth.publickey.rsa;

import com.google.common.io.Resources;
import com.palominolabs.ssh.auth.publickey.PublicKeyMatcher;
import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public final class RsaPublicKeyMatcherTest {
    @Test
    public void testSameKeyMatches() throws IOException, InvalidKeyException, InvalidKeySpecException {
        RsaPublicKeyMatcher matcher = getMatcher("rsa1.pub");

        RSAPublicKey key = matcher.getKey();

        assertTrue(matcher.isMatch(
            new StubRsaPublicKey(key.getPublicExponent(), key.getModulus(), key.getAlgorithm(), key.getFormat(),
                key.getEncoded())));
    }

    @Test
    public void testDifferentKeyDoesntMatch() throws IOException, InvalidKeySpecException {
        PublicKeyMatcher matcher1 = getMatcher("rsa1.pub");

        RsaPublicKeyMatcher matcher2 = getMatcher("rsa2.pub");

        assertFalse(matcher1.isMatch(matcher2.getKey()));
    }

    @Test
    public void testRejectsNonRsaKey() throws IOException, InvalidKeyException, InvalidKeySpecException {
        RsaPublicKeyMatcher matcher = getMatcher("rsa1.pub");

        assertFalse(matcher.isMatch(new PublicKey() {
            @Override
            public String getAlgorithm() {
                return "algo";
            }

            @Override
            public String getFormat() {
                return "foo";
            }

            @Override
            public byte[] getEncoded() {
                return new byte[0];
            }
        }));
    }

    @Test
    public void testRejectsWrongModulus() throws InvalidKeyException, IOException, InvalidKeySpecException {
        RsaPublicKeyMatcher matcher = getMatcher("rsa1.pub");

        RSAPublicKey key = matcher.getKey();
        RSAPublicKey otherKey =
            new StubRsaPublicKey(key.getPublicExponent(), key.getModulus().add(new BigInteger("3")), key.getAlgorithm(),
                key.getFormat(), key.getEncoded());

        assertFalse(matcher.isMatch(otherKey));
    }

    @Test
    public void testRejectsWrongPublicExponent() throws InvalidKeyException, IOException, InvalidKeySpecException {
        RsaPublicKeyMatcher matcher = getMatcher("rsa1.pub");

        RSAPublicKey key = matcher.getKey();
        RSAPublicKey otherKey =
            new StubRsaPublicKey(key.getPublicExponent().add(new BigInteger("3")), key.getModulus(), key.getAlgorithm(),
                key.getFormat(), key.getEncoded());

        assertFalse(matcher.isMatch(otherKey));
    }

    @Test
    public void testRejectsWrongAlgorithm() throws IOException, InvalidKeySpecException {
        final RsaPublicKeyMatcher matcher = getMatcher("rsa1.pub");

        RSAPublicKey key = matcher.getKey();
        assertFalse(
            matcher.isMatch(
                new StubRsaPublicKey(key.getPublicExponent(), key.getModulus(), key.getAlgorithm() + "x",
                    key.getFormat(), key.getEncoded())));
    }

    private RsaPublicKeyMatcher getMatcher(String resourceName) throws IOException, InvalidKeySpecException {
        return RsaPublicKeyLoaderTest.getRsaMatcher(Resources.getResource(getClass(), resourceName));
    }

    static class StubRsaPublicKey implements RSAPublicKey {

        private final BigInteger publicExponent;
        private final BigInteger modulus;
        private final String algorithm;
        private final String format;
        private final byte[] encoded;

        StubRsaPublicKey(BigInteger publicExponent, BigInteger modulus, String algorithm, String format,
            byte[] encoded) {
            this.publicExponent = publicExponent;
            this.modulus = modulus;
            this.algorithm = algorithm;
            this.format = format;
            this.encoded = encoded;
        }

        @Override
        public BigInteger getPublicExponent() {
            return publicExponent;
        }

        @Override
        public String getAlgorithm() {
            return algorithm;
        }

        @Override
        public String getFormat() {
            return format;
        }

        @Override
        public byte[] getEncoded() {
            return encoded;
        }

        @Override
        public BigInteger getModulus() {
            return modulus;
        }
    }
}
