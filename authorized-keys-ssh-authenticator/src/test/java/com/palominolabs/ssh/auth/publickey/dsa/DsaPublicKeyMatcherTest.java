package com.palominolabs.ssh.auth.publickey.dsa;

import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public final class DsaPublicKeyMatcherTest {
    @Test
    public void testSameKeyMatches() throws IOException, InvalidKeySpecException {
        DsaPublicKeyMatcher matcher = DsaPublicKeyMatcherFactoryTest.getPublicKeyMatcher("dsa1.pub");

        assertTrue(matcher.isMatch(new StubDsaPublicKey(matcher.getKey())));
    }

    @Test
    public void testDifferentKeyDoesntMatch() throws IOException, InvalidKeySpecException {
        DsaPublicKeyMatcher matcher = DsaPublicKeyMatcherFactoryTest.getPublicKeyMatcher("dsa1.pub");
        DSAPublicKey otherKey = DsaPublicKeyMatcherFactoryTest.getPublicKeyMatcher("dsa2.pub").getKey();

        assertFalse(matcher.isMatch(otherKey));
    }

    @Test
    public void testDifferentYDoesntMatch() throws IOException, InvalidKeySpecException {
        DsaPublicKeyMatcher matcher = DsaPublicKeyMatcherFactoryTest.getPublicKeyMatcher("dsa1.pub");

        StubDsaPublicKey other = new StubDsaPublicKey(matcher.getKey());
        other.setY(other.getY().add(new BigInteger("1")));
        assertFalse(matcher.isMatch(other));
    }

    @Test
    public void testDifferentGDoesntMatch() throws IOException, InvalidKeySpecException {
        DsaPublicKeyMatcher matcher = DsaPublicKeyMatcherFactoryTest.getPublicKeyMatcher("dsa1.pub");

        StubDsaPublicKey other = new StubDsaPublicKey(matcher.getKey());
        other.setG(other.getParams().getG().add(new BigInteger("1")));
        assertFalse(matcher.isMatch(other));
    }

    @Test
    public void testDifferentPDoesntMatch() throws IOException, InvalidKeySpecException {
        DsaPublicKeyMatcher matcher = DsaPublicKeyMatcherFactoryTest.getPublicKeyMatcher("dsa1.pub");

        StubDsaPublicKey other = new StubDsaPublicKey(matcher.getKey());
        other.setP(other.getParams().getP().add(new BigInteger("1")));
        assertFalse(matcher.isMatch(other));
    }

    @Test
    public void testDifferentQDoesntMatch() throws IOException, InvalidKeySpecException {
        DsaPublicKeyMatcher matcher = DsaPublicKeyMatcherFactoryTest.getPublicKeyMatcher("dsa1.pub");

        StubDsaPublicKey other = new StubDsaPublicKey(matcher.getKey());
        other.setQ(other.getParams().getQ().add(new BigInteger("1")));
        assertFalse(matcher.isMatch(other));
    }

    @Test
    public void testDifferentAlgorithmDoesntMatch() throws IOException, InvalidKeySpecException {
        DsaPublicKeyMatcher matcher = DsaPublicKeyMatcherFactoryTest.getPublicKeyMatcher("dsa1.pub");

        StubDsaPublicKey other = new StubDsaPublicKey(matcher.getKey());
        other.setAlgorithm(other.algorithm + "x");
        assertFalse(matcher.isMatch(other));
    }

    static class StubDsaPublicKey implements DSAPublicKey {
        private BigInteger y;
        private BigInteger g;
        private BigInteger p;
        private BigInteger q;
        private String algorithm;
        private String format;
        private byte[] encoded;

        StubDsaPublicKey(DSAPublicKey key) {
            y = key.getY();
            g = key.getParams().getG();
            p = key.getParams().getP();
            q = key.getParams().getQ();
            algorithm = key.getAlgorithm();
            format = key.getFormat();
            encoded = key.getEncoded();
        }

        @Override
        public BigInteger getY() {
            return y;
        }

        @Override
        public DSAParams getParams() {
            return new DSAParams() {
                @Override
                public BigInteger getP() {
                    return p;
                }

                @Override
                public BigInteger getQ() {
                    return q;
                }

                @Override
                public BigInteger getG() {
                    return g;
                }
            };
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

        void setY(BigInteger y) {
            this.y = y;
        }

        void setG(BigInteger g) {
            this.g = g;
        }

        void setP(BigInteger p) {
            this.p = p;
        }

        void setQ(BigInteger q) {
            this.q = q;
        }

        void setAlgorithm(String algorithm) {
            this.algorithm = algorithm;
        }
    }
}
