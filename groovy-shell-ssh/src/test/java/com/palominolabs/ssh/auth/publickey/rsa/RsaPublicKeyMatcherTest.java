package com.palominolabs.ssh.auth.publickey.rsa;

import com.google.common.io.Resources;
import org.junit.Test;

import java.io.IOException;
import java.security.PublicKey;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public final class RsaPublicKeyMatcherTest {
    @Test
    public void testSameKeyMatches() throws IOException {
        PublicKey key = OpenSshRsaParserTest.getRsaKey(Resources.getResource(getClass(), "rsa1.pub"));

        assertTrue(new RsaPublicKeyMatcher().matches(key, key));
    }

    @Test
    public void testDifferentKeyDoesntMatch() throws IOException {
        PublicKey key1 = OpenSshRsaParserTest.getRsaKey(Resources.getResource(getClass(), "rsa1.pub"));
        PublicKey key2 = OpenSshRsaParserTest.getRsaKey(Resources.getResource(getClass(), "rsa2.pub"));

        assertFalse(new RsaPublicKeyMatcher().matches(key1, key2));
    }
}
