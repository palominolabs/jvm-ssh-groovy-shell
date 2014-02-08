package com.palominolabs.ssh.auth.publickey.rsa;

import com.google.common.io.Resources;
import com.palominolabs.ssh.auth.publickey.PublicKeyMatcher;
import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public final class RsaPublicKeyMatcherTest {
    @Test
    public void testSameKeyMatches() throws IOException {
        RsaPublicKeyMatcher matcher =
            (RsaPublicKeyMatcher) SshRsaPublicKeyLoaderTest
                .getRsaKey(Resources.getResource(getClass(), "rsa1.pub"));

        assertTrue(matcher.isMatch(matcher.getKey()));
    }

    @Test
    public void testDifferentKeyDoesntMatch() throws IOException {
        PublicKeyMatcher matcher1 = SshRsaPublicKeyLoaderTest.getRsaKey(Resources.getResource(getClass(), "rsa1.pub"));
        RsaPublicKeyMatcher matcher2 =
            (RsaPublicKeyMatcher) SshRsaPublicKeyLoaderTest
                .getRsaKey(Resources.getResource(getClass(), "rsa2.pub"));

        assertFalse(matcher1.isMatch(matcher2.getKey()));
    }
}
