package com.palominolabs.ssh.auth.publickey.dsa;

import com.google.common.io.BaseEncoding;
import com.google.common.io.Resources;
import com.palominolabs.ssh.auth.publickey.PublicKeyMatcher;
import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;

public final class DsaPublicKeyMatcherFactoryTest {
    @Test
    public void testParseValidLine() throws IOException, InvalidKeySpecException {
        String[] chunks = Resources.toString(Resources.getResource(getClass(), "dsa1.pub"), UTF_8).split(" ");

        byte[] bytes = BaseEncoding.base64().decode(chunks[1]);

        PublicKeyMatcher matcher = new DsaPublicKeyMatcherFactory().buildMatcher(bytes, chunks[2].trim());

        DSAPublicKey publicKey = ((DsaPublicKeyMatcher) matcher).getKey();

        // decoding logic already covered in the key parser
        assertEquals(new BigInteger("1035488456611306799546464428508766441880259252349"), publicKey.getParams().getQ());
        assertEquals("dsa1", matcher.getComment());
    }
}
