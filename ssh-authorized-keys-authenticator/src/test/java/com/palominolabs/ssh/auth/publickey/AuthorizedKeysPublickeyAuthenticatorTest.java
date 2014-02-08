package com.palominolabs.ssh.auth.publickey;

import com.google.common.base.Suppliers;
import com.google.common.collect.Lists;
import org.easymock.EasyMock;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.easymock.EasyMock.anyInt;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public final class AuthorizedKeysPublickeyAuthenticatorTest {

    private final ArrayList<PublicKeyLoader> loaders =
        Lists.<PublicKeyLoader>newArrayList(new FakePublicKeyLoader(false));

    @Test
    public void testRejectsWhenCantGetKeyStream() {
        AuthorizedKeysPublickeyAuthenticator auth =
            new AuthorizedKeysPublickeyAuthenticator(loaders, Suppliers.<InputStream>ofInstance(null));

        assertFalse(auth.authenticate("user", null, null));
    }

    @Test
    public void testRejectsWhenCantLoadKeyStream() throws IOException {
        InputStream stream = EasyMock.createStrictMock(InputStream.class);

        expect(stream.read(EasyMock.<byte[]>anyObject(), anyInt(), anyInt())).andThrow(new IOException("boom"));
        stream.close();

        replay(stream);

        AuthorizedKeysPublickeyAuthenticator auth =
            new AuthorizedKeysPublickeyAuthenticator(loaders, Suppliers.ofInstance(stream));

        assertFalse(auth.authenticate("user", null, null));

        verify(stream);
    }

    @Test
    public void testRejectsWhenCantParseKeys() {
        InputStream stream = new ByteArrayInputStream("bad-format".getBytes(UTF_8));

        AuthorizedKeysPublickeyAuthenticator auth =
            new AuthorizedKeysPublickeyAuthenticator(loaders, Suppliers.ofInstance(stream));

        assertFalse(auth.authenticate("user", null, null));
    }

    @Test
    public void testRejectsWhenNoMatcherMatches() {
        InputStream stream = new ByteArrayInputStream("dummy aaa comment1".getBytes(UTF_8));

        AuthorizedKeysPublickeyAuthenticator auth =
            new AuthorizedKeysPublickeyAuthenticator(loaders, Suppliers.ofInstance(stream));

        assertFalse(auth.authenticate("foo", null, null));
    }

    @Test
    public void testAcceptsWhenOneMatcherMatches() {
        InputStream stream = new ByteArrayInputStream("dummy aaa comment1".getBytes(UTF_8));

        List<PublicKeyLoader> loaders =
            Lists.<PublicKeyLoader>newArrayList(new FakePublicKeyLoader(true));

        AuthorizedKeysPublickeyAuthenticator auth =
            new AuthorizedKeysPublickeyAuthenticator(
                loaders, Suppliers.ofInstance(stream));

        assertTrue(auth.authenticate("foo", null, null));
    }
}
