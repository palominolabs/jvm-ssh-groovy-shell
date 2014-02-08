package com.palominolabs.ssh.auth.publickey;

import com.google.common.base.Suppliers;
import com.google.common.collect.Lists;
import org.easymock.EasyMock;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;

import static com.google.common.collect.Iterables.isEmpty;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.easymock.EasyMock.anyInt;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertTrue;

public final class AuthorizedKeysPublicKeyDataSourceTest {

    private final ArrayList<PublicKeyMatcherFactory> loaders =
        Lists.<PublicKeyMatcherFactory>newArrayList(new FakePublicKeyMatcherFactory(false));

    @Test
    public void testReturnsEmptyWhenCantGetStream() {
        AuthorizedKeysPublicKeyDataSource provider =
            new AuthorizedKeysPublicKeyDataSource(Suppliers.<InputStream>ofInstance(null));

        assertTrue(isEmpty(provider.getMatchers(loaders)));
    }

    @Test
    public void testReturnsEmptyWhenCantReadFromStream() throws IOException {
        InputStream stream = EasyMock.createStrictMock(InputStream.class);

        expect(stream.read(EasyMock.<byte[]>anyObject(), anyInt(), anyInt())).andThrow(new IOException("boom"));
        stream.close();

        replay(stream);

        AuthorizedKeysPublicKeyDataSource provider =
            new AuthorizedKeysPublicKeyDataSource(Suppliers.ofInstance(stream));

        assertTrue(isEmpty(provider.getMatchers(loaders)));

        verify(stream);
    }

    @Test
    public void testReturnsEmptyWhenCantParse() {
        InputStream stream = new ByteArrayInputStream("bad-format".getBytes(UTF_8));

        AuthorizedKeysPublicKeyDataSource provider =
            new AuthorizedKeysPublicKeyDataSource(Suppliers.ofInstance(stream));

        assertTrue(isEmpty(provider.getMatchers(loaders)));
    }
}
