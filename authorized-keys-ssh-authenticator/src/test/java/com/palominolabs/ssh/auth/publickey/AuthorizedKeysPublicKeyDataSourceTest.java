package com.palominolabs.ssh.auth.publickey;

import com.google.common.base.Suppliers;
import com.google.common.collect.Lists;
import com.google.common.io.BaseEncoding;
import org.easymock.EasyMock;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import static com.google.common.collect.Iterables.isEmpty;
import static com.google.common.collect.Lists.newArrayList;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.easymock.EasyMock.anyInt;
import static org.easymock.EasyMock.aryEq;
import static org.easymock.EasyMock.createStrictMock;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public final class AuthorizedKeysPublicKeyDataSourceTest {

    private final ArrayList<PublicKeyMatcherFactory> loaders =
        Lists.<PublicKeyMatcherFactory>newArrayList(new FakePublicKeyMatcherFactory());

    @Test
    public void testReturnsEmptyWhenCantGetStream() {
        AuthorizedKeysPublicKeyDataSource provider =
            new AuthorizedKeysPublicKeyDataSource(Suppliers.<InputStream>ofInstance(null));

        assertTrue(isEmpty(provider.getMatchers(loaders)));
    }

    @Test
    public void testReturnsEmptyWhenCantReadFromStream() throws IOException {
        InputStream stream = createStrictMock(InputStream.class);

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

    @Test
    public void testReturnsEmptyWhenFactoryThrowsException() throws InvalidKeySpecException {
        PublicKeyMatcherFactory factory = createStrictMock(PublicKeyMatcherFactory.class);
        expect(factory.getKeyType()).andReturn("dummy");
        expect(factory.buildMatcher(aryEq(BaseEncoding.base64().decode("aaa")), eq("dummy-comment")))
            .andThrow(new InvalidKeySpecException("kaboom"));
        replay(factory);

        InputStream stream = new ByteArrayInputStream("dummy aaa dummy-comment".getBytes(UTF_8));

        AuthorizedKeysPublicKeyDataSource provider =
            new AuthorizedKeysPublicKeyDataSource(Suppliers.ofInstance(stream));

        assertTrue(isEmpty(provider.getMatchers(newArrayList(factory))));

        verify(factory);
    }

    @Test
    public void testReturnsEmptyWhenNoFactoryMatchesType() {
        InputStream stream = new ByteArrayInputStream("no-match aaa comment".getBytes(UTF_8));

        AuthorizedKeysPublicKeyDataSource provider =
            new AuthorizedKeysPublicKeyDataSource(Suppliers.ofInstance(stream));

        assertTrue(isEmpty(provider.getMatchers(loaders)));
    }

    @Test
    public void testReturnsMatcherWhenMatchesFactory() {
        InputStream stream = new ByteArrayInputStream("dummy aaa comment".getBytes(UTF_8));

        AuthorizedKeysPublicKeyDataSource provider =
            new AuthorizedKeysPublicKeyDataSource(Suppliers.ofInstance(stream));

        List<PublicKeyMatcher> list = newArrayList(provider.getMatchers(loaders));
        assertEquals(1, list.size());
        FakePublicKeyMatcher matcher = (FakePublicKeyMatcher) list.get(0);
        assertArrayEquals(BaseEncoding.base64().decode("aaa"), matcher.getData());
    }
}
