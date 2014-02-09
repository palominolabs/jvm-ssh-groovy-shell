package com.palominolabs.ssh.auth.publickey;

import com.google.common.collect.Lists;
import com.google.common.io.BaseEncoding;
import org.easymock.EasyMock;
import org.junit.Test;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import static com.google.common.collect.Iterables.isEmpty;
import static com.google.common.collect.Lists.newArrayList;
import static com.palominolabs.ssh.auth.publickey.FakePublicKeyMatcherFactory.TYPE;
import static org.easymock.EasyMock.createStrictMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public final class AuthorizedKeysPublicKeyControllerTest {

    private static final BaseEncoding BASE_64 = BaseEncoding.base64();

    private final ArrayList<PublicKeyMatcherFactory> loaders =
        Lists.<PublicKeyMatcherFactory>newArrayList(new FakePublicKeyMatcherFactory());
    private final AuthorizedKeysPublicKeyController controller = new AuthorizedKeysPublicKeyController();

    @Test
    public void testReturnsEmptyWhenDataSourceThrowsException() throws IOException {

        AuthorizedKeyDataSource dataSource = createStrictMock(AuthorizedKeyDataSource.class);
        expect(dataSource.loadKeys()).andThrow(new IOException("kaboom"));
        replay(dataSource);

        assertTrue(isEmpty(controller.getMatchers(dataSource, loaders)));

        verify(dataSource);
    }

    @Test
    public void testReturnsEmptyWhenFactoryThrowsException() throws InvalidKeySpecException {
        PublicKeyMatcherFactory factory = createStrictMock(PublicKeyMatcherFactory.class);
        expect(factory.getKeyType()).andReturn(TYPE);
        expect(factory.buildMatcher(EasyMock.<AuthorizedKey>anyObject()))
            .andThrow(new InvalidKeySpecException("kaboom"));
        replay(factory);

        assertTrue(
            isEmpty(controller.getMatchers(new StubDataSource(TYPE, "aaa", "dummy-comment"), newArrayList(factory))));

        verify(factory);
    }

    @Test
    public void testReturnsEmptyWhenNoFactoryMatchesType() {
        assertTrue(isEmpty(controller.getMatchers(new StubDataSource("no-match", "aaa", "comment"), loaders)));
    }

    @Test
    public void testReturnsMatcherWhenMatchesFactory() {
        List<PublicKeyMatcher> list =
            newArrayList(controller.getMatchers(new StubDataSource(TYPE, "aaa", "comment"), loaders));
        assertEquals(1, list.size());
        FakePublicKeyMatcher matcher = (FakePublicKeyMatcher) list.get(0);
        assertArrayEquals(BASE_64.decode("aaa"), matcher.getData());
    }

    static class StubDataSource implements AuthorizedKeyDataSource {

        private final Iterable<AuthorizedKey> keys;

        StubDataSource(String type, String base64, String comment) {
            this(newArrayList(new AuthorizedKey(type, BASE_64.decode(base64), comment)));
        }

        StubDataSource(Iterable<AuthorizedKey> keys) {
            this.keys = keys;
        }

        @Nonnull
        @Override
        public Iterable<AuthorizedKey> loadKeys() throws IOException {
            return keys;
        }
    }
}
