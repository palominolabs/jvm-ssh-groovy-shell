package com.palominolabs.ssh.auth.publickey;

import com.google.common.collect.Lists;
import org.junit.Test;

import java.util.List;

import static org.easymock.EasyMock.createStrictMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public final class AuthorizedKeysPublickeyAuthenticatorTest {

    private final List<PublicKeyMatcherFactory> loaders = Lists.newArrayList();

    @Test
    public void testRejectsWhenNoMatchersLoaded() {

        PublicKeyDataSource dataSource = createStrictMock(PublicKeyDataSource.class);

        expect(dataSource.getMatchers(loaders)).andReturn(Lists.<PublicKeyMatcher>newArrayList());
        replay(dataSource);

        AuthorizedKeysPublickeyAuthenticator auth =
            new AuthorizedKeysPublickeyAuthenticator(loaders, dataSource);

        assertFalse(auth.authenticate("foo", null, null));
        verify(dataSource);
    }

    @Test
    public void testAcceptsWhenOneMatcherMatches() {
        PublicKeyDataSource dataSource = createStrictMock(PublicKeyDataSource.class);

        expect(dataSource.getMatchers(loaders))
            .andReturn(Lists.<PublicKeyMatcher>newArrayList(new FakePublicKeyMatcher(new byte[0], "comment", true)));

        replay(dataSource);

        AuthorizedKeysPublickeyAuthenticator auth =
            new AuthorizedKeysPublickeyAuthenticator(loaders, dataSource);

        assertTrue(auth.authenticate("foo", null, null));

        verify(dataSource);
    }

    @Test
    public void testAcceptsWhenOnlyMatcherDoesntMatch() {
        PublicKeyDataSource dataSource = createStrictMock(PublicKeyDataSource.class);

        expect(dataSource.getMatchers(loaders))
            .andReturn(Lists.<PublicKeyMatcher>newArrayList(new FakePublicKeyMatcher(new byte[0], "comment", false)));

        replay(dataSource);

        AuthorizedKeysPublickeyAuthenticator auth =
            new AuthorizedKeysPublickeyAuthenticator(loaders, dataSource);

        assertFalse(auth.authenticate("foo", null, null));

        verify(dataSource);
    }
}
