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

    private final List<PublicKeyLoader> loaders = Lists.newArrayList();

    @Test
    public void testRejectsWhenNoMatchersLoaded() {

        PublicKeyMatcherProvider provider = createStrictMock(PublicKeyMatcherProvider.class);

        expect(provider.getMatchers(loaders)).andReturn(Lists.<PublicKeyMatcher>newArrayList());
        replay(provider);

        AuthorizedKeysPublickeyAuthenticator auth =
            new AuthorizedKeysPublickeyAuthenticator(loaders, provider);

        assertFalse(auth.authenticate("foo", null, null));
        verify(provider);
    }

    @Test
    public void testAcceptsWhenOneMatcherMatches() {
        PublicKeyMatcherProvider provider = createStrictMock(PublicKeyMatcherProvider.class);

        expect(provider.getMatchers(loaders))
            .andReturn(Lists.<PublicKeyMatcher>newArrayList(new FakePublicKeyMatcher(new byte[0], "comment", true)));

        replay(provider);

        AuthorizedKeysPublickeyAuthenticator auth =
            new AuthorizedKeysPublickeyAuthenticator(loaders, provider);

        assertTrue(auth.authenticate("foo", null, null));

        verify(provider);
    }

    @Test
    public void testAcceptsWhenOnlyMatcherDoesntMatch() {
        PublicKeyMatcherProvider provider = createStrictMock(PublicKeyMatcherProvider.class);

        expect(provider.getMatchers(loaders))
            .andReturn(Lists.<PublicKeyMatcher>newArrayList(new FakePublicKeyMatcher(new byte[0], "comment", false)));

        replay(provider);

        AuthorizedKeysPublickeyAuthenticator auth =
            new AuthorizedKeysPublickeyAuthenticator(loaders, provider);

        assertFalse(auth.authenticate("foo", null, null));

        verify(provider);
    }
}
