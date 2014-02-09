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

        PublicKeyMatcherController controller = createStrictMock(PublicKeyMatcherController.class);

        expect(controller.getMatchers(loaders)).andReturn(Lists.<PublicKeyMatcher>newArrayList());
        replay(controller);

        AuthorizedKeysPublickeyAuthenticator auth =
            new AuthorizedKeysPublickeyAuthenticator(loaders, controller);

        assertFalse(auth.authenticate("foo", null, null));
        verify(controller);
    }

    @Test
    public void testAcceptsWhenOneMatcherMatches() {
        PublicKeyMatcherController controller = createStrictMock(PublicKeyMatcherController.class);

        expect(controller.getMatchers(loaders))
            .andReturn(Lists.<PublicKeyMatcher>newArrayList(new FakePublicKeyMatcher(new byte[0], "comment", true)));

        replay(controller);

        AuthorizedKeysPublickeyAuthenticator auth =
            new AuthorizedKeysPublickeyAuthenticator(loaders, controller);

        assertTrue(auth.authenticate("foo", null, null));

        verify(controller);
    }

    @Test
    public void testAcceptsWhenOnlyMatcherDoesntMatch() {
        PublicKeyMatcherController controller = createStrictMock(PublicKeyMatcherController.class);

        expect(controller.getMatchers(loaders))
            .andReturn(Lists.<PublicKeyMatcher>newArrayList(new FakePublicKeyMatcher(new byte[0], "comment", false)));

        replay(controller);

        AuthorizedKeysPublickeyAuthenticator auth =
            new AuthorizedKeysPublickeyAuthenticator(loaders, controller);

        assertFalse(auth.authenticate("foo", null, null));

        verify(controller);
    }
}
