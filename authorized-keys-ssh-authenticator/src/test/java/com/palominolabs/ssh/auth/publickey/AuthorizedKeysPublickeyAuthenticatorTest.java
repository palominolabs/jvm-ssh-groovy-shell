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

        PublicKeyMatcherFactoryController controller = createStrictMock(PublicKeyMatcherFactoryController.class);
        AuthorizedKeyDataSource dataSource = createStrictMock(AuthorizedKeyDataSource.class);

        expect(controller.getMatchers(dataSource, loaders)).andReturn(Lists.<PublicKeyMatcher>newArrayList());
        replay(controller, dataSource);

        AuthorizedKeysPublickeyAuthenticator auth =
            new AuthorizedKeysPublickeyAuthenticator(loaders, dataSource, controller);

        assertFalse(auth.authenticate("foo", null, null));
        verify(controller, dataSource);
    }

    @Test
    public void testAcceptsWhenOneMatcherMatches() {
        PublicKeyMatcherFactoryController controller = createStrictMock(PublicKeyMatcherFactoryController.class);
        AuthorizedKeyDataSource dataSource = createStrictMock(AuthorizedKeyDataSource.class);

        expect(controller.getMatchers(dataSource, loaders))
            .andReturn(Lists.<PublicKeyMatcher>newArrayList(new FakePublicKeyMatcher(new byte[0], "comment", true)));

        replay(controller, dataSource);

        AuthorizedKeysPublickeyAuthenticator auth =
            new AuthorizedKeysPublickeyAuthenticator(loaders, dataSource, controller);

        assertTrue(auth.authenticate("foo", null, null));

        verify(controller, dataSource);
    }

    @Test
    public void testAcceptsWhenOnlyMatcherDoesntMatch() {
        PublicKeyMatcherFactoryController controller = createStrictMock(PublicKeyMatcherFactoryController.class);
        AuthorizedKeyDataSource dataSource = createStrictMock(AuthorizedKeyDataSource.class);

        expect(controller.getMatchers(dataSource, loaders))
            .andReturn(Lists.<PublicKeyMatcher>newArrayList(new FakePublicKeyMatcher(new byte[0], "comment", false)));

        replay(controller, dataSource);

        AuthorizedKeysPublickeyAuthenticator auth =
            new AuthorizedKeysPublickeyAuthenticator(loaders, dataSource, controller);

        assertFalse(auth.authenticate("foo", null, null));

        verify(controller, dataSource);
    }
}
