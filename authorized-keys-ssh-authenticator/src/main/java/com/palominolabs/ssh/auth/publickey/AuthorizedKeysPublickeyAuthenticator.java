package com.palominolabs.ssh.auth.publickey;

import com.google.common.base.Predicate;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.security.PublicKey;

import static com.google.common.collect.Iterables.filter;
import static com.google.common.collect.Iterables.getFirst;

/**
 * Authenticates users against an authorized_keys file in OpenSSH format. See the sshd(8) manpage for details on the
 * format.
 *
 * Technically, only a subset of the format is supported. The full format allows for options to be specified for each
 * key line, but this is both very rare and not always applicable to this, so any such lines will not be processed.
 */
public final class AuthorizedKeysPublickeyAuthenticator implements PublickeyAuthenticator {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizedKeysPublickeyAuthenticator.class);

    private final Iterable<PublicKeyMatcherFactory> matcherFactories;
    private final AuthorizedKeyDataSource authorizedKeyDataSource;
    private final PublicKeyMatcherFactoryController factoryController;

    public AuthorizedKeysPublickeyAuthenticator(Iterable<PublicKeyMatcherFactory> matcherFactories,
        AuthorizedKeyDataSource authorizedKeyDataSource, PublicKeyMatcherFactoryController factoryController) {
        this.matcherFactories = matcherFactories;
        this.authorizedKeyDataSource = authorizedKeyDataSource;
        this.factoryController = factoryController;
    }

    @Override
    public boolean authenticate(String username, final PublicKey key, ServerSession session) {

        Iterable<PublicKeyMatcher> matchers = factoryController.getMatchers(authorizedKeyDataSource, matcherFactories);

        PublicKeyMatcher matcher =
            getFirst(filter(matchers, new MatcherMatchPredicate(key)), null);

        if (matcher != null) {
            logger.debug(
                "Authenticated user <" + username + "> against authorized key with comment <" + matcher.getComment() +
                    ">");
            return true;
        }

        logger.debug("User <" + username + "> did not match any keys");
        return false;
    }

    static class MatcherMatchPredicate implements Predicate<PublicKeyMatcher> {

        private final PublicKey candidateKey;

        MatcherMatchPredicate(PublicKey candidateKey) {
            this.candidateKey = candidateKey;
        }

        @Override
        public boolean apply(@Nullable PublicKeyMatcher input) {
            return input.isMatch(candidateKey);
        }
    }
}
