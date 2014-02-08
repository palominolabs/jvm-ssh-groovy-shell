package com.palominolabs.ssh.auth.publickey;

import com.google.common.base.Predicate;
import com.google.common.base.Supplier;
import com.google.common.collect.Iterables;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
import java.util.Iterator;
import java.util.List;

/**
 * Authenticates users against an authorized_keys file in OpenSSH format. See the sshd(8) manpage for details on the
 * format.
 *
 * Technically, only a subset of the format is supported. The full format allows for options to be specified for each
 * key line, but this is both very rare and not always applicable to this demo, so any such lines will not be processed.
 * This class only supports lines that include exactly the following, separated by a single space:
 *
 * key-type key-bytes-in-base64 comment
 *
 * This class is thread-safe if its provided Supplier is.
 */
public final class AuthorizedKeysPublickeyAuthenticator implements PublickeyAuthenticator {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizedKeysPublickeyAuthenticator.class);

    private final Supplier<InputStream> inputSupplier;

    private final AuthorizedKeyParser parser;

    AuthorizedKeysPublickeyAuthenticator(List<PublicKeyLoader> loaders,
        Supplier<InputStream> inputSupplier) {
        parser = new AuthorizedKeyParser(loaders);
        this.inputSupplier = inputSupplier;
    }

    @Override
    public boolean authenticate(String username, final PublicKey key, ServerSession session) {

        List<PublicKeyMatcher> authenticators = getKeys();
        if (authenticators == null) {
            return false;
        }

        Iterator<PublicKeyMatcher> matchers =
            Iterables.filter(authenticators, new MatcherMatchPredicate(key)).iterator();

        if (matchers.hasNext()) {
            logger.info("Matched key with comment " + matchers.next().getComment());
            return true;
        }

        logger.info("Did not match any keys");
        return false;
    }

    @Nullable
    List<PublicKeyMatcher> getKeys() {
        InputStream inputStream = inputSupplier.get();
        if (inputStream == null) {
            logger.warn("Could not load key data stream; rejecting");
            return null;
        }

        try {
            return parser.parse(inputStream);
        } catch (IOException e) {
            logger.warn("Could not read authorized keys", e);
            return null;
        }
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
