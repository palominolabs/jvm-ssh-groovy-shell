package com.palominolabs.ssh.auth.publickey;

import com.google.common.base.Predicate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.IOException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

import static com.google.common.collect.Iterables.filter;
import static com.google.common.collect.Iterables.getFirst;
import static com.google.common.collect.Lists.newArrayList;

/**
 * Uses an InputStream to an OpenSSH-format authorized_keys file. The file is re-read every time, hence the use of a
 * Supplier. This allows changes to the file to take effect immediately without requiring a restart.
 */
public final class AuthorizedKeysPublicKeyController implements PublicKeyMatcherController {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizedKeysPublicKeyController.class);

    private final AuthorizedKeyDataSource dataSource;

    public AuthorizedKeysPublicKeyController(AuthorizedKeyDataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    @Nonnull
    public Iterable<PublicKeyMatcher> getMatchers(@Nonnull Iterable<PublicKeyMatcherFactory> factories) {

        Iterable<AuthorizedKey> keys;
        try {
            keys = dataSource.loadKeys();
        } catch (IOException e) {
            logger.warn("Could not read authorized keys", e);
            return newArrayList();
        }

        List<PublicKeyMatcher> matchers = newArrayList();

        for (AuthorizedKey key : keys) {
            PublicKeyMatcherFactory factory = getFirst(filter(factories, new KeyTypePredicate(key.getType())), null);

            if (factory == null) {
                logger.warn("No matcher factories for key type: <" + key.getType() + ">");
                continue;
            }

            try {
                matchers.add(factory.buildMatcher(key));
            } catch (InvalidKeySpecException e) {
                logger.warn("Could not parse key data", e);
            }

            logger.debug("Parsed key with comment <" + key.getComment() + ">");
        }

        return matchers;
    }

    private static class KeyTypePredicate implements Predicate<PublicKeyMatcherFactory> {
        private final String type;

        private KeyTypePredicate(String type) {
            this.type = type;
        }

        @Override
        public boolean apply(@Nullable PublicKeyMatcherFactory input) {
            return input.getKeyType().equals(type);
        }
    }
}
