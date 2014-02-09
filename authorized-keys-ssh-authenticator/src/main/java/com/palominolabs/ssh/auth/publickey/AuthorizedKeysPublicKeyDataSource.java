package com.palominolabs.ssh.auth.publickey;

import com.google.common.base.Predicate;
import com.google.common.base.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.IOException;
import java.io.InputStream;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

import static com.google.common.collect.Iterables.filter;
import static com.google.common.collect.Iterables.getFirst;
import static com.google.common.collect.Lists.newArrayList;

/**
 * Uses an InputStream to an OpenSSH-format authorized_keys file. The file is re-read every time, hence the use of a
 * Supplier. This allows changes to the file to take effect immediately without requiring a restart.
 */
public final class AuthorizedKeysPublicKeyDataSource implements PublicKeyDataSource {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizedKeysPublicKeyDataSource.class);

    private final Supplier<InputStream> inputSupplier;

    public AuthorizedKeysPublicKeyDataSource(Supplier<InputStream> inputSupplier) {
        this.inputSupplier = inputSupplier;
    }

    @Nonnull
    @Override
    public Iterable<PublicKeyMatcher> getMatchers(@Nonnull Iterable<PublicKeyMatcherFactory> factories) {
        // TODO refactor so that this logic is shared since it's dependent only on an Iterable<AuthorizedKey>

        AuthorizedKeyParser parser = new AuthorizedKeyParser();

        InputStream inputStream = inputSupplier.get();
        if (inputStream == null) {
            logger.warn("Could not load key data stream; rejecting");
            return newArrayList();
        }

        Iterable<AuthorizedKey> keys;
        try {
            keys = parser.parse(inputStream);
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
                // TODO refactor factory to take AuthorizedKey
                matchers.add(factory.buildMatcher(key.getData(), key.getComment()));
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
