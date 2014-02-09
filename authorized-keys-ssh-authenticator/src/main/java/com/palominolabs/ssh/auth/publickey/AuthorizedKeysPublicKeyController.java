package com.palominolabs.ssh.auth.publickey;

import com.google.common.base.Predicate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;
import java.io.IOException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

import static com.google.common.collect.Iterables.filter;
import static com.google.common.collect.Iterables.getFirst;
import static com.google.common.collect.Lists.newArrayList;

@Immutable
public final class AuthorizedKeysPublicKeyController implements PublicKeyMatcherController {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizedKeysPublicKeyController.class);

    @Nonnull
    @Override
    public Iterable<PublicKeyMatcher> getMatchers(@Nonnull AuthorizedKeyDataSource dataSource,
        @Nonnull Iterable<PublicKeyMatcherFactory> factories) {

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
