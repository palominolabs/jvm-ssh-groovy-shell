package com.palominolabs.ssh.auth.publickey;

import com.google.common.base.Supplier;
import com.google.common.collect.Lists;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.InputStream;

/**
 * Implements PublicKeyMatcherProvider using an InputStream to an OpenSSH-format authorized_keys file. The file is
 * re-read every time, hence the use of a Supplier. This allows changes to the file to take effect immediately without
 * requiring a restart.
 */
final class AuthorizedKeysMatcherProvider implements PublicKeyMatcherProvider {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizedKeysMatcherProvider.class);

    private final Supplier<InputStream> inputSupplier;

    AuthorizedKeysMatcherProvider(Supplier<InputStream> inputSupplier) {
        this.inputSupplier = inputSupplier;
    }

    @Nonnull
    @Override
    public Iterable<PublicKeyMatcher> getMatchers(@Nonnull Iterable<PublicKeyLoader> loaders) {
        AuthorizedKeyParser parser = new AuthorizedKeyParser(loaders);

        InputStream inputStream = inputSupplier.get();
        if (inputStream == null) {
            logger.warn("Could not load key data stream; rejecting");
            return Lists.newArrayList();
        }

        try {
            return parser.parse(inputStream);
        } catch (IOException e) {
            logger.warn("Could not read authorized keys", e);
            return Lists.newArrayList();
        }
    }
}
