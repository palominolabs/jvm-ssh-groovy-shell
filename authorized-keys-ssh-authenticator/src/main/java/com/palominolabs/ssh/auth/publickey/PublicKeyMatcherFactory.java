package com.palominolabs.ssh.auth.publickey;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.ThreadSafe;
import java.security.spec.InvalidKeySpecException;

/**
 * Loads data from an authorized_keys entry.
 */
@ThreadSafe
public interface PublicKeyMatcherFactory {

    /**
     * @return the key type that this factory can handle (e.g. "ssh-rsa").
     */
    @Nonnull
    String getKeyType();

    /**
     * Build a matcher from an authorized_keys entry. The entry must have the type provided by {@link
     * PublicKeyMatcherFactory#getKeyType()}.
     *
     * @param key the key to build a matcher for
     * @return a key matcher
     * @throws InvalidKeySpecException if the key data is invalid
     */
    @Nonnull
    PublicKeyMatcher buildMatcher(AuthorizedKey key) throws InvalidKeySpecException;
}
