package com.palominolabs.ssh.auth.publickey;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.ThreadSafe;
import java.security.spec.InvalidKeySpecException;

/**
 * Loads data from an authorized_keys entry.
 */
@ThreadSafe
public interface PublicKeyLoader {

    /**
     * @return the key type that this parser can handle (e.g. "ssh-rsa").
     */
    @Nonnull
    String getKeyType();

    /**
     * Build a matcher from an authorized_keys entry. The entry must have the type provided by {@link
     * PublicKeyLoader#getKeyType()}.
     *
     * @param data    PEM encoded key data
     * @param comment comment for the authorized key entry
     * @return a key matcher
     * @throws InvalidKeySpecException if the key data is invalid
     */
    @Nonnull
    PublicKeyMatcher buildMatcher(byte[] data, String comment) throws InvalidKeySpecException;
}
