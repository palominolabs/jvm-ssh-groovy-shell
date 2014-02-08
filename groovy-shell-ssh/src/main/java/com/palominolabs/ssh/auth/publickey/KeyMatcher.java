package com.palominolabs.ssh.auth.publickey;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.ThreadSafe;
import java.security.PublicKey;

/**
 * Determines if two PublicKeys are equivalent. Only meaningful for a specific type of PublicKey (e.g. RSAPublicKey).
 */
@ThreadSafe
public interface KeyMatcher {

    /**
     * Both keys must be of the same type (e.g. RSAPublicKey). The appropriate type is determined by the
     * PublicKeyHandler that provided this object.
     *
     * @param key1 a key
     * @param key2 another key
     * @return true if keys are equivalent
     */
    boolean matches(@Nonnull PublicKey key1, @Nonnull PublicKey key2);
}
