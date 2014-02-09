package com.palominolabs.ssh.auth.publickey;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.NotThreadSafe;
import java.security.PublicKey;

/**
 * Determines if a user-presented public key matches a predefined authorized key.
 */
@NotThreadSafe
public interface PublicKeyMatcher {

    /**
     * @param key a public key to allow or deny
     * @return true if the public key is considered to match an authorized key
     */
    boolean isMatch(@Nonnull PublicKey key);

    /**
     * @return the SSH authorized key comment
     */
    @Nonnull
    String getComment();
}
