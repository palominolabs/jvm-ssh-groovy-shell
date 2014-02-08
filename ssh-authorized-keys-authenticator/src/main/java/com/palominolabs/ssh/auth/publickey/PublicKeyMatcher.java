package com.palominolabs.ssh.auth.publickey;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.NotThreadSafe;
import java.security.PublicKey;

/**
 * Determines if a public key matches a certain authorized key.
 */
@NotThreadSafe
public interface PublicKeyMatcher {

    /**
     * @param key a public key to compare against
     * @return true if the public key matches this matcher's internal key
     */
    boolean isMatch(@Nonnull PublicKey key);

    /**
     * @return the SSH authorized key comment
     */
    @Nonnull
    String getComment();
}
