package com.palominolabs.ssh.auth.publickey;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.ThreadSafe;

/**
 * Abstraction around manipulating authorized_keys files.
 */
@ThreadSafe
public interface PublicKeyMatcherProvider {

    /**
     * Use the provided loaders to extract matchers from an implementation-specific data source.
     *
     * @param loaders loaders to use
     * @return matchers that the laoders created
     */
    @Nonnull
    Iterable<PublicKeyMatcher> getMatchers(@Nonnull Iterable<PublicKeyLoader> loaders);
}
