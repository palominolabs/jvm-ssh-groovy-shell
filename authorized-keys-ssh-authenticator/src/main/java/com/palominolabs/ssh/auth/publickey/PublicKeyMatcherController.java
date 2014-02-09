package com.palominolabs.ssh.auth.publickey;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.ThreadSafe;

/**
 * Manages creating PublicKeyMatcher instances using PublicKeyMatcherFactory instances and an AuthorizedKeyDataSource.
 */
@ThreadSafe
public interface PublicKeyMatcherController {

    /**
     * @param dataSource key source
     * @param factories  factories to use on authorized keys. Factories will only be invoked on keys whose type matches
     *                   {@link PublicKeyMatcherFactory#getKeyType()}}.
     * @return matchers created by factories
     */
    @Nonnull
    Iterable<PublicKeyMatcher> getMatchers(@Nonnull AuthorizedKeyDataSource dataSource,
        @Nonnull Iterable<PublicKeyMatcherFactory> factories);
}
