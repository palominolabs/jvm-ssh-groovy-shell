package com.palominolabs.ssh.auth.publickey;

import javax.annotation.Nonnull;

// TODO rename
public interface PublicKeyMatcherController {

    @Nonnull
    Iterable<PublicKeyMatcher> getMatchers(@Nonnull Iterable<PublicKeyMatcherFactory> factories);
}
