package com.palominolabs.ssh.auth.publickey.dsa;

import com.google.common.annotations.VisibleForTesting;
import com.palominolabs.ssh.auth.publickey.PublicKeyMatcher;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.NotThreadSafe;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;

@NotThreadSafe
final class DsaPublicKeyMatcher implements PublicKeyMatcher {

    private final DSAPublicKey key;
    private final String comment;

    DsaPublicKeyMatcher(@Nonnull DSAPublicKey key, String comment) {
        this.key = key;
        this.comment = comment;
    }

    @Override
    public boolean isMatch(@Nonnull PublicKey key) {
        throw new UnsupportedOperationException();
    }

    @Nonnull
    @Override
    public String getComment() {
        return comment;
    }

    @VisibleForTesting
    DSAPublicKey getKey() {
        return key;
    }
}
