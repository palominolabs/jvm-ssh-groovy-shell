package com.palominolabs.ssh.auth.publickey;

import javax.annotation.Nonnull;
import java.security.PublicKey;

class FakePublicKeyMatcher implements PublicKeyMatcher {

    private final byte[] data;
    private final String comment;
    private final boolean shouldMatch;

    FakePublicKeyMatcher(byte[] data, String comment, boolean shouldMatch) {
        this.data = data;
        this.comment = comment;
        this.shouldMatch = shouldMatch;
    }

    @Override
    public boolean isMatch(@Nonnull PublicKey key) {
        return shouldMatch;
    }

    @Nonnull
    @Override
    public String getComment() {
        return comment;
    }

    byte[] getData() {
        return data;
    }
}
