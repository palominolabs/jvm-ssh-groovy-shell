package com.palominolabs.ssh.auth.publickey;

import javax.annotation.Nonnull;

class FakePublicKeyLoader implements PublicKeyLoader {

    private final boolean matcherShouldMatch;

    FakePublicKeyLoader(boolean matcherShouldMatch) {
        this.matcherShouldMatch = matcherShouldMatch;
    }

    @Nonnull
    @Override
    public String getKeyType() {
        return "dummy";
    }

    @Nonnull
    @Override
    public PublicKeyMatcher buildMatcher(byte[] data, String comment) {
        return new FakePublicKeyMatcher(data, comment, matcherShouldMatch);
    }
}
