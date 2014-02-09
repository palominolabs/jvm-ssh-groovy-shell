package com.palominolabs.ssh.auth.publickey;

import javax.annotation.Nonnull;
import java.security.spec.InvalidKeySpecException;

class FakePublicKeyMatcherFactory implements PublicKeyMatcherFactory {

    static final String TYPE = "dummy";

    @Nonnull
    @Override
    public String getKeyType() {
        return TYPE;
    }

    @Nonnull
    @Override
    public PublicKeyMatcher buildMatcher(AuthorizedKey key) throws InvalidKeySpecException {
        return new FakePublicKeyMatcher(key.getData(), key.getComment(), false);
    }
}
