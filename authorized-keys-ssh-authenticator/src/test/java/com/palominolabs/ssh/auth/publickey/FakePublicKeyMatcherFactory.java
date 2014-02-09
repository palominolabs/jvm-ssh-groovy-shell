package com.palominolabs.ssh.auth.publickey;

import javax.annotation.Nonnull;
import java.security.spec.InvalidKeySpecException;

class FakePublicKeyMatcherFactory implements PublicKeyMatcherFactory {

    @Nonnull
    @Override
    public String getKeyType() {
        return "dummy";
    }

    @Nonnull
    @Override
    public PublicKeyMatcher buildMatcher(AuthorizedKey key) throws InvalidKeySpecException {
        return new FakePublicKeyMatcher(key.getData(), key.getComment(), false);
    }
}
