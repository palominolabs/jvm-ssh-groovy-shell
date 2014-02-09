package com.palominolabs.ssh.auth.publickey.dsa;

import com.palominolabs.ssh.auth.publickey.AuthorizedKey;
import com.palominolabs.ssh.auth.publickey.PublicKeyMatcher;
import com.palominolabs.ssh.auth.publickey.PublicKeyMatcherFactory;
import com.palominolabs.ssh.auth.publickey.rfc4253.DsaSshPublicKeyParser;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;
import java.security.spec.InvalidKeySpecException;

/**
 * Builds PublicKeyMatcher instances for DSA keys (type "ssh-dss").
 */
@Immutable
public final class DsaPublicKeyMatcherFactory implements PublicKeyMatcherFactory {
    @Nonnull
    @Override
    public String getKeyType() {
        return "ssh-dss";
    }

    @Nonnull
    @Override
    public PublicKeyMatcher buildMatcher(AuthorizedKey key) throws InvalidKeySpecException {
        return new DsaPublicKeyMatcher(new DsaSshPublicKeyParser(key.getData()).getKey(), key.getComment());
    }
}
