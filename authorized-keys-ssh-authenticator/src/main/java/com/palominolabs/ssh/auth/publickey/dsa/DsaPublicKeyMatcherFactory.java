package com.palominolabs.ssh.auth.publickey.dsa;

import com.palominolabs.ssh.auth.publickey.PublicKeyMatcher;
import com.palominolabs.ssh.auth.publickey.PublicKeyMatcherFactory;
import com.palominolabs.ssh.auth.publickey.rfc4253.DsaSshPublicKeyParser;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;
import java.security.spec.InvalidKeySpecException;

@Immutable
public final class DsaPublicKeyMatcherFactory implements PublicKeyMatcherFactory {
    @Nonnull
    @Override
    public String getKeyType() {
        return "ssh-dss";
    }

    @Nonnull
    @Override
    public PublicKeyMatcher buildMatcher(byte[] data, String comment) throws InvalidKeySpecException {
        return new DsaPublicKeyMatcher(new DsaSshPublicKeyParser(data).getKey(), comment);
    }
}
