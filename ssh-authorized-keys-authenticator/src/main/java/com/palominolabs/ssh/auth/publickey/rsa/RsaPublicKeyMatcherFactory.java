package com.palominolabs.ssh.auth.publickey.rsa;

import com.palominolabs.ssh.auth.publickey.PublicKeyMatcherFactory;
import com.palominolabs.ssh.auth.publickey.PublicKeyMatcher;
import com.palominolabs.ssh.auth.publickey.rfc4253.SshRsaPublicKeyParser;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;
import java.security.spec.InvalidKeySpecException;

@Immutable
class RsaPublicKeyMatcherFactory implements PublicKeyMatcherFactory {

    @Nonnull
    @Override
    public String getKeyType() {
        return "ssh-rsa";
    }

    @Nonnull
    @Override
    public PublicKeyMatcher buildMatcher(byte[] data, String comment) throws InvalidKeySpecException {
        return new RsaPublicKeyMatcher(new SshRsaPublicKeyParser(data).getKey(), comment);
    }
}
