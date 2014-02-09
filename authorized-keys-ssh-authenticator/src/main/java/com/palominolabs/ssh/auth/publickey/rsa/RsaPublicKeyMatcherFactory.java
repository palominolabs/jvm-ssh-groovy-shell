package com.palominolabs.ssh.auth.publickey.rsa;

import com.palominolabs.ssh.auth.publickey.AuthorizedKey;
import com.palominolabs.ssh.auth.publickey.PublicKeyMatcher;
import com.palominolabs.ssh.auth.publickey.PublicKeyMatcherFactory;
import com.palominolabs.ssh.auth.publickey.rfc4253.RsaSshPublicKeyParser;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;
import java.security.spec.InvalidKeySpecException;

/**
 * Builds PublicKeyMatcher instances for RSA keys (type "ssh-rsa").
 */
@Immutable
public class RsaPublicKeyMatcherFactory implements PublicKeyMatcherFactory {

    @Nonnull
    @Override
    public String getKeyType() {
        return "ssh-rsa";
    }

    @Nonnull
    @Override
    public PublicKeyMatcher buildMatcher(AuthorizedKey key) throws InvalidKeySpecException {
        return new RsaPublicKeyMatcher(new RsaSshPublicKeyParser(key.getData()).getKey(), key.getComment());
    }
}
