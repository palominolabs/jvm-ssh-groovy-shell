package com.palominolabs.ssh.auth.publickey.rsa;

import com.palominolabs.ssh.auth.publickey.PublicKeyLoader;
import com.palominolabs.ssh.auth.publickey.PublicKeyMatcher;
import com.palominolabs.ssh.auth.publickey.rfc4253.SshRsaPublicKeyParser;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;
import java.security.spec.InvalidKeySpecException;

/**
 * OpenSSH RSA key parser, guided by http://stackoverflow.com/questions/3531506/using-public-key-from-authorized-keys-with-java-security
 * and http://stackoverflow.com/questions/12749858/rsa-public-key-format and http://blog.oddbit.com/2011/05/08/converting-openssh-public-keys/
 */
@Immutable
class RsaPublicKeyLoader implements PublicKeyLoader {

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
