package com.palominolabs.ssh.auth.publickey;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

@Immutable
class RsaPublicKeyMatcher implements KeyMatcher {

    @Override
    public boolean matches(@Nonnull PublicKey key1, @Nonnull PublicKey key2) {
        RSAPublicKey r1 = (RSAPublicKey) key1;
        RSAPublicKey r2 = (RSAPublicKey) key2;

        return Objects.equals(r1.getPublicExponent(), r2.getPublicExponent())
            && Objects.equals(r1.getModulus(), r2.getModulus())
            && Objects.equals(r1.getAlgorithm(), r2.getAlgorithm());
    }
}
