package com.palominolabs.ssh.auth.publickey.rsa;

import com.google.common.annotations.VisibleForTesting;
import com.palominolabs.ssh.auth.publickey.PublicKeyMatcher;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.NotThreadSafe;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

@NotThreadSafe
class RsaPublicKeyMatcher implements PublicKeyMatcher {

    private final RSAPublicKey authorizedKey;
    private final String comment;

    RsaPublicKeyMatcher(RSAPublicKey authorizedKey, String comment) {
        this.authorizedKey = authorizedKey;
        this.comment = comment;
    }

    @Override
    public boolean isMatch(@Nonnull PublicKey key) {
        if (!(key instanceof RSAPublicKey)) {
            return false;
        }

        RSAPublicKey other = (RSAPublicKey) key;

        // TODO avoid timing side channel attack
        return Objects.equals(authorizedKey.getPublicExponent(), other.getPublicExponent())
            && Objects.equals(authorizedKey.getModulus(), other.getModulus())
            && Objects.equals(authorizedKey.getAlgorithm(), other.getAlgorithm());
    }

    @Nonnull
    @Override
    public String getComment() {
        return comment;
    }

    @VisibleForTesting
    RSAPublicKey getKey() {
        return authorizedKey;
    }
}
