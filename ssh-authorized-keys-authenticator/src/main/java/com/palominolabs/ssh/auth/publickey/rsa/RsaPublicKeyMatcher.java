package com.palominolabs.ssh.auth.publickey.rsa;

import com.google.common.annotations.VisibleForTesting;
import com.palominolabs.ssh.auth.publickey.PublicKeyMatcher;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.NotThreadSafe;
import java.security.MessageDigest;
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

        // this does require allocation to get the byte arrays, but it allows us to use the timing-attack-resistant
        // comparison from MessageDigest
        boolean ok = MessageDigest
            .isEqual(authorizedKey.getPublicExponent().toByteArray(), other.getPublicExponent().toByteArray());
        ok &= MessageDigest.isEqual(authorizedKey.getModulus().toByteArray(), other.getModulus().toByteArray());
        ok &= Objects.equals(authorizedKey.getAlgorithm(), other.getAlgorithm());

        return ok;
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
