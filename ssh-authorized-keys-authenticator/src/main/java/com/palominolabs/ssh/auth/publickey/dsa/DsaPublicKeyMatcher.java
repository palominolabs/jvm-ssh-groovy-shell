package com.palominolabs.ssh.auth.publickey.dsa;

import com.google.common.annotations.VisibleForTesting;
import com.palominolabs.ssh.auth.publickey.PublicKeyMatcher;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.NotThreadSafe;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;

@NotThreadSafe
final class DsaPublicKeyMatcher implements PublicKeyMatcher {

    private final DSAPublicKey authorizedKey;
    private final String comment;

    DsaPublicKeyMatcher(@Nonnull DSAPublicKey authorizedKey, String comment) {
        this.authorizedKey = authorizedKey;
        this.comment = comment;
    }

    @Override
    public boolean isMatch(@Nonnull PublicKey key) {
        if (!(key instanceof DSAPublicKey)) {
            return false;
        }

        DSAPublicKey other = (DSAPublicKey) key;

        boolean ok = isEqual(authorizedKey.getY(), other.getY());
        ok &= isEqual(authorizedKey.getParams().getG(), other.getParams().getG());
        ok &= isEqual(authorizedKey.getParams().getP(), other.getParams().getP());
        ok &= isEqual(authorizedKey.getParams().getQ(), other.getParams().getQ());
        ok &= authorizedKey.getAlgorithm().equals(other.getAlgorithm());

        return ok;
    }

    @Nonnull
    @Override
    public String getComment() {
        return comment;
    }

    @VisibleForTesting
    DSAPublicKey getKey() {
        return authorizedKey;
    }

    private static boolean isEqual(BigInteger i1, BigInteger i2) {
        return MessageDigest.isEqual(i1.toByteArray(), i2.toByteArray());
    }
}
