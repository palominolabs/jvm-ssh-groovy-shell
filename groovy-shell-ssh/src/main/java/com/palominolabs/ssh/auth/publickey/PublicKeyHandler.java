package com.palominolabs.ssh.auth.publickey;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.ThreadSafe;
import java.security.PublicKey;

/**
 * Packages the various aspects of SSH public key handling.
 */
@ThreadSafe
public interface PublicKeyHandler {

    /**
     * Used to match against {@link PublicKey#getAlgorithm()}
     *
     * @return a JCA crypto algorithm name
     */
    @Nonnull
    String getJavaAlgorithmName();

    /**
     * @return the PublicKey subclass that this factory can generate via its parser
     */
    @Nonnull
    Class<? extends PublicKey> getKeyClass();

    /**
     * @return a parser that can generate PublicKey instances of the type specified by {@link
     * PublicKeyHandler#getKeyClass()}.
     */
    @Nonnull
    PublicKeyParser getParser();

    /**
     * @return a KeyMatcher that can compare instances of the class indicated by {@link PublicKeyHandler#getKeyClass()}
     */
    @Nonnull
    KeyMatcher getKeyMatcher();
}
