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
     * This type is used to match the incoming key type from the SSH authentication attempt as well as loading keys from
     * an authorized_keys file.
     *
     * @return the key type that this factory can handle (e.g. "ssh-rsa").
     */
    @Nonnull
    String getKeyType();

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
