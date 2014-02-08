package com.palominolabs.ssh.auth.publickey;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.ThreadSafe;
import java.security.PublicKey;

/**
 * Extracts a of PublicKey from encoded bytes.
 */
@ThreadSafe
public interface PublicKeyParser {

    /**
     * This type is used to match the incoming key type from the SSH authentication attempt as well as loading keys from
     * an authorized_keys file.
     *
     * @return the key type that this parser can handle (e.g. "ssh-rsa").
     */
    @Nonnull
    String getKeyType();

    /**
     * @param data PEM encoded key data
     * @return PublicKey instance
     */
    PublicKey parse(byte[] data);
}
