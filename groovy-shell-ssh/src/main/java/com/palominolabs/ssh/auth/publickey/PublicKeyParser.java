package com.palominolabs.ssh.auth.publickey;

import javax.annotation.concurrent.ThreadSafe;
import java.security.PublicKey;

/**
 * Extracts a certain type of PublicKey from encoded bytes.
 */
@ThreadSafe
public interface PublicKeyParser {

    /**
     * @param data PEM encoded key data
     * @return
     */
    PublicKey parse(byte[] data);
}
