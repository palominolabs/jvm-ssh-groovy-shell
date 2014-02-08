package com.palominolabs.ssh.auth;

import java.security.PublicKey;

/**
 * Represents a parsed key from an OpenSSH authorized_keys file.
 */
final class AuthorizedKey {

    private final String keyType;

    private final PublicKey publicKey;

    private final String comment;

    /**
     * @param keyType   key type; must be one of VALID_KEY_TYPES
     * @param publicKey raw key bytes; ownership is claimed by this object
     * @param comment   key comment
     */
    AuthorizedKey(String keyType, PublicKey publicKey, String comment) {
        this.keyType = keyType;
        this.publicKey = publicKey;
        this.comment = comment;
    }

    public String getKeyType() {
        return keyType;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String getComment() {
        return comment;
    }
}
