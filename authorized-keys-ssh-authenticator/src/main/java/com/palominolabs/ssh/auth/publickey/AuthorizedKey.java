package com.palominolabs.ssh.auth.publickey;

import javax.annotation.Nonnull;

/**
 * Encapsulates the result of parsing a line of an SSH authorized_keys file.
 */
public final class AuthorizedKey {
    private final String type;
    private final byte[] data;
    private final String comment;

    public AuthorizedKey(@Nonnull String type, @Nonnull byte[] data, @Nonnull String comment) {
        this.type = type;
        this.data = data;
        this.comment = comment;
    }

    /**
     * @return key type (e.g. "ssh-rsa")
     */
    @Nonnull
    public String getType() {
        return type;
    }

    /**
     * @return encoded key data in RFC 4253 format
     */
    @Nonnull
    public byte[] getData() {
        return data;
    }

    /**
     * @return key comment
     */
    @Nonnull
    public String getComment() {
        return comment;
    }
}
