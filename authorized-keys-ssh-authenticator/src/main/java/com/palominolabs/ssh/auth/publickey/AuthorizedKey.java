package com.palominolabs.ssh.auth.publickey;

import javax.annotation.Nonnull;

public final class AuthorizedKey {
    private final String type;
    private final byte[] data;
    private final String comment;

    public AuthorizedKey(@Nonnull String type, @Nonnull byte[] data, @Nonnull String comment) {
        this.type = type;
        this.data = data;
        this.comment = comment;
    }

    @Nonnull
    public String getType() {
        return type;
    }

    @Nonnull
    public byte[] getData() {
        return data;
    }

    @Nonnull
    public String getComment() {
        return comment;
    }
}
