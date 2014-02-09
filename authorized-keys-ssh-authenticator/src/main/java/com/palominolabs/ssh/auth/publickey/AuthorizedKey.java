package com.palominolabs.ssh.auth.publickey;

import javax.annotation.Nonnull;

final class AuthorizedKey {
    private final String type;
    private final byte[] data;
    private final String comment;

    AuthorizedKey(@Nonnull String type, @Nonnull byte[] data, @Nonnull String comment) {
        this.type = type;
        this.data = data;
        this.comment = comment;
    }

    @Nonnull
    String getType() {
        return type;
    }

    @Nonnull
    byte[] getData() {
        return data;
    }

    @Nonnull
    String getComment() {
        return comment;
    }
}
