package com.palominolabs.ssh.auth.publickey;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;

/**
 * A source of keys to authenticate against.
 */
@ThreadSafe
public interface AuthorizedKeyDataSource {

    /**
     * Load the keys in an implementation-defined way. This will be called on every authentication request.
     *
     * @return loaded keys
     * @throws IOException on i/o errors
     */
    @Nonnull
    Iterable<AuthorizedKey> loadKeys() throws IOException;
}
