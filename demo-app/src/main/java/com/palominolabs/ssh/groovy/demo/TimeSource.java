package com.palominolabs.ssh.groovy.demo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.ThreadSafe;
import javax.inject.Singleton;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/**
 * Just a dummy class so we have something to inject
 */
@ThreadSafe
@Singleton
public class TimeSource {
    private static final Logger logger = LoggerFactory.getLogger(TimeSource.class);

    private volatile int secondsOffset = 0;

    /**
     * Perform deep and mystical calculations to get the current time.
     *
     * @return now in UTC, offset by whatever number of seconds
     */
    @Nonnull
    public OffsetDateTime now() {
        return OffsetDateTime.now(ZoneOffset.UTC).plusSeconds(secondsOffset);
    }

    /**
     * A meaningless mutable thing to demonstrate the utility of the groovy shell
     *
     * @param seconds an offset in seconds to apply when calculating now(). Positive values will move time forward,
     *                negative values will move it backwards.
     */
    public void setSecondsOffset(int seconds) {
        logger.info("Setting offset to " + seconds);
        this.secondsOffset = seconds;
    }
}
