package com.palominolabs.ssh.auth.publickey;

import com.google.common.io.BaseEncoding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Immutable
final class AuthorizedKeyParser {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizedKeyParser.class);

    private static final Pattern KEY_PATTERN = Pattern.compile("^([-a-z\\d]+) ([a-zA-Z0-9/+=]+) ([^ ]+)$");

    /**
     * Load key data from an authorized_keys input stream.
     *
     * @param keyData authorized_keys data
     * @return a list of keys
     * @throws IOException if key data can't be read
     */
    @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
    @Nonnull
    Iterable<AuthorizedKey> parse(@Nonnull InputStream keyData) throws IOException {

        List<AuthorizedKey> keys = new ArrayList<>();

        try (Scanner scanner = new Scanner(keyData, StandardCharsets.UTF_8.name())) {
            int lineNum = 0;
            while (scanner.hasNextLine()) {
                if (scanner.ioException() != null) {
                    throw scanner.ioException();
                }

                lineNum++;
                String line = scanner.nextLine();

                if (scanner.ioException() != null) {
                    throw scanner.ioException();
                }

                if (line.charAt(0) == '#') {
                    logger.debug("Skipping comment line {}", line);
                    continue;
                }

                Matcher matcher = KEY_PATTERN.matcher(line);
                if (!matcher.matches()) {
                    logger.warn("Line " + lineNum + ": Could not parse line: <" + line + ">");
                    continue;
                }

                String type = matcher.group(1);
                byte[] data = BaseEncoding.base64().decode(matcher.group(2));
                String comment = matcher.group(3);

                keys.add(new AuthorizedKey(type, data, comment));
            }

            if (scanner.ioException() != null) {
                throw scanner.ioException();
            }
        }

        return keys;
    }
}
