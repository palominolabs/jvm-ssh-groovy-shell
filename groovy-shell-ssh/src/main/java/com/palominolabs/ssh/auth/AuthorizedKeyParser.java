package com.palominolabs.ssh.auth;

import com.google.common.base.Predicate;
import com.google.common.io.BaseEncoding;
import com.palominolabs.ssh.auth.publickey.PublicKeyLoader;
import com.palominolabs.ssh.auth.publickey.PublicKeyMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.google.common.collect.Collections2.filter;
import static com.google.common.collect.Iterables.getFirst;

@Immutable
final class AuthorizedKeyParser {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizedKeyParser.class);

    private static final Pattern KEY_PATTERN = Pattern.compile("^([-a-z\\d]+) ([a-zA-Z0-9/+=]+) ([^ ]+)$");

    private final List<PublicKeyLoader> loaders;

    AuthorizedKeyParser(List<PublicKeyLoader> loaders) {
        this.loaders = loaders;
    }

    /**
     * Load key matchers from an authorized_keys input stream.
     *
     * @param keyData authorized_keys data
     * @return a list of matchers
     * @throws IOException if key data can't be read
     */
    @Nonnull
    List<PublicKeyMatcher> parse(@Nonnull InputStream keyData) throws IOException {

        List<PublicKeyMatcher> keys = new ArrayList<>();

        try (Scanner scanner = new Scanner(keyData, StandardCharsets.UTF_8.name())) {
            int lineNum = 0;
            while (scanner.hasNextLine()) {
                lineNum++;
                String line = scanner.nextLine();

                IOException e = scanner.ioException();
                if (e != null) {
                    logger.warn("Read failed", e);
                    throw e;
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

                final String type = matcher.group(1);

                PublicKeyLoader loader = getFirst(filter(loaders, new KeyTypePredicate(type)), null);

                if (loader == null) {
                    logger.warn("Line " + lineNum + ": Invalid key type: <" + type + ">");
                    continue;
                }

                String keyBase64 = matcher.group(2);
                String comment = matcher.group(3);

                keys.add(loader.buildMatcher(BaseEncoding.base64().decode(keyBase64), comment));
            }
        }

        return keys;
    }

    private static class KeyTypePredicate implements Predicate<PublicKeyLoader> {
        private final String type;

        private KeyTypePredicate(String type) {
            this.type = type;
        }

        @Override
        public boolean apply(@Nullable PublicKeyLoader input) {
            return input.getKeyType().equals(type);
        }
    }
}
