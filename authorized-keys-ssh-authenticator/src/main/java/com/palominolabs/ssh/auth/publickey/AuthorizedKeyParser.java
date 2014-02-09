package com.palominolabs.ssh.auth.publickey;

import com.google.common.base.Predicate;
import com.google.common.io.BaseEncoding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.google.common.collect.Iterables.filter;
import static com.google.common.collect.Iterables.getFirst;

@Immutable
final class AuthorizedKeyParser {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizedKeyParser.class);

    private static final Pattern KEY_PATTERN = Pattern.compile("^([-a-z\\d]+) ([a-zA-Z0-9/+=]+) ([^ ]+)$");

    private final Iterable<PublicKeyMatcherFactory> matcherFactories;

    AuthorizedKeyParser(Iterable<PublicKeyMatcherFactory> matcherFactories) {
        this.matcherFactories = matcherFactories;
    }

    /**
     * Load key matchers from an authorized_keys input stream.
     *
     * @param keyData authorized_keys data
     * @return a list of matchers
     * @throws IOException if key data can't be read
     */
    @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
    @Nonnull
    Iterable<PublicKeyMatcher> parse(@Nonnull InputStream keyData) throws IOException {

        List<PublicKeyMatcher> matchers = new ArrayList<>();

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

                final String type = matcher.group(1);

                PublicKeyMatcherFactory factory = getFirst(filter(matcherFactories, new KeyTypePredicate(type)), null);

                if (factory == null) {
                    logger.warn("Line " + lineNum + ": Invalid key type: <" + type + ">");
                    continue;
                }

                String keyBase64 = matcher.group(2);
                String comment = matcher.group(3);

                try {
                    matchers.add(factory.buildMatcher(BaseEncoding.base64().decode(keyBase64), comment));
                } catch (InvalidKeySpecException e) {
                    logger.warn("Could not parse key data", e);
                }
            }

            if (scanner.ioException() != null) {
                throw scanner.ioException();
            }
        }

        return matchers;
    }

    private static class KeyTypePredicate implements Predicate<PublicKeyMatcherFactory> {
        private final String type;

        private KeyTypePredicate(String type) {
            this.type = type;
        }

        @Override
        public boolean apply(@Nullable PublicKeyMatcherFactory input) {
            return input.getKeyType().equals(type);
        }
    }
}
