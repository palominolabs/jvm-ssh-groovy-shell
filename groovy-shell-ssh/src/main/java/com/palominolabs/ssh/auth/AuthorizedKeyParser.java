package com.palominolabs.ssh.auth;

import com.google.common.base.Predicate;
import com.google.common.collect.Collections2;
import com.google.common.io.BaseEncoding;
import com.palominolabs.ssh.auth.publickey.PublicKeyParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.google.common.collect.Iterables.getOnlyElement;

@Immutable
final class AuthorizedKeyParser {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizedKeyParser.class);

    private static final Pattern KEY_PATTERN = Pattern.compile("^([-a-z\\d]+) ([a-zA-Z0-9/+=]+) ([^ ]+)$");

    private final List<PublicKeyParser> handlers;

    AuthorizedKeyParser(List<PublicKeyParser> handlers) {
        this.handlers = handlers;
    }

    @Nonnull
    List<AuthorizedKey> parse(@Nonnull InputStream keyData) throws IOException {

        List<AuthorizedKey> keys = new ArrayList<>();

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

                Matcher matcher = KEY_PATTERN.matcher(line);
                if (!matcher.matches()) {
                    logger.warn("Line " + lineNum + ": Could not parse line: <" + line + ">");
                    continue;
                }

                final String type = matcher.group(1);

                PublicKeyParser parser = getOnlyElement(
                    Collections2.filter(handlers, new Predicate<PublicKeyParser>() {
                        @Override
                        public boolean apply(@Nullable PublicKeyParser input) {
                            return input.getKeyType().equals(type);
                        }
                    }), null);

                if (parser == null) {
                    logger.warn("Line " + lineNum + ": Invalid key type: <" + type + ">");
                    continue;
                }

                String keyBase64 = matcher.group(2);
                PublicKey key = parser.parse(BaseEncoding.base64().decode(keyBase64));

                String comment = matcher.group(3);

                keys.add(new AuthorizedKey(type, key, comment));
            }
        }

        return keys;
    }
}
