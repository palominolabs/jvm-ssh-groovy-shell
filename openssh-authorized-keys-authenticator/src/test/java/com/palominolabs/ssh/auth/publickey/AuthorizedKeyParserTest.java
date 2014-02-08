package com.palominolabs.ssh.auth.publickey;

import com.google.common.collect.Lists;
import com.google.common.io.BaseEncoding;
import org.junit.Before;
import org.junit.Test;

import javax.annotation.Nonnull;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public final class AuthorizedKeyParserTest {

    private AuthorizedKeyParser authorizedKeyParser;

    @Before
    public void setUp() {
        authorizedKeyParser = new AuthorizedKeyParser(Lists.<PublicKeyLoader>newArrayList(new DummyLoader()));
    }

    @Test
    public void testParseValidLine() throws IOException {
        ByteArrayInputStream is =
            new ByteArrayInputStream("dummy aaa comment1\ndummy bbb comment2".getBytes(UTF_8));

        List<PublicKeyMatcher> keys = authorizedKeyParser.parse(is);

        assertEquals(2, keys.size());

        assertKey(keys.get(0), "aaa", "comment1");
        assertKey(keys.get(1), "bbb", "comment2");
    }

    @Test
    public void testSkipsInvalidLnes() throws IOException {
        ByteArrayInputStream is =
            new ByteArrayInputStream("asdf\ndummy bbb comment2\nfoo".getBytes(UTF_8));

        List<PublicKeyMatcher> keys = authorizedKeyParser.parse(is);

        assertEquals(1, keys.size());

        assertKey(keys.get(0), "bbb", "comment2");
    }

    @Test
    public void testSkipsCommentLines() throws IOException {
        ByteArrayInputStream is =
            new ByteArrayInputStream("# foo\ndummy bbb comment2".getBytes(UTF_8));

        List<PublicKeyMatcher> keys = authorizedKeyParser.parse(is);

        assertEquals(1, keys.size());

        assertKey(keys.get(0), "bbb", "comment2");
    }

    private void assertKey(PublicKeyMatcher k0, String data, String comment) {
        BaseEncoding b64 = BaseEncoding.base64();
        assertArrayEquals(b64.decode(data), ((DummyMatcher) k0).data);

        assertEquals(comment, k0.getComment());
    }

    private static class DummyLoader implements PublicKeyLoader {

        @Nonnull
        @Override
        public String getKeyType() {
            return "dummy";
        }

        @Nonnull
        @Override
        public PublicKeyMatcher buildMatcher(byte[] data, String comment) {
            return new DummyMatcher(data, comment);
        }
    }

    private static class DummyMatcher implements PublicKeyMatcher {

        private final byte[] data;
        private final String comment;

        private DummyMatcher(byte[] data, String comment) {
            this.data = data;
            this.comment = comment;
        }

        @Override
        public boolean isMatch(@Nonnull PublicKey key) {
            throw new UnsupportedOperationException();
        }

        @Nonnull
        @Override
        public String getComment() {
            return comment;
        }
    }
}
