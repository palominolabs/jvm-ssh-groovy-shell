package com.palominolabs.ssh.auth.publickey;

import com.google.common.collect.Lists;
import com.google.common.io.BaseEncoding;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;

import static com.google.common.collect.Lists.newArrayList;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public final class AuthorizedKeyParserTest {

    private AuthorizedKeyParser authorizedKeyParser;

    @Before
    public void setUp() {
        authorizedKeyParser =
            new AuthorizedKeyParser(
                Lists.<PublicKeyMatcherFactory>newArrayList(new FakePublicKeyMatcherFactory(false)));
    }

    @Test
    public void testParseValidLine() throws IOException {
        ByteArrayInputStream is =
            new ByteArrayInputStream("dummy aaa comment1\ndummy bbb comment2".getBytes(UTF_8));

        List<PublicKeyMatcher> keys = newArrayList(authorizedKeyParser.parse(is));

        assertEquals(2, keys.size());

        assertKey(keys.get(0), "aaa", "comment1");
        assertKey(keys.get(1), "bbb", "comment2");
    }

    @Test
    public void testSkipsInvalidLnes() throws IOException {
        ByteArrayInputStream is =
            new ByteArrayInputStream("asdf\ndummy bbb comment2\nfoo".getBytes(UTF_8));

        List<PublicKeyMatcher> keys = newArrayList(authorizedKeyParser.parse(is));

        assertEquals(1, keys.size());

        assertKey(keys.get(0), "bbb", "comment2");
    }

    @Test
    public void testSkipsCommentLines() throws IOException {
        ByteArrayInputStream is =
            new ByteArrayInputStream("# foo\ndummy bbb comment2".getBytes(UTF_8));

        List<PublicKeyMatcher> keys = newArrayList(authorizedKeyParser.parse(is));

        assertEquals(1, keys.size());

        assertKey(keys.get(0), "bbb", "comment2");
    }

    @Test
    public void testSkipsUnknownTypeLines() throws IOException {
        ByteArrayInputStream is =
            new ByteArrayInputStream("dummy2 aaa comment1\ndummy bbb comment2".getBytes(UTF_8));

        List<PublicKeyMatcher> keys = newArrayList(authorizedKeyParser.parse(is));

        assertEquals(1, keys.size());

        assertKey(keys.get(0), "bbb", "comment2");
    }

    private void assertKey(PublicKeyMatcher k0, String data, String comment) {
        BaseEncoding b64 = BaseEncoding.base64();
        assertArrayEquals(b64.decode(data), ((FakePublicKeyMatcher) k0).getData());

        assertEquals(comment, k0.getComment());
    }
}
