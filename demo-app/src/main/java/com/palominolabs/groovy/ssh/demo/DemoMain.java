package com.palominolabs.groovy.ssh.demo;

import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.servlet.ServletModule;
import com.palominolabs.http.server.HttpServerConnectorConfig;
import com.palominolabs.http.server.HttpServerWrapperConfig;
import com.palominolabs.http.server.HttpServerWrapperFactory;
import com.palominolabs.http.server.HttpServerWrapperModule;
import com.palominolabs.ssh.auth.publickey.AuthorizedKeyDataSource;
import com.palominolabs.ssh.auth.publickey.AuthorizedKeysPublicKeyController;
import com.palominolabs.ssh.auth.publickey.AuthorizedKeysPublickeyAuthenticator;
import com.palominolabs.ssh.auth.publickey.InputStreamAuthorizedKeyDataSource;
import com.palominolabs.ssh.auth.publickey.PublicKeyMatcherController;
import com.palominolabs.ssh.auth.publickey.PublicKeyMatcherFactory;
import com.palominolabs.ssh.auth.publickey.dsa.DsaPublicKeyMatcherFactory;
import com.palominolabs.ssh.auth.publickey.rsa.RsaPublicKeyMatcherFactory;
import com.palominolabs.ssh.groovy.GroovyShellCommandFactory;
import groovy.lang.Binding;
import org.apache.sshd.SshServer;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.auth.UserAuthNone;
import org.apache.sshd.server.auth.UserAuthPublicKey;
import org.apache.sshd.server.keyprovider.PEMGeneratorHostKeyProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public final class DemoMain {
    public static void main(String[] args) throws Exception {
        Injector injector = getInjector();

        startHttpServer(injector);

        PublickeyAuthenticator authenticator = null;
        if (args.length == 1) {
            // user provided an authorized_keys path
            final File authorizedKeys = new File(args[0]);

            // we want to read RSA and DSA keys
            List<PublicKeyMatcherFactory> factories =
                Lists.newArrayList(new RsaPublicKeyMatcherFactory(), new DsaPublicKeyMatcherFactory());

            // read keys from an ssh authorized_keys file
            AuthorizedKeyDataSource dataSource = new InputStreamAuthorizedKeyDataSource(
                new InputStreamSupplier(authorizedKeys));
            PublicKeyMatcherController controller = new AuthorizedKeysPublicKeyController(dataSource);

            // configure the authenticator with the above
            authenticator = new AuthorizedKeysPublickeyAuthenticator(factories, controller);
        }

        startSshServer(injector, authenticator);
    }

    private static void startHttpServer(Injector injector) throws Exception {
        HttpServerWrapperConfig config = new HttpServerWrapperConfig()
            .withHttpServerConnectorConfig(HttpServerConnectorConfig.forHttp("localhost", 8080));

        injector.getInstance(HttpServerWrapperFactory.class).getHttpServerWrapper(config).start();
    }

    private static Injector getInjector() {
        return Guice.createInjector(new AbstractModule() {
            @Override
            protected void configure() {
                binder().requireExplicitBindings();
                install(new HttpServerWrapperModule());
                install(new ServletModule() {
                    @Override
                    protected void configureServlets() {
                        bind(TimeServlet.class);
                        serve("/nowUtc").with(TimeServlet.class);
                    }
                });

                bind(TimeSource.class);
            }
        });
    }

    private static void startSshServer(Injector injector, @Nullable PublickeyAuthenticator authenticator) throws
        IOException {
        SshServer sshd = SshServer.setUpDefaultServer();

        sshd.setPort(10222);

        sshd.setKeyPairProvider(new PEMGeneratorHostKeyProvider("demo-hostkey.pem", "DSA", 1024));

        Binding binding = new Binding();
        binding.setProperty("injector", injector);
        binding.setProperty("timeSource", injector.getInstance(TimeSource.class));

        Executor executor = Executors.newCachedThreadPool();
        sshd.setShellFactory(new GroovyShellCommandFactory(binding, executor));

        if (authenticator == null) {
            // allow all users
            sshd.setUserAuthFactories(ImmutableList.of(new UserAuthNone.Factory()));
        } else {
            sshd.setUserAuthFactories(ImmutableList.of(new UserAuthPublicKey.Factory()));
            sshd.setPublickeyAuthenticator(authenticator);
        }

        // starts a daemon thread; you'll need something else running to keep the jvm up
        sshd.start();
    }

    private static class InputStreamSupplier implements Supplier<InputStream> {
        private static final Logger logger = LoggerFactory.getLogger(InputStreamSupplier.class);
        private final File authorizedKeys;

        private InputStreamSupplier(File authorizedKeys) {
            this.authorizedKeys = authorizedKeys;
        }

        @Override
        public InputStream get() {
            try {
                return new FileInputStream(authorizedKeys);
            } catch (FileNotFoundException e) {
                logger.warn("Couldn't load key file", e);
                return null;
            }
        }
    }
}
