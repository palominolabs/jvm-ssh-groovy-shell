package com.palominolabs.groovy.ssh.demo;

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.servlet.ServletModule;
import com.palominolabs.ssh.groovy.GroovyShellCommandFactory;
import com.palominolabs.http.server.HttpServerConnectorConfig;
import com.palominolabs.http.server.HttpServerWrapperConfig;
import com.palominolabs.http.server.HttpServerWrapperFactory;
import com.palominolabs.http.server.HttpServerWrapperModule;
import groovy.lang.Binding;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.auth.UserAuthNone;
import org.apache.sshd.server.keyprovider.PEMGeneratorHostKeyProvider;

import java.io.IOException;
import java.util.ArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public final class DemoMain {
    public static void main(String[] args) throws Exception {
        Injector injector = getInjector();

        startHttpServer(injector);

        startSshServer(injector);
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

    private static void startSshServer(Injector injector) throws IOException {
        SshServer sshd = SshServer.setUpDefaultServer();

        sshd.setPort(10222);

        sshd.setKeyPairProvider(new PEMGeneratorHostKeyProvider("hostkey.pem", "DSA", 1024));

        Binding binding = new Binding();
        binding.setProperty("injector", injector);
        binding.setProperty("timeSource", injector.getInstance(TimeSource.class));

        Executor executor = Executors.newCachedThreadPool();
        sshd.setShellFactory(new GroovyShellCommandFactory(binding, executor));
        ArrayList<NamedFactory<UserAuth>> userAuthFactories = new ArrayList<NamedFactory<UserAuth>>();
        userAuthFactories.add(new UserAuthNone.Factory());
        sshd.setUserAuthFactories(userAuthFactories);

        // starts a daemon thread; you'll need something else running to keep the jvm up
        sshd.start();
    }
}
