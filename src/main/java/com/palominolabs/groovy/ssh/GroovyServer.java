package com.palominolabs.groovy.ssh;

import groovy.lang.Binding;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.auth.UserAuthNone;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;

import java.io.IOException;
import java.util.ArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

final class GroovyServer {
    void go() throws IOException, InterruptedException {
        SshServer sshd = SshServer.setUpDefaultServer();

        sshd.setPort(10222);

        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());

        Binding binding = new Binding();
        Executor executor = Executors.newCachedThreadPool();
        sshd.setShellFactory(new GroovyShellCommandFactory(binding, executor));
        ArrayList<NamedFactory<UserAuth>> userAuthFactories = new ArrayList<>();
        userAuthFactories.add(new UserAuthNone.Factory());
        sshd.setUserAuthFactories(userAuthFactories);

        sshd.start();

        Thread.sleep(100000000);
    }

    public static void main(String[] args) throws IOException, InterruptedException {
        new GroovyServer().go();
    }
}
