package com.palominolabs.groovy.ssh;

import groovy.lang.Binding;
import org.apache.sshd.common.Factory;
import org.apache.sshd.server.Command;

import java.util.concurrent.Executor;

public final class GroovyShellCommandFactory implements Factory<Command> {
    private final Binding binding;
    private final Executor executor;

    public GroovyShellCommandFactory(Binding binding, Executor executor) {
        this.binding = binding;
        this.executor = executor;
    }

    @Override
    public Command create() {
        return new GroovyShellCommand(binding, executor);
    }
}
