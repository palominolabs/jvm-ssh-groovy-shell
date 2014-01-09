package com.palominolabs.groovy.ssh;

import groovy.lang.Binding;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.codehaus.groovy.tools.shell.Groovysh;
import org.codehaus.groovy.tools.shell.IO;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.Executor;

final class GroovyShellCommand implements Runnable, Command {

    private final Binding binding;
    private final Executor executor;
    private InputStream inputStream;
    private OutputStream outputStream;
    private OutputStream errorStream;

    GroovyShellCommand(Binding binding, Executor executor) {

        this.binding = binding;
        this.executor = executor;
    }

    @Override
    public void setInputStream(InputStream in) {
        inputStream = in;
    }

    @Override
    public void setOutputStream(OutputStream out) {
        outputStream = out;
    }

    @Override
    public void setErrorStream(OutputStream err) {
        errorStream = err;
    }

    @Override
    public void setExitCallback(ExitCallback callback) {
        // TODO
    }

    @Override
    public void start(Environment env) throws IOException {
        executor.execute(this);
    }

    @Override
    public void destroy() {
        // TODO
    }

    @Override
    public void run() {
        IO io = new IO(inputStream, outputStream, errorStream);
        new Groovysh(binding, io).run();
    }
}
