package com.palominolabs.ssh.groovy.demo;

import javax.inject.Inject;
import javax.inject.Singleton;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Singleton
public class TimeServlet extends HttpServlet {
    private final TimeSource timeSource;

    @Inject
    public TimeServlet(TimeSource timeSource) {
        this.timeSource = timeSource;
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setCharacterEncoding(StandardCharsets.UTF_8.name());
        resp.getWriter().println(timeSource.now().toString());
    }
}
