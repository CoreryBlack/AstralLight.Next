package com.coreryblack.benchmark.util;

import com.coreryblack.benchmark.nativebenchmark.NativeDataGenerator;
import jakarta.servlet.*;
import jakarta.servlet.http.*;

import java.io.BufferedReader;
import java.security.Principal;
import java.util.*;

/**
 * Lightweight mock HttpServletRequest for benchmark ABAC condition evaluation.
 * Provides clientIp and User-Agent from AbacContext so that ipRange and deviceType
 * conditions can be evaluated during benchmarks without a real HTTP request.
 */
public class BenchmarkMockRequest implements HttpServletRequest {

    private final String remoteAddr;
    private final String userAgent;

    public BenchmarkMockRequest(String remoteAddr, String userAgent) {
        this.remoteAddr = remoteAddr;
        this.userAgent = userAgent;
    }

    /**
     * Create a mock request from an AbacContext.
     * Returns null if abacCtx is null (caller should handle this gracefully).
     */
    public static HttpServletRequest fromAbacContext(NativeDataGenerator.AbacContext abacCtx) {
        if (abacCtx == null) {
            return null;
        }
        return new BenchmarkMockRequest(abacCtx.clientIp, "device_" + abacCtx.deviceId);
    }

    @Override
    public String getAuthType() { return null; }

    @Override
    public Cookie[] getCookies() { return new Cookie[0]; }

    @Override
    public long getDateHeader(String name) { return -1; }

    @Override
    public String getHeader(String name) {
        if ("User-Agent".equalsIgnoreCase(name)) {
            return userAgent;
        }
        return null;
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        String value = getHeader(name);
        return value != null ? Collections.enumeration(Collections.singletonList(value)) : Collections.emptyEnumeration();
    }

    @Override
    public Enumeration<String> getHeaderNames() {
        return Collections.enumeration(Arrays.asList("User-Agent"));
    }

    @Override
    public int getIntHeader(String name) { return -1; }

    @Override
    public String getMethod() { return "GET"; }

    @Override
    public String getPathInfo() { return null; }

    @Override
    public String getPathTranslated() { return null; }

    @Override
    public String getContextPath() { return ""; }

    @Override
    public String getQueryString() { return null; }

    @Override
    public String getRemoteUser() { return null; }

    @Override
    public boolean isUserInRole(String role) { return false; }

    @Override
    public Principal getUserPrincipal() { return null; }

    @Override
    public String getRequestedSessionId() { return null; }

    @Override
    public String getRequestURI() { return "/benchmark"; }

    @Override
    public StringBuffer getRequestURL() { return new StringBuffer("/benchmark"); }

    @Override
    public String getServletPath() { return ""; }

    @Override
    public HttpSession getSession(boolean create) { return null; }

    @Override
    public HttpSession getSession() { return null; }

    @Override
    public String changeSessionId() { return null; }

    @Override
    public boolean isRequestedSessionIdValid() { return false; }

    @Override
    public boolean isRequestedSessionIdFromCookie() { return false; }

    @Override
    public boolean isRequestedSessionIdFromURL() { return false; }

    @Override
    public boolean authenticate(HttpServletResponse response) { return false; }

    @Override
    public void login(String username, String password) {}

    @Override
    public void logout() {}

    @Override
    public Collection<Part> getParts() { return Collections.emptyList(); }

    @Override
    public Part getPart(String name) { return null; }

    @Override
    public <T extends HttpUpgradeHandler> T upgrade(Class<T> handlerClass) { return null; }

    @Override
    public Object getAttribute(String name) { return null; }

    @Override
    public Enumeration<String> getAttributeNames() { return Collections.emptyEnumeration(); }

    @Override
    public String getCharacterEncoding() { return "UTF-8"; }

    @Override
    public void setCharacterEncoding(String env) {}

    @Override
    public int getContentLength() { return -1; }

    @Override
    public long getContentLengthLong() { return -1; }

    @Override
    public String getContentType() { return null; }

    @Override
    public ServletInputStream getInputStream() { return null; }

    @Override
    public String getParameter(String name) { return null; }

    @Override
    public Enumeration<String> getParameterNames() { return Collections.emptyEnumeration(); }

    @Override
    public String[] getParameterValues(String name) { return new String[0]; }

    @Override
    public Map<String, String[]> getParameterMap() { return Collections.emptyMap(); }

    @Override
    public String getProtocol() { return "HTTP/1.1"; }

    @Override
    public String getScheme() { return "http"; }

    @Override
    public String getServerName() { return "benchmark"; }

    @Override
    public int getServerPort() { return 8080; }

    @Override
    public BufferedReader getReader() { return null; }

    @Override
    public String getRemoteAddr() { return remoteAddr; }

    @Override
    public String getRemoteHost() { return remoteAddr; }

    @Override
    public void setAttribute(String name, Object o) {}

    @Override
    public void removeAttribute(String name) {}

    @Override
    public Locale getLocale() { return Locale.getDefault(); }

    @Override
    public Enumeration<Locale> getLocales() { return Collections.enumeration(Collections.singletonList(Locale.getDefault())); }

    @Override
    public boolean isSecure() { return false; }

    @Override
    public RequestDispatcher getRequestDispatcher(String path) { return null; }

    @Override
    public int getRemotePort() { return 0; }

    @Override
    public String getLocalName() { return "benchmark"; }

    @Override
    public String getLocalAddr() { return "127.0.0.1"; }

    @Override
    public int getLocalPort() { return 8080; }

    @Override
    public ServletContext getServletContext() { return null; }

    @Override
    public AsyncContext startAsync() throws IllegalStateException { throw new IllegalStateException(); }

    @Override
    public AsyncContext startAsync(ServletRequest servletRequest, ServletResponse servletResponse) throws IllegalStateException { throw new IllegalStateException(); }

    @Override
    public boolean isAsyncStarted() { return false; }

    @Override
    public boolean isAsyncSupported() { return false; }

    @Override
    public AsyncContext getAsyncContext() { throw new IllegalStateException(); }

    @Override
    public DispatcherType getDispatcherType() { return DispatcherType.REQUEST; }

    @Override
    public String getRequestId() { return "benchmark"; }

    @Override
    public String getProtocolRequestId() { return "benchmark"; }

    @Override
    public ServletConnection getServletConnection() { return null; }
}
