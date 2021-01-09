/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.web.filter;

import org.apache.shiro.util.AntPathMatcher;
import org.apache.shiro.util.PatternMatcher;
import org.apache.shiro.util.StringUtils;
import org.apache.shiro.web.servlet.AdviceFilter;
import org.apache.shiro.web.util.WebUtils;
import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Filter;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.apache.shiro.util.StringUtils.split;

/**
 * <p>Base class for Filters that will process only specified paths and allow all others to pass through.</p>
 *
 * @since 0.9
 * 这个过滤器会处理指定的请求路径，和对其他路径的请求放行。
 * 打个比方：如果配置如：/hello=authc,意味着，用户请求/hello时，这时的authc过滤就会对这个请求拦截并进行过滤逻辑处理，如果一个用户请求是/word，则不会对此请求过滤
 * PathMatchingFilter对配置了URL请求拦截的地址进行过滤器过滤，对没有匹配拦截的URL请求直接放行，不进行拦截。如果请求需要过滤，则处理过滤的逻辑由子类实现onPreHandle完成
 */
public abstract class PathMatchingFilter extends AdviceFilter implements PathConfigProcessor {

    /**
     * Log available to this class only
     */
    private static final Logger log = LoggerFactory.getLogger(PathMatchingFilter.class);

    private static final String DEFAULT_PATH_SEPARATOR = "/";

    /**
     * PatternMatcher used in determining which paths to react to for a given request.
     * 路径匹配器
     */
    protected PatternMatcher pathMatcher = new AntPathMatcher();

    /**
     * A collection of path-to-config entries where the key is a path which this filter should process and
     * the value is the (possibly null) configuration element specific to this Filter for that specific path.
     * <p/>
     * <p>To put it another way, the keys are the paths (urls) that this Filter will process.
     * <p>The values are filter-specific data that this Filter should use when processing the corresponding
     * key (path).  The values can be null if no Filter-specific config was specified for that url.
     * 这里存的内容是 例如:
     *  /login.jsp [anon]
     *  /index.jsp [bar, baz]
     *  这里的appliedPaths是一个地址过滤器的映射map
     *  key存放的是请求的URL，value是对应该URL处理的Filter过滤器，这个value也可以是空值
     */
    protected Map<String, Object> appliedPaths = new LinkedHashMap<String, Object>();

    /**
     * Splits any comma-delmited values that might be found in the <code>config</code> argument and sets the resulting
     * <code>String[]</code> array on the <code>appliedPaths</code> internal Map.
     * <p/>
     * That is:
     * <pre><code>
     * String[] values = null;
     * if (config != null) {
     *     values = split(config);
     * }
     * <p/>
     * this.{@link #appliedPaths appliedPaths}.put(path, values);
     * </code></pre>
     *
     * @param path   the application context path to match for executing this filter.
     * @param config the specified for <em>this particular filter only</em> for the given <code>path</code>
     * @return this configured filter.
     * 假设你的配置是 /user/** = user, roles[admin, foo]
     * 如果这个类是roles path为/user/**   config为admin, foo
     * 如果这个类是user path为/user/**  config为null
     */
    public Filter processPathConfig(String path, String config) {
        String[] values = null;
        if (config != null) {
            values = split(config);
        }

        this.appliedPaths.put(path, values);
        return this;
    }

    /**
     * Returns the context path within the application based on the specified <code>request</code>.
     * <p/>
     * This implementation merely delegates to
     * {@link WebUtils#getPathWithinApplication(javax.servlet.http.HttpServletRequest) WebUtils.getPathWithinApplication(request)},
     * but can be overridden by subclasses for custom logic.
     *
     * @param request the incoming <code>ServletRequest</code>
     * @return the context path within the application.
     * 获得请求路径
     * 假设请求http://localhost/index.jsp?id=18
     * 则返回值为/index.jsp
     */
    protected String getPathWithinApplication(ServletRequest request) {
        return WebUtils.getPathWithinApplication(WebUtils.toHttp(request));
    }

    /**
     * Returns <code>true</code> if the incoming <code>request</code> matches the specified <code>path</code> pattern,
     * <code>false</code> otherwise.
     * <p/>
     * The default implementation acquires the <code>request</code>'s path within the application and determines
     * if that matches:
     * <p/>
     * <code>String requestURI = {@link #getPathWithinApplication(javax.servlet.ServletRequest) getPathWithinApplication(request)};<br/>
     * return {@link #pathsMatch(String, String) pathsMatch(path,requestURI)}</code>
     *
     * @param path    the configured url pattern to check the incoming request against.
     * @param request the incoming ServletRequest
     * @return <code>true</code> if the incoming <code>request</code> matches the specified <code>path</code> pattern,
     *         <code>false</code> otherwise.
     * 请求路径与path匹配
     */
    protected boolean pathsMatch(String path, ServletRequest request) {
        String requestURI = getPathWithinApplication(request);
        if (requestURI != null && !DEFAULT_PATH_SEPARATOR.equals(requestURI)
                && requestURI.endsWith(DEFAULT_PATH_SEPARATOR)) {
            requestURI = requestURI.substring(0, requestURI.length() - 1);
        }
        if (path != null && !DEFAULT_PATH_SEPARATOR.equals(path)
                && path.endsWith(DEFAULT_PATH_SEPARATOR)) {
            path = path.substring(0, path.length() - 1);
        }
        log.trace("Attempting to match pattern '{}' with current requestURI '{}'...", path, Encode.forHtml(requestURI));
        return pathsMatch(path, requestURI);
    }

    /**
     * Returns <code>true</code> if the <code>path</code> matches the specified <code>pattern</code> string,
     * <code>false</code> otherwise.
     * <p/>
     * Simply delegates to
     * <b><code>this.pathMatcher.{@link PatternMatcher#matches(String, String) matches(pattern,path)}</code></b>,
     * but can be overridden by subclasses for custom matching behavior.
     *
     * @param pattern the pattern to match against
     * @param path    the value to match with the specified <code>pattern</code>
     * @return <code>true</code> if the <code>path</code> matches the specified <code>pattern</code> string,
     *         <code>false</code> otherwise.
     */
    protected boolean pathsMatch(String pattern, String path) {
        return pathMatcher.matches(pattern, path);
    }

    /**
     * Implementation that handles path-matching behavior before a request is evaluated.  If the path matches and
     * the filter
     * {@link #isEnabled(javax.servlet.ServletRequest, javax.servlet.ServletResponse, String, Object) isEnabled} for
     * that path/config, the request will be allowed through via the result from
     * {@link #onPreHandle(javax.servlet.ServletRequest, javax.servlet.ServletResponse, Object) onPreHandle}.  If the
     * path does not match or the filter is not enabled for that path, this filter will allow passthrough immediately
     * to allow the {@code FilterChain} to continue executing.
     * <p/>
     * In order to retain path-matching functionality, subclasses should not override this method if at all
     * possible, and instead override
     * {@link #onPreHandle(javax.servlet.ServletRequest, javax.servlet.ServletResponse, Object) onPreHandle} instead.
     *
     * @param request  the incoming ServletRequest
     * @param response the outgoing ServletResponse
     * @return {@code true} if the filter chain is allowed to continue to execute, {@code false} if a subclass has
     *         handled the request explicitly.
     * @throws Exception if an error occurs
     * 这个方法返回false则请求会被中断
     */
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        // 判断appliedPaths为空，则放行，不作拦截请求的处理（这里的appliedPaths是一个地址过滤器的映射map）
        // key存放的是请求的URL，value是对应该URL处理的Filter过滤器，这个value也可以是空值
        if (this.appliedPaths == null || this.appliedPaths.isEmpty()) {
            if (log.isTraceEnabled()) {
                log.trace("appliedPaths property is null or empty.  This Filter will passthrough immediately.");
            }
            return true;
        }
        // 首先进行路径匹配
        for (String path : this.appliedPaths.keySet()) {
            // If the path does match, then pass on to the subclass implementation for specific checks
            //(first match 'wins'):
            if (pathsMatch(path, request)) {
                log.trace("Current requestURI matches pattern '{}'.  Determining filter chain execution...", path);
                Object config = this.appliedPaths.get(path);
                // 如果用户的请求与配置中拦截的请求匹配，则会调用isFilterChainContinued方法进行下一步处理
                return isFilterChainContinued(request, response, path, config);
            }
        }

        //no path matched, allow the request to go through:
        // 如果没有匹配允许执行
        return true;
    }

    /**
     * Simple method to abstract out logic from the preHandle implementation - it was getting a bit unruly.
     *
     * @since 1.2
     */
    @SuppressWarnings({"JavaDoc"})
    private boolean isFilterChainContinued(ServletRequest request, ServletResponse response,
                                           String path, Object pathConfig) throws Exception {
        // 如果拦截器是开启的，则调用方法onPreHandle进行拦截处理，默认允许
        if (isEnabled(request, response, path, pathConfig)) { //isEnabled check added in 1.2
            if (log.isTraceEnabled()) {
                log.trace("Filter '{}' is enabled for the current request under path '{}' with config [{}].  " +
                        "Delegating to subclass implementation for 'onPreHandle' check.",
                        new Object[]{getName(), path, pathConfig});
            }
            //The filter is enabled for this specific request, so delegate to subclass implementations
            //so they can decide if the request should continue through the chain or not:
            // 则执行onPreHandle,根据返回值来决定是否继续允许执行后续的filter
            // 所有shiro-fiter都会重写此方法，如果返回false 则请求会被中断
            return onPreHandle(request, response, pathConfig);
        }

        if (log.isTraceEnabled()) {
            log.trace("Filter '{}' is disabled for the current request under path '{}' with config [{}].  " +
                    "The next element in the FilterChain will be called immediately.",
                    new Object[]{getName(), path, pathConfig});
        }
        //This filter is disabled for this specific request,
        //return 'true' immediately to indicate that the filter will not process the request
        //and let the request/response to continue through the filter chain:
        return true;
    }

    /**
     * This default implementation always returns {@code true} and should be overridden by subclasses for custom
     * logic if necessary.
     *
     * @param request     the incoming ServletRequest
     * @param response    the outgoing ServletResponse
     * @param mappedValue the filter-specific config value mapped to this filter in the URL rules mappings.
     * @return {@code true} if the request should be able to continue, {@code false} if the filter will
     *         handle the response directly.
     * @throws Exception if an error occurs
     * @see #isEnabled(javax.servlet.ServletRequest, javax.servlet.ServletResponse, String, Object)
     */
    protected boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        return true;
    }

    /**
     * Path-matching version of the parent class's
     * {@link #isEnabled(javax.servlet.ServletRequest, javax.servlet.ServletResponse)} method, but additionally allows
     * for inspection of any path-specific configuration values corresponding to the specified request.  Subclasses
     * may wish to inspect this additional mapped configuration to determine if the filter is enabled or not.
     * <p/>
     * This method's default implementation ignores the {@code path} and {@code mappedValue} arguments and merely
     * returns the value from a call to {@link #isEnabled(javax.servlet.ServletRequest, javax.servlet.ServletResponse)}.
     * It is expected that subclasses override this method if they need to perform enable/disable logic for a specific
     * request based on any path-specific config for the filter instance.
     *
     * @param request     the incoming servlet request
     * @param response    the outbound servlet response
     * @param path        the path matched for the incoming servlet request that has been configured with the given {@code mappedValue}.
     * @param mappedValue the filter-specific config value mapped to this filter in the URL rules mappings for the given {@code path}.
     * @return {@code true} if this filter should filter the specified request, {@code false} if it should let the
     *         request/response pass through immediately to the next element in the {@code FilterChain}.
     * @throws Exception in the case of any error
     * @since 1.2
     */
    @SuppressWarnings({"UnusedParameters"})
    protected boolean isEnabled(ServletRequest request, ServletResponse response, String path, Object mappedValue)
            throws Exception {
        return isEnabled(request, response);
    }
}
