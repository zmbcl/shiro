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
package org.apache.shiro.web.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

/**
 * A Servlet Filter that enables AOP-style &quot;around&quot; advice for a ServletRequest via
 * {@link #preHandle(javax.servlet.ServletRequest, javax.servlet.ServletResponse) preHandle},
 * {@link #postHandle(javax.servlet.ServletRequest, javax.servlet.ServletResponse) postHandle},
 * and {@link #afterCompletion(javax.servlet.ServletRequest, javax.servlet.ServletResponse, Exception) afterCompletion}
 * hooks.
 *
 * @since 0.9
 * 一个AOP的类，在执行chain.doFilter(request, response); 添加了前置 后置 最终三个环绕方法.
 * 这个过滤器，类似于开启了AOP环绕通知，提供了preHandle,postHandle和afterCompletion三个方法
 * AdviceFilter提供了类似于AOP环绕通知式的编程方式，其处理拦截的逻辑是在preHandle方法中完成的。
 * preHandle方法返回true和false代表了通过过滤，请求可以到达用户的请求地址和过滤器拦截掉了用户的请求
 */
public abstract class AdviceFilter extends OncePerRequestFilter {

    /**
     * The static logger available to this class only
     */
    private static final Logger log = LoggerFactory.getLogger(AdviceFilter.class);

    /**
     * Returns {@code true} if the filter chain should be allowed to continue, {@code false} otherwise.
     * It is called before the chain is actually consulted/executed.
     * <p/>
     * The default implementation returns {@code true} always and exists as a template method for subclasses.
     *
     * @param request  the incoming ServletRequest
     * @param response the outgoing ServletResponse
     * @return {@code true} if the filter chain should be allowed to continue, {@code false} otherwise.
     * @throws Exception if there is any error.
     * handle [ˈhændl] v. （用手）触摸；以手（或前臂）触球；操纵（车辆）；（车辆）按特定方式作出反应；处理；对付（某人或某事）；有办法应付；n. （门的）把手；柄；（织物等的）手感；
     * AOP方法
     */
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        return true;
    }

    /**
     * Allows 'post' advice logic to be called, but only if no exception occurs during filter chain execution.  That
     * is, if {@link #executeChain executeChain} throws an exception, this method will never be called.  Be aware of
     * this when implementing logic.  Most resource 'cleanup' behavior is often done in the
     * {@link #afterCompletion(javax.servlet.ServletRequest, javax.servlet.ServletResponse, Exception) afterCompletion(request,response,exception)}
     * implementation, which is guaranteed to be called for every request, even when the chain processing throws
     * an Exception.
     * <p/>
     * The default implementation does nothing (no-op) and exists as a template method for subclasses.
     *
     * @param request  the incoming ServletRequest
     * @param response the outgoing ServletResponse
     * @throws Exception if an error occurs.
     * handle [ˈhændl] v. （用手）触摸；以手（或前臂）触球；操纵（车辆）；（车辆）按特定方式作出反应；处理；对付（某人或某事）；有办法应付；n. （门的）把手；柄；（织物等的）手感；
     * AOP方法
     */
    @SuppressWarnings({"UnusedDeclaration"})
    protected void postHandle(ServletRequest request, ServletResponse response) throws Exception {
    }

    /**
     * Called in all cases in a {@code finally} block even if {@link #preHandle preHandle} returns
     * {@code false} or if an exception is thrown during filter chain processing.  Can be used for resource
     * cleanup if so desired.
     * <p/>
     * The default implementation does nothing (no-op) and exists as a template method for subclasses.
     *
     * @param request   the incoming ServletRequest
     * @param response  the outgoing ServletResponse
     * @param exception any exception thrown during {@link #preHandle preHandle}, {@link #executeChain executeChain},
     *                  or {@link #postHandle postHandle} execution, or {@code null} if no exception was thrown
     *                  (i.e. the chain processed successfully).
     * @throws Exception if an error occurs.
     * AOP方法
     */
    @SuppressWarnings({"UnusedDeclaration"})
    public void afterCompletion(ServletRequest request, ServletResponse response, Exception exception) throws Exception {
    }

    /**
     * Actually executes the specified filter chain by calling <code>chain.doFilter(request,response);</code>.
     * <p/>
     * Can be overridden by subclasses for custom logic.
     *
     * @param request  the incoming ServletRequest
     * @param response the outgoing ServletResponse
     * @param chain    the filter chain to execute
     * @throws Exception if there is any error executing the chain.
     */
    protected void executeChain(ServletRequest request, ServletResponse response, FilterChain chain) throws Exception {
        chain.doFilter(request, response);
    }

    /**
     * Actually implements the chain execution logic, utilizing
     * {@link #preHandle(javax.servlet.ServletRequest, javax.servlet.ServletResponse) pre},
     * {@link #postHandle(javax.servlet.ServletRequest, javax.servlet.ServletResponse) post}, and
     * {@link #afterCompletion(javax.servlet.ServletRequest, javax.servlet.ServletResponse, Exception) after}
     * advice hooks.
     *
     * @param request  the incoming ServletRequest
     * @param response the outgoing ServletResponse
     * @param chain    the filter chain to execute
     * @throws ServletException if a servlet-related error occurs
     * @throws IOException      if an IO error occurs
     * internal [ɪnˈtɜːnl] adj. 内部的；体内的；（机构）内部的；国内的；本身的；内心的；（大学生）本校生的 n. 内脏；内部特征
     */
    public void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        Exception exception = null;

        try {
            // handle [ˈhændl] v. （用手）触摸；以手（或前臂）触球；操纵（车辆）；（车辆）按特定方式作出反应；处理；对付（某人或某事）；有办法应付；n. （门的）把手；柄；（织物等的）手感；
            // 执行前置AOP方法 根据返回值continueChain觉得是否继续执行chain.doFilter(request, response);
            boolean continueChain = preHandle(request, response);
            if (log.isTraceEnabled()) {
                log.trace("Invoked preHandle method.  Continuing chain?: [" + continueChain + "]");
            }
            // 如果preHandle返回true则执行
            // executeChain方法中的实现为：chain.doFilter(request, response);
            // 所以如果preHandle方法返回false，则说明过滤器不会执行chain.doFilter，意味着请求被拦截掉了，不会进入到用户请求的地址上去。
            // 如果为true，表示过滤器放行了过滤的逻辑通过
            if (continueChain) {
                executeChain(request, response, chain);
            }
            // 如果不出异常则执行postHandle
            postHandle(request, response);
            if (log.isTraceEnabled()) {
                log.trace("Successfully invoked postHandle method");
            }

        } catch (Exception e) {
            exception = e;
        } finally {
            // 异常与否都在最后执行
            cleanup(request, response, exception);
        }
    }

    /**
     * Executes cleanup logic in the {@code finally} code block in the
     * {@link #doFilterInternal(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain) doFilterInternal}
     * implementation.
     * <p/>
     * This implementation specifically calls
     * {@link #afterCompletion(javax.servlet.ServletRequest, javax.servlet.ServletResponse, Exception) afterCompletion}
     * as well as handles any exceptions properly.
     *
     * @param request  the incoming {@code ServletRequest}
     * @param response the outgoing {@code ServletResponse}
     * @param existing any exception that might have occurred while executing the {@code FilterChain} or
     *                 pre or post advice, or {@code null} if the pre/chain/post execution did not throw an {@code Exception}.
     * @throws ServletException if any exception other than an {@code IOException} is thrown.
     * @throws IOException      if the pre/chain/post execution throw an {@code IOException}
     */
    protected void cleanup(ServletRequest request, ServletResponse response, Exception existing)
            throws ServletException, IOException {
        Exception exception = existing;
        try {
            // AOP方法
            afterCompletion(request, response, exception);
            if (log.isTraceEnabled()) {
                log.trace("Successfully invoked afterCompletion method.");
            }
        } catch (Exception e) {
            if (exception == null) {
                exception = e;
            } else {
                log.debug("afterCompletion implementation threw an exception.  This will be ignored to " +
                        "allow the original source exception to be propagated.", e);
            }
        }
        // 如果executeChain方法出现异常则在这里抛出
        if (exception != null) {
            if (exception instanceof ServletException) {
                throw (ServletException) exception;
            } else if (exception instanceof IOException) {
                throw (IOException) exception;
            } else {
                if (log.isDebugEnabled()) {
                    String msg = "Filter execution resulted in an unexpected Exception " +
                            "(not IOException or ServletException as the Filter API recommends).  " +
                            "Wrapping in ServletException and propagating.";
                    log.debug(msg);
                }
                throw new ServletException(exception);
            }
        }
    }
}
