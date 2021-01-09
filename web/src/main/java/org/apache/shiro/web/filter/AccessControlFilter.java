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

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

/**
 * Superclass for any filter that controls access to a resource and may redirect the user to the login page
 * if they are not authenticated.  This superclass provides the method
 * {@link #saveRequestAndRedirectToLogin(javax.servlet.ServletRequest, javax.servlet.ServletResponse)}
 * which is used by many subclasses as the behavior when a user is unauthenticated.
 *
 * @since 0.9
 * 如果用户没有认证（即登录）那么这个过滤器就是控制访问资源和用户重定向到登录页面的过滤器父类。
 * 当一个用户没有认证（即登录）时，可以通过saveRequestAndRedirectToLogin这个方法，重定向到登录页。
 *
 * 总结：AccessControlfilter中的onPreHandle处理真正的拦截逻辑，isAccessAllowed方法验证用户是否登录，onAccessDenied处理用户没登录后的逻辑，
 * 在这个过滤器中并没有给出isAccessAllowed和onAccessDenied方法的实现，下一步得去子类中看，目前只能通过文档的注释去了解这些方法大概会执行什么样的操作。
 */
public abstract class AccessControlFilter extends PathMatchingFilter {

    /**
     * Simple default login URL equal to <code>/login.jsp</code>, which can be overridden by calling the
     * {@link #setLoginUrl(String) setLoginUrl} method.
     * 默认登录页
     */
    public static final String DEFAULT_LOGIN_URL = "/login.jsp";

    /**
     * Constant representing the HTTP 'GET' request method, equal to <code>GET</code>.
     */
    public static final String GET_METHOD = "GET";

    /**
     * Constant representing the HTTP 'POST' request method, equal to <code>POST</code>.
     */
    public static final String POST_METHOD = "POST";

    /**
     * The login url to used to authenticate a user, used when redirecting users if authentication is required.
     */
    private String loginUrl = DEFAULT_LOGIN_URL;

    /**
     * Returns the login URL used to authenticate a user.
     * <p/>
     * Most Shiro filters use this url
     * as the location to redirect a user when the filter requires authentication.  Unless overridden, the
     * {@link #DEFAULT_LOGIN_URL DEFAULT_LOGIN_URL} is assumed, which can be overridden via
     * {@link #setLoginUrl(String) setLoginUrl}.
     *
     * @return the login URL used to authenticate a user, used when redirecting users if authentication is required.
     */
    public String getLoginUrl() {
        return loginUrl;
    }

    /**
     * Sets the login URL used to authenticate a user.
     * <p/>
     * Most Shiro filters use this url as the location to redirect a user when the filter requires
     * authentication.  Unless overridden, the {@link #DEFAULT_LOGIN_URL DEFAULT_LOGIN_URL} is assumed.
     *
     * @param loginUrl the login URL used to authenticate a user, used when redirecting users if authentication is required.
     */
    public void setLoginUrl(String loginUrl) {
        this.loginUrl = loginUrl;
    }

    /**
     * Convenience method that acquires the Subject associated with the request.
     * <p/>
     * The default implementation simply returns
     * {@link org.apache.shiro.SecurityUtils#getSubject() SecurityUtils.getSubject()}.
     *
     * @param request  the incoming <code>ServletRequest</code>
     * @param response the outgoing <code>ServletResponse</code>
     * @return the Subject associated with the request.
     */
    protected Subject getSubject(ServletRequest request, ServletResponse response) {
        return SecurityUtils.getSubject();
    }

    /**
     * Returns <code>true</code> if the request is allowed to proceed through the filter normally, or <code>false</code>
     * if the request should be handled by the
     * {@link #onAccessDenied(ServletRequest,ServletResponse,Object) onAccessDenied(request,response,mappedValue)}
     * method instead.
     *
     * @param request     the incoming <code>ServletRequest</code>
     * @param response    the outgoing <code>ServletResponse</code>
     * @param mappedValue the filter-specific config value mapped to this filter in the URL rules mappings.
     * @return <code>true</code> if the request should proceed through the filter normally, <code>false</code> if the
     *         request should be processed by this filter's
     *         {@link #onAccessDenied(ServletRequest,ServletResponse,Object)} method instead.
     * @throws Exception if an error occurs during processing.
     * access [ˈækses] n. 通道；进入；机会；使用权；探望权；（对计算机存储器的）访问；（情感）爆发；入口 v. 接近，使用；访问，存取（电脑文档）
     * 即isAccessAllowed返回true表示用户已经登录过，false表示用户还未登录
     * 子类根据业务规则觉得是否中断请求
     */
    protected abstract boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception;

    /**
     * Processes requests where the subject was denied access as determined by the
     * {@link #isAccessAllowed(javax.servlet.ServletRequest, javax.servlet.ServletResponse, Object) isAccessAllowed}
     * method, retaining the {@code mappedValue} that was used during configuration.
     * <p/>
     * This method immediately delegates to {@link #onAccessDenied(ServletRequest,ServletResponse)} as a
     * convenience in that most post-denial behavior does not need the mapped config again.
     *
     * @param request     the incoming <code>ServletRequest</code>
     * @param response    the outgoing <code>ServletResponse</code>
     * @param mappedValue the config specified for the filter in the matching request's filter chain.
     * @return <code>true</code> if the request should continue to be processed; false if the subclass will
     *         handle/render the response directly.
     * @throws Exception if there is an error processing the request.
     * @since 1.0
     * access [ˈækses] n. 通道；进入；机会；使用权；探望权；（对计算机存储器的）访问；（情感）爆发；入口 v. 接近，使用；访问，存取（电脑文档）
     * denied [dɪ'naɪd] v. 拒绝；拒签（deny的过去式）
     * onAccessDenied即登录验证在isAccessAllowed方法中被拒绝以后调用，其中参数mappedValue可以通过配置获取到，也可以是null。
     * 这个方法的委托方法
     */
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        return onAccessDenied(request, response);
    }

    /**
     * Processes requests where the subject was denied access as determined by the
     * {@link #isAccessAllowed(javax.servlet.ServletRequest, javax.servlet.ServletResponse, Object) isAccessAllowed}
     * method.
     *
     * @param request  the incoming <code>ServletRequest</code>
     * @param response the outgoing <code>ServletResponse</code>
     * @return <code>true</code> if the request should continue to be processed; false if the subclass will
     *         handle/render the response directly.
     * @throws Exception if there is an error processing the request.
     */
    protected abstract boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception;

    /**
     * Returns <code>true</code> if
     * {@link #isAccessAllowed(ServletRequest,ServletResponse,Object) isAccessAllowed(Request,Response,Object)},
     * otherwise returns the result of
     * {@link #onAccessDenied(ServletRequest,ServletResponse,Object) onAccessDenied(Request,Response,Object)}.
     *
     * @return <code>true</code> if
     *         {@link #isAccessAllowed(javax.servlet.ServletRequest, javax.servlet.ServletResponse, Object) isAccessAllowed},
     *         otherwise returns the result of
     *         {@link #onAccessDenied(javax.servlet.ServletRequest, javax.servlet.ServletResponse) onAccessDenied}.
     * @throws Exception if an error occurs.
     * 这里调用的isAccessAllowed
     */
    public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        // isAccessAllowed如果请求允许正常处理，则返回true。否则返回false由方法onAccessDenied进行处理请求。
        // 即isAccessAllowed返回true表示用户已经登录过，false表示用户还未登录
        // access [ˈækses] n. 通道；进入；机会；使用权；探望权；（对计算机存储器的）访问；（情感）爆发；入口 v. 接近，使用；访问，存取（电脑文档）
        // denied [dɪ'naɪd] v. 拒绝；拒签（deny的过去式）
        return isAccessAllowed(request, response, mappedValue) || onAccessDenied(request, response, mappedValue);
    }

    /**
     * Returns <code>true</code> if the incoming request is a login request, <code>false</code> otherwise.
     * <p/>
     * The default implementation merely returns <code>true</code> if the incoming request matches the configured
     * {@link #getLoginUrl() loginUrl} by calling
     * <code>{@link #pathsMatch(String, String) pathsMatch(loginUrl, request)}</code>.
     *
     * @param request  the incoming <code>ServletRequest</code>
     * @param response the outgoing <code>ServletResponse</code>
     * @return <code>true</code> if the incoming request is a login request, <code>false</code> otherwise.
     */
    protected boolean isLoginRequest(ServletRequest request, ServletResponse response) {
        return pathsMatch(getLoginUrl(), request);
    }

    /**
     * Convenience method for subclasses to use when a login redirect is required.
     * <p/>
     * This implementation simply calls {@link #saveRequest(javax.servlet.ServletRequest) saveRequest(request)}
     * and then {@link #redirectToLogin(javax.servlet.ServletRequest, javax.servlet.ServletResponse) redirectToLogin(request,response)}.
     *
     * @param request  the incoming <code>ServletRequest</code>
     * @param response the outgoing <code>ServletResponse</code>
     * @throws IOException if an error occurs.
     * 保存请求路径调转到登录页面
     */
    protected void saveRequestAndRedirectToLogin(ServletRequest request, ServletResponse response) throws IOException {
        saveRequest(request);
        redirectToLogin(request, response);
    }

    /**
     * Convenience method merely delegates to
     * {@link WebUtils#saveRequest(javax.servlet.ServletRequest) WebUtils.saveRequest(request)} to save the request
     * state for reuse later.  This is mostly used to retain user request state when a redirect is issued to
     * return the user to their originally requested url/resource.
     * <p/>
     * If you need to save and then immediately redirect the user to login, consider using
     * {@link #saveRequestAndRedirectToLogin(javax.servlet.ServletRequest, javax.servlet.ServletResponse)
     * saveRequestAndRedirectToLogin(request,response)} directly.
     *
     * @param request the incoming ServletRequest to save for re-use later (for example, after a redirect).
     * 保存请求路径
     */
    protected void saveRequest(ServletRequest request) {
        WebUtils.saveRequest(request);
    }

    /**
     * Convenience method for subclasses that merely acquires the {@link #getLoginUrl() getLoginUrl} and redirects
     * the request to that url.
     * <p/>
     * <b>N.B.</b>  If you want to issue a redirect with the intention of allowing the user to then return to their
     * originally requested URL, don't use this method directly.  Instead you should call
     * {@link #saveRequestAndRedirectToLogin(javax.servlet.ServletRequest, javax.servlet.ServletResponse)
     * saveRequestAndRedirectToLogin(request,response)}, which will save the current request state so that it can
     * be reconstructed and re-used after a successful login.
     *
     * @param request  the incoming <code>ServletRequest</code>
     * @param response the outgoing <code>ServletResponse</code>
     * @throws IOException if an error occurs.
     * 跳转到登录页
     */
    protected void redirectToLogin(ServletRequest request, ServletResponse response) throws IOException {
        String loginUrl = getLoginUrl();
        WebUtils.issueRedirect(request, response, loginUrl);
    }

}
