/*
 * Copyright (c) 2012 - 2015, Internet Corporation for Assigned Names and
 * Numbers (ICANN) and China Internet Network Information Center (CNNIC)
 * 
 * All rights reserved.
 *  
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *  
 * * Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice,
 *  this list of conditions and the following disclaimer in the documentation
 *  and/or other materials provided with the distribution.
 * * Neither the name of the ICANN, CNNIC nor the names of its contributors may
 *  be used to endorse or promote products derived from this software without
 *  specific prior written permission.
 *  
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL ICANN OR CNNIC BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */
package cn.cnnic.rdap.controller.support;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang.StringUtils;
import org.springframework.http.ResponseEntity;

import sun.misc.BASE64Decoder;
import cn.cnnic.rdap.bean.ErrorMessage;
import cn.cnnic.rdap.bean.Principal;
import cn.cnnic.rdap.bean.User;
import cn.cnnic.rdap.common.util.RestResponseUtil;
import cn.cnnic.rdap.common.util.ServiceBeanUtil;
import cn.cnnic.rdap.service.IdentityCheckService;

/**
 * authentication filter, set user id to session after logined.
 * 
 * @author
 * 
 */
public class AuthenticationFilter implements Filter {

    @Override
    public void destroy() {
    }

    @Override
    public void doFilter(ServletRequest arg0, ServletResponse arg1,
            FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) arg0;
        HttpServletResponse response = (HttpServletResponse) arg1;

        String tempPass = null;
        tempPass = request.getHeader("authorization");

        Principal principal = Principal.getAnonymousPrincipal();
        if (StringUtils.isNotBlank(tempPass)) {
            String AUTH_BASIC_PREFIX = "Basic ";
           // if(!StringUtils.startsWith(tempPass,AUTH_BASIC_PREFIX)){
            String tempPassStart = tempPass.substring(0,AUTH_BASIC_PREFIX.length()-1);
            if(!tempPassStart.equalsIgnoreCase(AUTH_BASIC_PREFIX)){
                writeError401Response(response);
                return;
            }
            tempPass = tempPass.substring(AUTH_BASIC_PREFIX.length(), tempPass.length());
            String tempPassdeCode = "";
            BASE64Decoder decoder = new BASE64Decoder();

            try {
                byte[] b = decoder.decodeBuffer(tempPass);
                tempPassdeCode = new String(b);
            } catch (Exception e) {
                writeError401Response(response);
                return;
            }

            String userReqId = "";
            String userReqPwd = "";
            int indexOfSeparator = tempPassdeCode.indexOf(":");
            if (-1 == indexOfSeparator) {
                writeError401Response(response);
                return;
            }
            userReqId = tempPassdeCode.substring(0, indexOfSeparator);
            userReqPwd = tempPassdeCode.substring(indexOfSeparator + 1);
            User user = null;
            IdentityCheckService idcService =
                    ServiceBeanUtil.getIdentityCheckService();
            user = idcService.IdentityCheckService(userReqId, userReqPwd);
            if (null == user) {
                request.getSession().removeAttribute("SESSION_ATTR_USER_ID");
                writeError401Response(response);
                // chain.doFilter(request, response);
                return;
            } else {
                principal = new Principal(user.getUserId());
            }
        }
        PrincipalHolder.setPrincipal(principal);
        chain.doFilter(request, response);
        PrincipalHolder.remove();
    }

    @Override
    public void init(FilterConfig arg0) throws ServletException {
    }

    private void writeError401Response(HttpServletResponse response)
            throws IOException {
        ResponseEntity<ErrorMessage> responseEntity =
                RestResponseUtil.createResponse401();
        FilterHelper.writeResponse(responseEntity, response);
    }
}
