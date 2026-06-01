package com.wowo.wowo.security.filter;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.wowo.wowo.service.JwtService;
import jakarta.servlet.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;

public class TokenFilter implements Filter {

    // TokenFilter.java
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws
                                                                                              ServletException,
                                                                                              IOException {
        final Cookie[] cookies = ((HttpServletRequest) request).getCookies();

        if (cookies == null) {
            chain.doFilter(request, response);
            return;
        }

        var cookie = Arrays.stream(cookies).filter(c -> c.getName().equals("Token")).findFirst()
                .orElse(null);

        if (cookie == null) {
            chain.doFilter(request, response);
            return;
        }

        final DecodedJWT decodedJWT = JwtService.verifyToken(cookie.getValue());
        if (decodedJWT == null) {
            chain.doFilter(request, response);
            return;
        }

        String role = null;
        var roleClaim = decodedJWT.getClaim("role");
        if (!roleClaim.isMissing() && !roleClaim.isNull()) {
            try {
                var roleMap = roleClaim.asMap();
                if (roleMap != null && roleMap.get("name") instanceof String rName) {
                    role = rName;
                }
            } catch (Exception e) {
                role = roleClaim.as(String.class);
            }
        }

        if (role == null) {
            chain.doFilter(request, response);
            return;
        }

        SecurityContextHolderStrategy contextHolder =
                SecurityContextHolder.getContextHolderStrategy();
        SecurityContext context = SecurityContextHolder.createEmptyContext();

        var authorities = Collections.singleton(
                new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()));

        String principalId = null;
        if (role.equalsIgnoreCase("user")) {
            var userIdClaim = decodedJWT.getClaim("userId");
            if (!userIdClaim.isMissing() && !userIdClaim.isNull()) {
                principalId = userIdClaim.asString();
            }
        } else {
            var partnerIdClaim = decodedJWT.getClaim("partnerId");
            if (!partnerIdClaim.isMissing() && !partnerIdClaim.isNull()) {
                principalId = partnerIdClaim.asString();
            }
        }

        if (principalId == null) {
            var idClaim = decodedJWT.getClaim("id");
            if (!idClaim.isMissing() && !idClaim.isNull()) {
                principalId = idClaim.asString();
            }
        }

        if (principalId == null) {
            principalId = decodedJWT.getSubject();
        }

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                principalId,
                cookie.getValue(),
                authorities);

        authenticationToken.setDetails(decodedJWT);

        context.setAuthentication(authenticationToken);
        contextHolder.setContext(context);

        chain.doFilter(request, response);
    }
}
