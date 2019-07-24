package com.app.petmate.security.filters;

import com.app.petmate.security.util.TokenUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class AuthenticationTokenFilter extends UsernamePasswordAuthenticationFilter {

    @Value("${jwt.header}")
    private String tokenHeader;

    private TokenUtils tokenUtils;

    private UserDetailsService userDetailsService;

//    public AuthenticationTokenFilter(
//            TokenUtils tokenUtils,
//            @Qualifier("securityUserService") UserDetailsService userDetailsService) {
//        this.tokenUtils = tokenUtils;
//        this.userDetailsService = userDetailsService;
//    }



    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpServletRequest
                = (HttpServletRequest) request;

        String authToken
                = httpServletRequest.getHeader(tokenHeader);

        String username;
        Authentication auth
                = SecurityContextHolder.getContext().getAuthentication();



        if (authToken != null && auth == null) {
            username = tokenUtils.getUsernameFromToken(authToken);

            UserDetails userDetails
                    = userDetailsService.loadUserByUsername(username);

            if (tokenUtils.validateToken(authToken, userDetails)) {
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities());

                authentication
                        .setDetails(
                                new WebAuthenticationDetailsSource()
                                        .buildDetails(httpServletRequest));

                SecurityContextHolder.getContext().setAuthentication(authentication);


            }
        }
        chain.doFilter(request, response);

    }

    @Autowired
    public void setTokenUtils(TokenUtils tokenUtils) {
        this.tokenUtils = tokenUtils;
    }

    @Autowired
    public void setUserDetailsService(@Qualifier("securityUserService") UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }
}
