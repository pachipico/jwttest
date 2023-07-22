package com.jwt.jwtpractice.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.jwt.jwtpractice.user.Member;
import com.jwt.jwtpractice.user.MemberRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private MemberRepository memberRepository;
    private AuthenticationManager authenticationManager;
    private JwtUtil jwtUtil;


    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, MemberRepository memberRepository, JwtUtil jwtUtil) {

        super(authenticationManager);
        this.memberRepository = memberRepository;
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        log.info("인증로직 시작");
        String accessToken = request.getHeader("accessToken");

        // 토큰이 없으면 넘어가기(403)
        if (accessToken == null ) super.doFilterInternal(request, response, chain);
        else {
            // todo access 검증 시 유효하지 않으면 -> refresh 토큰 검증하는 로직 구현해야함

            MemberDetails memberDetails = jwtUtil.checkAccessToken(accessToken);
            SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(memberDetails, null, memberDetails.getAuthorities()));
        }

        super.doFilterInternal(request, response, chain);
    }


}
