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

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, MemberRepository memberRepository, JwtUtil jwtUtil, MemberRepository repository) {

        super(authenticationManager);
        this.memberRepository = memberRepository;
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        log.info("인증로직 시작");
        String accessToken = request.getHeader("accessToken");
        String refreshToken = request.getHeader("refreshToken");
        // 토큰이 없으면 넘어가기(403)
        if (accessToken == null || refreshToken == null) super.doFilterInternal(request, response, chain);
        else {
            // todo access 검증 시 유효하지 않으면 -> refresh 토큰 검증하는 로직 구현해야함
            // access 토큰, refresh 토큰 검증로직이 달라야함.(access 토큰은 파싱한 id 값으로 db에서 가져와 검증, refresh 토큰은 db에 있는 refresh 토큰과 직접 비교)
            // access 토큰이 유효한지 먼저 확인
            isTokenValid(accessToken);

            // access 토큰이 유효하지 않다면 refresh 토큰 확인
            isTokenValid(refreshToken);

            // refresh 토큰이 유효하다면 access 토큰 재발급


            // refresh 토큰이 유효하지 않다면 넘어가기(403), 유효하면

        }

        super.doFilterInternal(request, response, chain);
    }

    private void isTokenValid(String token) {
        if (!jwtUtil.isExpired(token)) {

            String memberId = JWT.require(Algorithm.HMAC256("aaa")).build().verify(token).getClaim("memberId").toString().replaceAll("\"", "");
            MemberDetails memberDetails = null;

            if (memberId != null) {

                Member byMemberId = memberRepository.findByMemberId(memberId);
                memberDetails = new MemberDetails(byMemberId);
                Authentication authentication = new UsernamePasswordAuthenticationToken(memberDetails, null, memberDetails.getAuthorities());
                log.info("\n접속유저: {}\n권한 {}", memberDetails, authentication.isAuthenticated() ? "있음" : "없음");
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        ;
    }
}
