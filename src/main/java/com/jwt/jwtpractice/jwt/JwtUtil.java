package com.jwt.jwtpractice.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.jwt.jwtpractice.user.Member;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Principal;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

@Component
@Slf4j
public class JwtUtil {

    public String createRefreshToken(MemberDetails memberDetails) {
        Member member = memberDetails.getMember();
        Map<String, Object> headerMap = Map.of("alg", "HMAC256");

        return JWT.create()
                .withHeader(headerMap)
                .withClaim("memberId", member.getMemberId())
                .withClaim("name", member.getName())
                .withExpiresAt(new Date(System.currentTimeMillis() + (1000 * 60 * 60 * 24 * 7)))
                .sign(Algorithm.HMAC256("aaa"));
    }

    public String createAccessToken(MemberDetails memberDetails) {
        Member member = memberDetails.getMember();
        Map<String, Object> headerMap = Map.of("alg", "HMAC256");
        log.info("now : {}, accessToken expire: {}", new Date(System.currentTimeMillis()),new Date(System.currentTimeMillis() + (1000 * 60 * 60 * 24 * 7)) );
        return JWT.create()
                .withHeader(headerMap)
                .withClaim("memberId", member.getMemberId())
                .withClaim("name", member.getName())
                .withClaim("roles", member.getRoleList())
                .withExpiresAt(new Date(System.currentTimeMillis() + (1000 * 60 * 60)))
                .sign(Algorithm.HMAC256("aaa"));
    }

    public boolean isExpired(String token){
        return JWT.decode(token).getExpiresAt().before(new Date());
    }



}
