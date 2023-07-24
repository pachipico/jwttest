package com.jwt.jwtpractice.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.jwt.jwtpractice.user.Member;
import com.jwt.jwtpractice.user.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Map;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtUtil {

    private final MemberRepository memberRepository;

    /* 1. access token 발행 */
    public String createAccessToken(MemberDetails memberDetails) {
        Member member = memberDetails.getMember();
        Map<String, Object> headerMap = Map.of("alg", "HMAC256");
        log.info("now : {}, accessToken expire: {}", new Date(System.currentTimeMillis()), new Date(System.currentTimeMillis() + (1000 * 60 * 60 * 24 * 7)));
        return JWT.create()
                .withHeader(headerMap)
                .withClaim("memberId", member.getMemberId())
                .withClaim("name", member.getName())
                .withClaim("roles", member.getRoleList())
                .withExpiresAt(new Date(System.currentTimeMillis() + (1000 * 60 * 60)))
                .sign(Algorithm.HMAC256("aaa"));
    }

    /* 2. refresh token 발행 */
    public String createRefreshToken(MemberDetails memberDetails) {
        Member member = memberDetails.getMember();
        Map<String, Object> headerMap = Map.of("alg", "HMAC256");
        String refreshToken = JWT.create()
                .withHeader(headerMap)
                .withClaim("memberId", member.getMemberId())
                .withClaim("name", member.getName())
                .withClaim("roles", member.getRoleList())
                .withExpiresAt(new Date(System.currentTimeMillis() + (1000 * 60 * 60 * 24 * 7)))
                .sign(Algorithm.HMAC256("aaa"));
        member.setToken(refreshToken);
        log.info("??? {}", member);
        memberRepository.save(member);
        return refreshToken;
    }

    /* 3. access token 검증 */
    public MemberDetails checkAccessToken(String accessToken) {
        /* 1. 받은 토큰 유효 시간 확인 */
        Date expiresAt = JWT.decode(accessToken).getExpiresAt();
        log.info("this token expire at : {} - it's {} now, so it is {}", expiresAt, new Date(), isExpired(accessToken) ? "expired" : "not expired");
        if (isExpired(accessToken)) return null;
        String memberId = JWT.require(Algorithm.HMAC256("aaa")).build().verify(accessToken).getClaim("memberId").toString().replaceAll("\"", "");
        if (memberId == null) return null;
        String roles = JWT.decode(accessToken).getClaim("roles").asList(String.class).stream().collect(Collectors.joining(","));
        Member member = new Member();
        member.setMemberId(memberId);
        member.setRoles(roles);
        return new MemberDetails(member);

    }

    /* 4. refresh token 검증 */
    public MemberDetails checkRefreshToken(String refreshToken) {
        if (refreshToken.isEmpty() || isExpired(refreshToken)) return null;
        Member member = memberRepository.findByToken(refreshToken);
        return new MemberDetails(member);
    }

    public boolean isExpired(String token) {

        return JWT.decode(token).getExpiresAt().toInstant().isBefore(new Date().toInstant());
    }


}
