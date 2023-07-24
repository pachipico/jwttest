package com.jwt.jwtpractice.user;

import com.jwt.jwtpractice.jwt.JwtUtil;
import com.jwt.jwtpractice.jwt.MemberDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

@RestController
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/member")
public class MemberController {

    private final MemberRepository repository;

    private final BCryptPasswordEncoder passwordEncoder;

    private final JwtUtil jwtUtil;

    @PostMapping("save")
    public Member save(@RequestBody Member member) {
        log.info("member save: {}", member);
        member.setRoles("USER");
        member.setPassword(passwordEncoder.encode(member.getPassword()));
        Member saved = repository.save(member);
        return saved;
    }

    @GetMapping("findAll")
    public List<Member> findAll() {
        return repository.findAll();
    }

    @GetMapping("findById")
    public Member findById(String id) {
        return repository.findByMemberId(id);
    }

    @GetMapping("admin")
    public String admin() {
        return "admin page";
    }

    @GetMapping("reissue")
    public String reissue(HttpServletRequest request, HttpServletResponse response) {
        // 1. refreshToken 으로 member_info 확인 후 있으면 가져옴
        MemberDetails memberDetails = jwtUtil.checkRefreshToken(request.getHeader("refreshToken"));
        if (memberDetails == null) throw new AuthorizationServiceException("토큰이 틀렸는데용");
        // 2. 같다면 accessToken 재발행 후 전송
        String accessToken = jwtUtil.createAccessToken(memberDetails);
        response.addHeader("accessToken", accessToken);
        return "재발행해드렸어요";
    }


    @PostMapping("logout")
    public void logout(@RequestBody Member member) {
        log.info("??? {}", member);
        Member byMemberId = repository.findByMemberId(member.getMemberId());
        log.info("member : {}", byMemberId);
        byMemberId.setToken("");
        repository.save(byMemberId);
    }
}
