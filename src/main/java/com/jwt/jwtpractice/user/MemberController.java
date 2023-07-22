package com.jwt.jwtpractice.user;

import com.jwt.jwtpractice.jwt.JwtUtil;
import com.jwt.jwtpractice.jwt.MemberDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

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
    public String reissue(@RequestBody String refreshToken) {
        // 1. refreshToken 으로 member_info 확인 후 있으면 가져옴
        Member member = repository.findByToken(refreshToken);
        if (member == null) throw new RuntimeException("토큰이 틀렸는데용");


        // 2. 같다면 accessToken 재발행 후 전송
        return jwtUtil.createAccessToken(new MemberDetails(member));
    }
}
