package com.jwt.jwtpractice.user;

import com.jwt.jwtpractice.jwt.JwtUtil;
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
    public Member save(@RequestBody Member member){
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
    public Member findById(String id){
        return repository.findByMemberId(id);
    }

    @GetMapping("admin")
    public String admin() {
        return "admin page";
    }
}
