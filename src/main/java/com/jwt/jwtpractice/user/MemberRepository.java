package com.jwt.jwtpractice.user;

import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<Member, String> {
    public Member findByMemberId(String memberId);
}
