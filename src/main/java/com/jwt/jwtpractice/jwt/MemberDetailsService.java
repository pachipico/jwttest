package com.jwt.jwtpractice.jwt;

import com.jwt.jwtpractice.user.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
@Slf4j
public class MemberDetailsService implements UserDetailsService {

    private final MemberRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        MemberDetails memberDetails = new MemberDetails(repository.findByMemberId(username));
        if(memberDetails == null) {
            log.error("없잖아");
            throw new UsernameNotFoundException("id를 확인해봐~");
        }
        return memberDetails;
    }
}
