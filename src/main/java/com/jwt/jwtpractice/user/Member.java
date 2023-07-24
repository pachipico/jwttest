package com.jwt.jwtpractice.user;

import lombok.Data;
import org.springframework.lang.Nullable;
import org.springframework.security.core.GrantedAuthority;


import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

import java.util.Arrays;
import java.util.List;

@Data
@Entity
@Table(name = "member_info")
public class Member {

    @Id
    private String memberId;

    @Nullable
    private String name;

    private String token;

    private String roles;

    private String password;

    public List<String> getRoleList() {
        return Arrays.asList(roles.split(","));
    }
}
