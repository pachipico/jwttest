package com.jwt.jwtpractice;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class BasicController {

    @PostMapping("/")
    public String login(){
        return "asdfas";
    }
}
