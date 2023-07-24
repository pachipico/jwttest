package com.jwt.jwtpractice.aop;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Before;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.http.HttpRequest;

@Component
@org.aspectj.lang.annotation.Aspect
@Slf4j
public class Aspect {


    @Around("execution(* com.jwt.jwtpractice.user.*Controller.*(..))")
    public Object around(ProceedingJoinPoint joinPoint) throws Throwable {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        String accessToken = request.getHeader("accessToken");
        String refreshToken = request.getHeader("refreshToken");
        log.info("\naccessToken: {}\nrefreshToken: {}", accessToken, refreshToken);
        Object proceed = joinPoint.proceed();
        return proceed;
    }

}
