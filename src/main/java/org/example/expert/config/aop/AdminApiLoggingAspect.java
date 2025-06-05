package org.example.expert.config.aop;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.lang.reflect.Method;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;

@Slf4j
@Aspect
@Component
@RequiredArgsConstructor
public class AdminApiLoggingAspect {

    private final ObjectMapper objectMapper;

    @Around("@annotation(org.example.expert.config.annotation.AdminAudit)")
    public Object logAdminApi(ProceedingJoinPoint joinPoint) throws Throwable {

        try {
            HttpServletRequest request = ((ServletRequestAttributes)
                    RequestContextHolder.currentRequestAttributes()).getRequest();

            log.info("요청한 사용자의 ID: {}", request.getAttribute("userId"));
            log.info("API 요청 시각: {}", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
            log.info("API 요청 URL: {} {}", request.getMethod(), request.getRequestURI());
            log.info("요청 본문: {}", getRequestBodyJson(joinPoint.getArgs()));

            Object result = joinPoint.proceed();

            log.info("응답 본문: {}", getResponseBodyJson(result, joinPoint));

            return result;

        } catch (Exception e) {
            log.warn("로깅 실패: {}", e.getMessage());
            return joinPoint.proceed();
        }
    }

    private String getRequestBodyJson(Object[] args) {
        try {
            return objectMapper.writeValueAsString(args);
        } catch (Exception e) {
            return Arrays.toString(args);
        }
    }

    private String getResponseBodyJson(Object result, ProceedingJoinPoint joinPoint) {
        try {
            Method method = ((MethodSignature) joinPoint.getSignature()).getMethod();
            if (method.getReturnType() == void.class) {
                return "void";
            }
            return objectMapper.writeValueAsString(result);
        } catch (Exception e) {
            return result != null ? result.toString() : "null";
        }
    }
}