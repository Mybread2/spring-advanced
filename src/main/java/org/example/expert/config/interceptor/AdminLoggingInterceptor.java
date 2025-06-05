package org.example.expert.config.interceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.example.expert.domain.auth.exception.AuthException;
import org.example.expert.domain.user.enums.UserRole;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Slf4j
@Component
public class AdminLoggingInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(@NonNull HttpServletRequest request,
                             @NonNull HttpServletResponse response,
                             @NonNull Object handler) {

        String userRole = (String) request.getAttribute("userRole");
        Long userId = (Long) request.getAttribute("userId");
        String requestURI = request.getRequestURI();

        if (!UserRole.ADMIN.name().equals(userRole)) {
            log.warn("어드민 API 접근 거부 - 사용자 ID: {}, 권한: {}, URL: {}",
                    userId, userRole, requestURI);
            throw new AuthException("관리자 권한이 필요합니다.");
        }

        String requestTime = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        log.info("🔑 [Interceptor] 어드민 API 접근 성공");
        log.info("   ├─ 요청 시각: {}", requestTime);
        log.info("   └─ 요청 URL: {}", requestURI);

        return true; // 계속 진행
    }
}
