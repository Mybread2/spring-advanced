package org.example.expert.config.security.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        log.warn("인증 실패 - URI: {}, 메시지: {}", request.getRequestURI(), authException.getMessage());

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        Map<String, Object> errorResponse = createErrorResponse(authException);

        String jsonResponse = objectMapper.writeValueAsString(errorResponse);
        response.getWriter().write(jsonResponse);
    }

    private Map<String, Object> createErrorResponse(AuthenticationException authException) {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("success", false);
        errorResponse.put("timestamp", java.time.LocalDateTime.now());

        // 핵심: 토큰 만료 vs 기타 인증 오류만 구분
        if (authException instanceof CredentialsExpiredException) {
            errorResponse.put("code", "JWT_EXPIRED");
            errorResponse.put("message", "로그인 세션이 만료되었습니다.");
            errorResponse.put("requiresRefresh", true);

        } else {
            errorResponse.put("code", "AUTHENTICATION_FAILED");
            errorResponse.put("message", "인증에 실패했습니다. 다시 로그인해주세요.");
            errorResponse.put("requiresLogin", true);
        }

        return errorResponse;
    }
}