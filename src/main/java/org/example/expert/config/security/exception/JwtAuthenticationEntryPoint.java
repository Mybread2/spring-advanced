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

        Map<String, Object> errorResponse = getStringObjectMap(authException);

        String jsonResponse = objectMapper.writeValueAsString(errorResponse);
        response.getWriter().write(jsonResponse);
    }

    private static Map<String, Object> getStringObjectMap(AuthenticationException authException) {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("status", HttpStatus.UNAUTHORIZED.name());
        errorResponse.put("code", HttpStatus.UNAUTHORIZED.value());

        // JWT 토큰 만료인지 확인
        if (authException instanceof CredentialsExpiredException) {
            errorResponse.put("message", "JWT 토큰이 만료되었습니다. 다시 로그인해주세요.");
            errorResponse.put("requiresRefresh", true); // ← 이 힌트 추가!
        } else {
            errorResponse.put("message", "인증이 필요합니다.");
            errorResponse.put("requiresRefresh", false);
        }
        errorResponse.put("message", "인증이 필요합니다.");
        return errorResponse;
    }
}