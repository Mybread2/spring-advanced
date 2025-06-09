
package org.example.expert.config.security;

import io.jsonwebtoken.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.expert.domain.auth.service.TokenBlacklistService;
import org.example.expert.domain.user.enums.UserRole;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationProvider {

    private final JwtTokenProvider jwtTokenProvider;
    private final JwtProperties jwtProperties;
    private final TokenBlacklistService tokenBlacklistService;

    // 요청에서 JWT 토큰을 추출하여 Authentication 객체 생성
    public Authentication getAuthentication(HttpServletRequest request) {
        String token = extractTokenFromRequest(request);

        if (!StringUtils.hasText(token)) {
            throw new BadCredentialsException("JWT 토큰이 없습니다.");
        }

        return createAuthentication(token);
    }

    // JWT 토큰으로부터 Authentication 객체 생성
    private Authentication createAuthentication(String token) {
        Claims claims = jwtTokenProvider.parseToken(token);

        // 블랙리스트 검증
        String jti = claims.getId();
        if (StringUtils.hasText(jti) && tokenBlacklistService.isBlacklisted(jti)) {
            throw new BadCredentialsException("로그아웃된 토큰입니다.");
        }

        // 사용자 정보 추출
        String userIdStr = claims.getSubject();
        String email = claims.get("email", String.class);
        String roleStr = claims.get("userRole", String.class);

        // 필수 정보 검증
        if (!StringUtils.hasText(userIdStr) || !StringUtils.hasText(email) || !StringUtils.hasText(roleStr)) {
            throw new BadCredentialsException("JWT 토큰에 필수 정보가 누락되었습니다.");
        }

        // UserPrincipal 생성
        UserPrincipal userPrincipal = UserPrincipal.builder()
                .id(Long.parseLong(userIdStr))
                .email(email)
                .role(UserRole.of(roleStr))
                .build();

        return new UsernamePasswordAuthenticationToken(
                userPrincipal,
                null,
                userPrincipal.getAuthorities()
        );
    }

    // 요청 헤더에서 JWT 토큰 추출
    public String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(jwtProperties.getBearerPrefix())) {
            String token = bearerToken.substring(7);
            return StringUtils.hasText(token) ? token : null;
        }

        return null;
    }
}