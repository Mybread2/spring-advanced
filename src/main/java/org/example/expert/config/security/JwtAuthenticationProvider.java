
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

    public Authentication getAuthentication(HttpServletRequest request) {
        String token = extractTokenFromRequest(request);

        if (!StringUtils.hasText(token)) {
            throw new BadCredentialsException("JWT 토큰이 없습니다.");
        }

        return createAuthentication(token);
    }

    private Authentication createAuthentication(String token) {
        Claims claims = jwtTokenProvider.parseToken(token);

        String jti = claims.getId();
        if (StringUtils.hasText(jti) && tokenBlacklistService.isBlacklisted(jti)) {
            throw new BadCredentialsException("로그아웃된 토큰입니다.");
        }

        String userIdStr = claims.getSubject();
        String email = claims.get("email", String.class);
        String roleStr = claims.get("userRole", String.class);

        if (!StringUtils.hasText(userIdStr) || !StringUtils.hasText(email) || !StringUtils.hasText(roleStr)) {
            throw new BadCredentialsException("JWT 토큰에 필수 정보가 누락되었습니다.");
        }

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

    public String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(jwtProperties.getBearerPrefix())) {
            String token = bearerToken.substring(7);
            return StringUtils.hasText(token) ? token : null;
        }

        return null;
    }
}