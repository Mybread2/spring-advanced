
package org.example.expert.config.security;

import io.jsonwebtoken.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.expert.domain.user.enums.UserRole;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
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
        try {
            // JwtTokenProvider 에게 토큰 파싱 위임
            Claims claims = jwtTokenProvider.parseToken(token);

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

            // Authentication 객체 반환
            return new UsernamePasswordAuthenticationToken(
                    userPrincipal,
                    null,
                    userPrincipal.getAuthorities()
            );

        } catch (ExpiredJwtException e) {
            log.debug("만료된 JWT 토큰: {}", e.getMessage());
            throw new CredentialsExpiredException("JWT 토큰이 만료되었습니다.");
        } catch (SignatureException | MalformedJwtException | UnsupportedJwtException e) {
            log.debug("유효하지 않은 JWT 토큰: {}", e.getMessage());
            throw new BadCredentialsException("유효하지 않은 JWT 토큰입니다.");
        } catch (NumberFormatException e) {
            throw new BadCredentialsException("JWT 토큰의 사용자 ID가 올바르지 않습니다.");
        } catch (IllegalArgumentException e) {
            throw new BadCredentialsException("JWT 토큰 정보가 올바르지 않습니다.");
        } catch (Exception e) {
            log.error("JWT 토큰 처리 중 예상치 못한 오류: {}", e.getMessage());
            throw new BadCredentialsException("JWT 토큰 처리 중 오류가 발생했습니다.");
        }
    }

    // 요청 헤더에서 JWT 토큰 추출
    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(jwtProperties.getBearerPrefix())) {
            String token = bearerToken.substring(7);
            return StringUtils.hasText(token) ? token : null;
        }

        return null;
    }
}