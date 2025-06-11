package org.example.expert.domain.auth.service;

import io.jsonwebtoken.Claims;
import org.example.expert.config.security.JwtTokenProvider;
import org.example.expert.domain.auth.entity.TokenBlacklist;
import org.example.expert.domain.auth.repository.TokenBlacklistRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.LocalDateTime;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TokenBlacklistServiceTest {

    @Mock
    private TokenBlacklistRepository tokenBlacklistRepository;

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private RedisTemplate<String, Object> redisTemplate;

    @Mock
    private ValueOperations<String, Object> valueOperations;

    @InjectMocks
    private TokenBlacklistService tokenBlacklistService;

    @Test
    @DisplayName("유효한 토큰을 블랙리스트에 추가한다")
    void addTokenToBlacklist_should_add_valid_token() {
        // given
        String accessToken = "valid.jwt.token";
        Long userId = 1L;
        String jti = "test-jti-123";
        LocalDateTime expiresAt = LocalDateTime.now().plusHours(1);

        Claims mockClaims = mock(Claims.class);
        given(jwtTokenProvider.parseToken(accessToken)).willReturn(mockClaims);
        given(mockClaims.getId()).willReturn(jti);
        given(jwtTokenProvider.getExpirationTime(mockClaims)).willReturn(expiresAt);
        given(tokenBlacklistRepository.existsById(jti)).willReturn(false);

        // Redis Mock 설정
        given(redisTemplate.opsForValue()).willReturn(valueOperations);

        // when
        tokenBlacklistService.addTokenToBlacklist(accessToken, userId);

        // then
        verify(tokenBlacklistRepository).save(any(TokenBlacklist.class));
        verify(valueOperations).set(eq("blacklist:" + jti), eq("blocked"), anyLong(), eq(TimeUnit.SECONDS));
    }

    @Test
    @DisplayName("만료된 토큰은 블랙리스트에 추가하지 않는다")
    void addTokenToBlacklist_should_not_add_expired_token() {
        // given
        String accessToken = "expired.jwt.token";
        Long userId = 1L;
        String jti = "test-jti-123";
        LocalDateTime expiresAt = LocalDateTime.now().minusHours(1);

        Claims mockClaims = mock(Claims.class);
        given(jwtTokenProvider.parseToken(accessToken)).willReturn(mockClaims);
        given(mockClaims.getId()).willReturn(jti);
        given(jwtTokenProvider.getExpirationTime(mockClaims)).willReturn(expiresAt);

        // when
        tokenBlacklistService.addTokenToBlacklist(accessToken, userId);

        // then
        verify(tokenBlacklistRepository, never()).save(any(TokenBlacklist.class));
        verify(redisTemplate, never()).opsForValue();
    }

    @Test
    @DisplayName("JTI가 없는 토큰은 블랙리스트에 추가하지 않는다")
    void addTokenToBlacklist_should_not_add_token_without_jti() {
        // given
        String accessToken = "token.without.jti";
        Long userId = 1L;

        Claims mockClaims = mock(Claims.class);
        given(jwtTokenProvider.parseToken(accessToken)).willReturn(mockClaims);
        given(mockClaims.getId()).willReturn(null);

        // when
        tokenBlacklistService.addTokenToBlacklist(accessToken, userId);

        // then
        verify(tokenBlacklistRepository, never()).save(any(TokenBlacklist.class));
        verify(redisTemplate, never()).opsForValue();
    }

    @Test
    @DisplayName("블랙리스트에 있는 토큰인지 정확히 확인한다 - Redis에서 발견")
    void isBlacklisted_should_return_true_when_found_in_redis() {
        // given
        String jti = "blacklisted-jti";
        String redisKey = "blacklist:" + jti;

        given(redisTemplate.hasKey(redisKey)).willReturn(true);

        // when
        boolean result = tokenBlacklistService.isBlacklisted(jti);

        // then
        assertThat(result).isTrue();
        verify(redisTemplate).hasKey(redisKey);
        verify(tokenBlacklistRepository, never()).existsByJtiAndExpiresAtAfter(anyString(), any(LocalDateTime.class));
    }

    @Test
    @DisplayName("블랙리스트에 없는 토큰은 false를 반환한다")
    void isBlacklisted_should_return_false_for_non_blacklisted_token() {
        // given
        String jti = "non-blacklisted-jti";
        String redisKey = "blacklist:" + jti;

        given(redisTemplate.hasKey(redisKey)).willReturn(false);
        given(tokenBlacklistRepository.existsByJtiAndExpiresAtAfter(eq(jti), any(LocalDateTime.class)))
                .willReturn(false);

        // when
        boolean result = tokenBlacklistService.isBlacklisted(jti);

        // then
        assertThat(result).isFalse();
        verify(redisTemplate).hasKey(redisKey);
        verify(tokenBlacklistRepository).existsByJtiAndExpiresAtAfter(eq(jti), any(LocalDateTime.class));
    }

    @Test
    @DisplayName("만료된 토큰들을 정리한다")
    void cleanupExpiredTokens_should_delete_expired_tokens() {
        // when
        tokenBlacklistService.cleanupExpiredTokens();

        // then
        verify(tokenBlacklistRepository).deleteExpiredTokens(any(LocalDateTime.class));
    }
}