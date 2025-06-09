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

import java.time.LocalDateTime;

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

        // when
        tokenBlacklistService.addTokenToBlacklist(accessToken, userId);

        // then
        verify(tokenBlacklistRepository).save(any(TokenBlacklist.class));
    }

    @Test
    @DisplayName("만료된 토큰은 블랙리스트에 추가하지 않는다")
    void addTokenToBlacklist_should_not_add_expired_token() {
        // given
        String accessToken = "expired.jwt.token";
        Long userId = 1L;
        String jti = "test-jti-123";
        LocalDateTime expiresAt = LocalDateTime.now().minusHours(1); // 이미 만료됨

        Claims mockClaims = mock(Claims.class);
        given(jwtTokenProvider.parseToken(accessToken)).willReturn(mockClaims);
        given(mockClaims.getId()).willReturn(jti);
        given(jwtTokenProvider.getExpirationTime(mockClaims)).willReturn(expiresAt);

        // when
        tokenBlacklistService.addTokenToBlacklist(accessToken, userId);

        // then
        verify(tokenBlacklistRepository, never()).save(any(TokenBlacklist.class));
    }

    @Test
    @DisplayName("JTI가 없는 토큰은 블랙리스트에 추가하지 않는다")
    void addTokenToBlacklist_should_not_add_token_without_jti() {
        // given
        String accessToken = "token.without.jti";
        Long userId = 1L;

        Claims mockClaims = mock(Claims.class);
        given(jwtTokenProvider.parseToken(accessToken)).willReturn(mockClaims);
        given(mockClaims.getId()).willReturn(null); // JTI 없음

        // when
        tokenBlacklistService.addTokenToBlacklist(accessToken, userId);

        // then
        verify(tokenBlacklistRepository, never()).save(any(TokenBlacklist.class));
    }

    @Test
    @DisplayName("JTI가 빈 문자열인 토큰은 블랙리스트에 추가하지 않는다")
    void addTokenToBlacklist_should_not_add_token_with_empty_jti() {
        // given
        String accessToken = "token.with.empty.jti";
        Long userId = 1L;

        Claims mockClaims = mock(Claims.class);
        given(jwtTokenProvider.parseToken(accessToken)).willReturn(mockClaims);
        given(mockClaims.getId()).willReturn(""); // 빈 JTI

        // when
        tokenBlacklistService.addTokenToBlacklist(accessToken, userId);

        // then
        verify(tokenBlacklistRepository, never()).save(any(TokenBlacklist.class));
    }

    @Test
    @DisplayName("이미 블랙리스트에 있는 토큰은 중복 추가하지 않는다")
    void addTokenToBlacklist_should_not_add_duplicate_jti() {
        // given
        String accessToken = "duplicate.jwt.token";
        Long userId = 1L;
        String jti = "existing-jti";
        LocalDateTime expiresAt = LocalDateTime.now().plusHours(1);

        Claims mockClaims = mock(Claims.class);
        given(jwtTokenProvider.parseToken(accessToken)).willReturn(mockClaims);
        given(mockClaims.getId()).willReturn(jti);
        given(jwtTokenProvider.getExpirationTime(mockClaims)).willReturn(expiresAt);
        given(tokenBlacklistRepository.existsById(jti)).willReturn(true); // 이미 존재

        // when
        tokenBlacklistService.addTokenToBlacklist(accessToken, userId);

        // then
        verify(tokenBlacklistRepository, never()).save(any(TokenBlacklist.class));
    }

    @Test
    @DisplayName("토큰 파싱 실패 시 예외를 던지지 않고 조용히 처리한다")
    void addTokenToBlacklist_should_handle_parse_failure_gracefully() {
        // given
        String invalidToken = "invalid.token";
        Long userId = 1L;

        given(jwtTokenProvider.parseToken(invalidToken))
                .willThrow(new RuntimeException("토큰 파싱 실패"));

        // when & then - 예외가 발생하지 않아야 함
        assertThatCode(() -> tokenBlacklistService.addTokenToBlacklist(invalidToken, userId))
                .doesNotThrowAnyException();

        verify(tokenBlacklistRepository, never()).save(any(TokenBlacklist.class));
    }

    @Test
    @DisplayName("블랙리스트에 있는 토큰인지 정확히 확인한다")
    void isBlacklisted_should_return_true_for_blacklisted_token() {
        // given
        String jti = "blacklisted-jti";

        given(tokenBlacklistRepository.existsByJtiAndExpiresAtAfter(eq(jti), any(LocalDateTime.class)))
                .willReturn(true);

        // when
        boolean result = tokenBlacklistService.isBlacklisted(jti);

        // then
        assertThat(result).isTrue();
        verify(tokenBlacklistRepository).existsByJtiAndExpiresAtAfter(eq(jti), any(LocalDateTime.class));
    }

    @Test
    @DisplayName("블랙리스트에 없는 토큰은 false를 반환한다")
    void isBlacklisted_should_return_false_for_non_blacklisted_token() {
        // given
        String jti = "non-blacklisted-jti";

        given(tokenBlacklistRepository.existsByJtiAndExpiresAtAfter(eq(jti), any(LocalDateTime.class)))
                .willReturn(false);

        // when
        boolean result = tokenBlacklistService.isBlacklisted(jti);

        // then
        assertThat(result).isFalse();
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

    @Test
    @DisplayName("토큰 정리 중 예외가 발생해도 애플리케이션이 중단되지 않는다")
    void cleanupExpiredTokens_should_handle_exceptions_gracefully() {
        // given
        doThrow(new RuntimeException("DB 연결 실패"))
                .when(tokenBlacklistRepository).deleteExpiredTokens(any(LocalDateTime.class));

        // when & then - 예외가 발생하지 않아야 함
        assertThatCode(() -> tokenBlacklistService.cleanupExpiredTokens())
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("새로운 토큰을 블랙리스트에 추가할 때 올바른 정보가 저장된다")
    void addTokenToBlacklist_should_save_correct_information() {
        // given
        String accessToken = "valid.jwt.token";
        Long userId = 1L;
        String jti = "new-jti";
        LocalDateTime expiresAt = LocalDateTime.now().plusHours(1);

        Claims mockClaims = mock(Claims.class);
        given(jwtTokenProvider.parseToken(accessToken)).willReturn(mockClaims);
        given(mockClaims.getId()).willReturn(jti);
        given(jwtTokenProvider.getExpirationTime(mockClaims)).willReturn(expiresAt);
        given(tokenBlacklistRepository.existsById(jti)).willReturn(false);

        // when
        tokenBlacklistService.addTokenToBlacklist(accessToken, userId);

        // then
        verify(tokenBlacklistRepository).save(argThat(tokenBlacklist ->
                tokenBlacklist.getJti().equals(jti) &&
                        tokenBlacklist.getUserId().equals(userId) &&
                        tokenBlacklist.getExpiresAt().equals(expiresAt)
        ));
    }
}