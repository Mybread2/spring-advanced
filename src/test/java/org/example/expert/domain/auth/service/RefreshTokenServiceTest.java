package org.example.expert.domain.auth.service;

import org.example.expert.domain.auth.entity.RefreshToken;
import org.example.expert.domain.auth.repository.RefreshTokenRepository;
import org.example.expert.domain.common.exception.InvalidRequestException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @InjectMocks
    private RefreshTokenService refreshTokenService;

    @Test
    @DisplayName("RefreshToken을 생성한다")
    void createRefreshToken_works() {
        // given
        Long userId = 1L;

        // when
        String result = refreshTokenService.createRefreshToken(userId);

        // then
        assertThat(result).isNotNull();
        assertThat(result).isNotEmpty();

        verify(refreshTokenRepository).deleteByUserId(userId);
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    @DisplayName("유효한 RefreshToken을 검증한다")
    void validateRefreshToken_works() {
        // given
        String tokenValue = "valid-token";
        RefreshToken refreshToken = new RefreshToken(tokenValue, 1L, LocalDateTime.now().plusDays(7));

        given(refreshTokenRepository.findByToken(tokenValue)).willReturn(Optional.of(refreshToken));

        // when
        RefreshToken result = refreshTokenService.validateRefreshToken(tokenValue);

        // then
        assertThat(result).isEqualTo(refreshToken);
        verify(refreshTokenRepository).findByToken(tokenValue);
    }

    @Test
    @DisplayName("존재하지 않는 RefreshToken 검증 시 예외가 발생한다")
    void validateRefreshToken_should_fail_when_token_not_found() {
        // given
        String tokenValue = "non-existent-token";
        given(refreshTokenRepository.findByToken(tokenValue)).willReturn(Optional.empty());

        // when & then
        assertThatThrownBy(() -> refreshTokenService.validateRefreshToken(tokenValue))
                .isInstanceOf(InvalidRequestException.class)
                .hasMessage("유효하지 않은 Refresh Token 입니다.");
    }

    @Test
    @DisplayName("만료된 RefreshToken 검증 시 예외가 발생한다")
    void validateRefreshToken_should_fail_when_token_expired() {
        // given
        String tokenValue = "expired-token";
        RefreshToken expiredToken = new RefreshToken(tokenValue, 1L, LocalDateTime.now().minusDays(1));

        given(refreshTokenRepository.findByToken(tokenValue)).willReturn(Optional.of(expiredToken));

        // when & then
        assertThatThrownBy(() -> refreshTokenService.validateRefreshToken(tokenValue))
                .isInstanceOf(InvalidRequestException.class)
                .hasMessage("만료된 Refresh Token 입니다.");
    }

    @Test
    @DisplayName("사용자별 RefreshToken을 삭제한다")
    void deleteRefreshTokenByUserId_works() {
        // given
        Long userId = 1L;

        // when
        refreshTokenService.deleteRefreshTokenByUserId(userId);

        // then
        verify(refreshTokenRepository).deleteByUserId(userId);
    }
}