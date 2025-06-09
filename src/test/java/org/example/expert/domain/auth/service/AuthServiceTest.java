package org.example.expert.domain.auth.service;

import org.example.expert.config.security.JwtTokenProvider;
import org.example.expert.domain.auth.dto.request.SigninRequest;
import org.example.expert.domain.auth.dto.request.SignupRequest;
import org.example.expert.domain.auth.dto.response.SigninResponse;
import org.example.expert.domain.auth.dto.response.SignupResponse;
import org.example.expert.domain.auth.entity.RefreshToken;
import org.example.expert.domain.auth.exception.RateLimitException;
import org.example.expert.domain.common.exception.InvalidRequestException;
import org.example.expert.domain.user.entity.User;
import org.example.expert.domain.user.enums.UserRole;
import org.example.expert.domain.user.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.BDDMockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private JwtTokenProvider jwtTokenProvider;
    @Mock
    private RefreshTokenService refreshTokenService;
    @Mock
    private TokenBlacklistService tokenBlacklistService;
    @Mock
    private LoginAttemptService loginAttemptService;

    @InjectMocks
    private AuthService authService;

    @Test
    @DisplayName("회원가입이 성공적으로 처리된다")
    void signup_should_succeed() {
        // given
        SignupRequest request = new SignupRequest("test@test.com", "password123", "USER");
        User savedUser = createUser();

        given(userRepository.existsByEmail("test@test.com")).willReturn(false);
        given(passwordEncoder.encode("password123")).willReturn("encodedPassword");
        given(userRepository.save(any(User.class))).willReturn(savedUser);
        given(jwtTokenProvider.createToken(1L, "test@test.com", UserRole.USER)).willReturn("access-token");
        given(refreshTokenService.createRefreshToken(1L)).willReturn("refresh-token");

        // when
        SignupResponse response = authService.signup(request);

        // then
        assertThat(response.getBearerToken()).isEqualTo("access-token");
        assertThat(response.getRefreshToken()).isEqualTo("refresh-token");

        verify(userRepository).existsByEmail("test@test.com");
        verify(passwordEncoder).encode("password123");
        verify(userRepository).save(any(User.class));
        verify(jwtTokenProvider).createToken(1L, "test@test.com", UserRole.USER);
        verify(refreshTokenService).createRefreshToken(1L);
    }

    @Test
    @DisplayName("로그인이 성공적으로 처리된다")
    void signin_should_succeed() {
        // given
        SigninRequest request = new SigninRequest("test@test.com", "password123");
        User user = createUser();

        given(loginAttemptService.isBlocked("test@test.com")).willReturn(false);
        given(userRepository.findByEmail("test@test.com")).willReturn(Optional.of(user));
        given(passwordEncoder.matches("password123", "encodedPassword")).willReturn(true);
        given(jwtTokenProvider.createToken(1L, "test@test.com", UserRole.USER)).willReturn("access-token");
        given(refreshTokenService.createRefreshToken(1L)).willReturn("refresh-token");

        // when
        SigninResponse response = authService.signin(request);

        // then
        assertThat(response.getBearerToken()).isEqualTo("access-token");
        assertThat(response.getRefreshToken()).isEqualTo("refresh-token");

        verify(loginAttemptService).isBlocked("test@test.com");
        verify(userRepository).findByEmail("test@test.com");
        verify(passwordEncoder).matches("password123", "encodedPassword");
        verify(jwtTokenProvider).createToken(1L, "test@test.com", UserRole.USER);
        verify(refreshTokenService).createRefreshToken(1L);
        verify(loginAttemptService).recordSuccessfulLogin("test@test.com");
    }

    @Test
    @DisplayName("차단된 사용자는 로그인할 수 없다")
    void signin_should_fail_when_user_is_blocked() {
        // given
        SigninRequest request = new SigninRequest("blocked@test.com", "password123");
        given(loginAttemptService.isBlocked("blocked@test.com")).willReturn(true);
        given(loginAttemptService.getRemainingBlockTimeMinutes("blocked@test.com")).willReturn(10L);

        // when & then
        assertThatThrownBy(() -> authService.signin(request))
                .isInstanceOf(RateLimitException.class)
                .hasMessage("로그인이 일시적으로 차단되었습니다.");

        verify(loginAttemptService).isBlocked("blocked@test.com");
        verify(userRepository, never()).findByEmail(anyString());
    }

    @Test
    @DisplayName("RefreshToken으로 새로운 토큰을 발급받는다")
    void refreshToken_should_generate_new_tokens() {
        // given
        String refreshTokenValue = "refresh-token";
        RefreshToken refreshToken = new RefreshToken(refreshTokenValue, 1L, LocalDateTime.now().plusDays(14));
        User user = createUser();

        given(refreshTokenService.validateRefreshToken(refreshTokenValue)).willReturn(refreshToken);
        given(userRepository.findById(1L)).willReturn(Optional.of(user));
        given(jwtTokenProvider.createToken(1L, "test@test.com", UserRole.USER)).willReturn("new-access-token");
        given(refreshTokenService.createRefreshToken(1L)).willReturn("new-refresh-token");

        // when
        SigninResponse response = authService.refreshToken(refreshTokenValue);

        // then
        assertThat(response.getBearerToken()).isEqualTo("new-access-token");
        assertThat(response.getRefreshToken()).isEqualTo("new-refresh-token");

        verify(refreshTokenService).validateRefreshToken(refreshTokenValue);
        verify(userRepository).findById(1L);
        verify(jwtTokenProvider).createToken(1L, "test@test.com", UserRole.USER);
        verify(refreshTokenService).createRefreshToken(1L);
    }

    @Test
    @DisplayName("유효하지 않은 RefreshToken으로 갱신 시 예외가 발생한다")
    void refreshToken_should_fail_with_invalid_token() {
        // given
        String invalidToken = "invalid-token";
        given(refreshTokenService.validateRefreshToken(invalidToken))
                .willThrow(new InvalidRequestException("유효하지 않은 Refresh Token입니다."));

        // when & then
        assertThatThrownBy(() -> authService.refreshToken(invalidToken))
                .isInstanceOf(InvalidRequestException.class)
                .hasMessage("유효하지 않은 Refresh Token입니다.");

        verify(userRepository, never()).findById(anyLong());
        verify(jwtTokenProvider, never()).createToken(anyLong(), anyString(), any(UserRole.class));
    }

    @Test
    @DisplayName("존재하지 않는 사용자의 RefreshToken으로 갱신 시 예외가 발생한다")
    void refreshToken_should_fail_when_user_not_found() {
        // given
        String refreshTokenValue = "valid-token";
        RefreshToken refreshToken = new RefreshToken(refreshTokenValue, 999L, LocalDateTime.now().plusDays(14));

        given(refreshTokenService.validateRefreshToken(refreshTokenValue)).willReturn(refreshToken);
        given(userRepository.findById(999L)).willReturn(Optional.empty());

        // when & then
        assertThatThrownBy(() -> authService.refreshToken(refreshTokenValue))
                .isInstanceOf(InvalidRequestException.class)
                .hasMessage("사용자를 찾을 수 없습니다.");

        verify(jwtTokenProvider, never()).createToken(anyLong(), anyString(), any(UserRole.class));
    }

    @Test
    @DisplayName("로그아웃이 성공적으로 처리된다")
    void logout_should_succeed() {
        // given
        Long userId = 1L;
        String accessToken = "access-token";

        // when
        authService.logout(userId, accessToken);

        // then
        verify(tokenBlacklistService).addTokenToBlacklist(accessToken, userId);
        verify(refreshTokenService).deleteRefreshTokenByUserId(userId);
    }

    @Test
    @DisplayName("AccessToken 없이 로그아웃해도 RefreshToken은 삭제된다")
    void logout_should_succeed_without_access_token() {
        // given
        Long userId = 1L;
        String accessToken = null;

        // when
        authService.logout(userId, accessToken);

        // then
        verify(tokenBlacklistService, never()).addTokenToBlacklist(anyString(), anyLong());
        verify(refreshTokenService).deleteRefreshTokenByUserId(userId);
    }

    @Test
    @DisplayName("빈 AccessToken으로 로그아웃해도 RefreshToken은 삭제된다")
    void logout_should_succeed_with_empty_access_token() {
        // given
        Long userId = 1L;
        String accessToken = "";

        // when
        authService.logout(userId, accessToken);

        // then
        verify(tokenBlacklistService, never()).addTokenToBlacklist(anyString(), anyLong());
        verify(refreshTokenService).deleteRefreshTokenByUserId(userId);
    }

    @Test
    @DisplayName("로그아웃 중 블랙리스트 추가 실패해도 RefreshToken은 삭제된다")
    void logout_should_delete_refresh_token_even_when_blacklist_fails() {
        // given
        Long userId = 1L;
        String accessToken = "access-token";

        doThrow(new RuntimeException("블랙리스트 추가 실패"))
                .when(tokenBlacklistService).addTokenToBlacklist(accessToken, userId);

        // when & then
        assertThatThrownBy(() -> authService.logout(userId, accessToken))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("로그아웃 처리 중 오류가 발생했습니다.");

        // RefreshToken 삭제가 호출되었는지 확인 (실제로는 2번이 아닐 수 있음)
        verify(refreshTokenService, atLeastOnce()).deleteRefreshTokenByUserId(userId);
    }

    // 테스트 헬퍼 메서드
    private User createUser() {
        User user = new User("test@test.com", "encodedPassword", UserRole.USER);
        ReflectionTestUtils.setField(user, "id", 1L);
        return user;
    }
}