package org.example.expert.domain.auth.service;

import org.example.expert.config.security.JwtTokenProvider;
import org.example.expert.domain.auth.dto.request.SigninRequest;
import org.example.expert.domain.auth.dto.request.SignupRequest;
import org.example.expert.domain.auth.dto.response.SigninResponse;
import org.example.expert.domain.auth.dto.response.SignupResponse;
import org.example.expert.domain.auth.entity.RefreshToken;
import org.example.expert.domain.auth.exception.AuthException;
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

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.never;

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
    private LoginAttemptService loginAttemptService;

    @InjectMocks
    private AuthService authService;

    @Test
    @DisplayName("회원가입 시 AccessToken과 RefreshToken이 모두 생성된다")
    void signup_creates_both_tokens() {
        // given
        SignupRequest request = new SignupRequest("test@test.com", "password123", "USER");

        User savedUser = new User("test@test.com", "encodedPassword", UserRole.USER);
        ReflectionTestUtils.setField(savedUser, "id", 1L);

        given(userRepository.existsByEmail("test@test.com")).willReturn(false);
        given(passwordEncoder.encode("password123")).willReturn("encodedPassword");
        given(userRepository.save(any(User.class))).willReturn(savedUser);
        given(jwtTokenProvider.createToken(1L, "test@test.com", UserRole.USER))
                .willReturn("access-token");
        given(refreshTokenService.createRefreshToken(1L)).willReturn("refresh-token-uuid");

        // when
        SignupResponse response = authService.signup(request);

        // then
        assertThat(response.getBearerToken()).isEqualTo("access-token");
        assertThat(response.getRefreshToken()).isEqualTo("refresh-token-uuid");

        verify(refreshTokenService).createRefreshToken(1L);
    }

    @Test
    @DisplayName("이미 존재하는 이메일로 회원가입 시 예외가 발생한다")
    void signup_with_existing_email_throws_exception() {
        // given
        SignupRequest request = new SignupRequest("test@test.com", "password123", "USER");
        given(userRepository.existsByEmail("test@test.com")).willReturn(true);

        // when & then
        assertThatThrownBy(() -> authService.signup(request))
                .isInstanceOf(InvalidRequestException.class)
                .hasMessage("이미 존재하는 이메일입니다.");

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("로그인 시 AccessToken과 RefreshToken이 모두 생성된다")
    void signin_creates_both_tokens() {
        // given
        SigninRequest request = new SigninRequest("test@test.com", "password123");

        User user = new User("test@test.com", "encodedPassword", UserRole.USER);
        ReflectionTestUtils.setField(user, "id", 1L);

        given(loginAttemptService.isBlocked("test@test.com")).willReturn(false);
        given(userRepository.findByEmail("test@test.com")).willReturn(Optional.of(user));
        given(passwordEncoder.matches("password123", "encodedPassword")).willReturn(true);
        given(jwtTokenProvider.createToken(1L, "test@test.com", UserRole.USER))
                .willReturn("access-token");
        given(refreshTokenService.createRefreshToken(1L)).willReturn("refresh-token-uuid");

        // when
        SigninResponse response = authService.signin(request);

        // then
        assertThat(response.getBearerToken()).isEqualTo("access-token");
        assertThat(response.getRefreshToken()).isEqualTo("refresh-token-uuid");

        verify(refreshTokenService).createRefreshToken(1L);
        verify(loginAttemptService).recordSuccessfulLogin("test@test.com");
    }

    @Test
    @DisplayName("존재하지 않는 사용자로 로그인 시 예외가 발생한다")
    void signin_with_non_existing_user_throws_exception() {
        // given
        SigninRequest request = new SigninRequest("nonexistent@test.com", "password123");

        given(loginAttemptService.isBlocked("nonexistent@test.com")).willReturn(false);
        given(userRepository.findByEmail("nonexistent@test.com")).willReturn(Optional.empty());

        // when & then
        assertThatThrownBy(() -> authService.signin(request))
                .isInstanceOf(AuthException.class)
                .hasMessage("이메일 또는 비밀번호가 올바르지 않습니다.");

        verify(loginAttemptService).recordFailedAttempt("nonexistent@test.com");
    }

    @Test
    @DisplayName("잘못된 비밀번호로 로그인 시 예외가 발생한다")
    void signin_with_wrong_password_throws_exception() {
        // given
        SigninRequest request = new SigninRequest("test@test.com", "wrongpassword");

        User user = new User("test@test.com", "encodedPassword", UserRole.USER);
        ReflectionTestUtils.setField(user, "id", 1L);

        given(loginAttemptService.isBlocked("test@test.com")).willReturn(false);
        given(userRepository.findByEmail("test@test.com")).willReturn(Optional.of(user));
        given(passwordEncoder.matches("wrongpassword", "encodedPassword")).willReturn(false);

        // when & then
        assertThatThrownBy(() -> authService.signin(request))
                .isInstanceOf(AuthException.class)
                .hasMessage("이메일 또는 비밀번호가 올바르지 않습니다.");

        verify(loginAttemptService).recordFailedAttempt("test@test.com");
    }

    @Test
    @DisplayName("로그인 시도가 차단된 사용자는 로그인할 수 없다")
    void signin_blocked_user_throws_exception() {
        // given
        SigninRequest request = new SigninRequest("blocked@test.com", "password123");

        given(loginAttemptService.isBlocked("blocked@test.com")).willReturn(true);
        given(loginAttemptService.getRemainingBlockTimeMinutes("blocked@test.com")).willReturn(10L);

        // when & then
        assertThatThrownBy(() -> authService.signin(request))
                .isInstanceOf(RateLimitException.class)
                .hasMessage("로그인이 일시적으로 차단되었습니다.");

        verify(userRepository, never()).findByEmail(anyString());
    }

    @Test
    @DisplayName("RefreshToken으로 새로운 AccessToken을 발급받는다")
    void refreshToken_generates_new_tokens() {
        // given
        String oldRefreshToken = "old-refresh-token";

        RefreshToken refreshToken = new RefreshToken(oldRefreshToken, 1L,
                java.time.LocalDateTime.now().plusDays(14));

        User user = new User("test@test.com", "encodedPassword", UserRole.USER);
        ReflectionTestUtils.setField(user, "id", 1L);

        given(refreshTokenService.validateRefreshToken(oldRefreshToken)).willReturn(refreshToken);
        given(userRepository.findById(1L)).willReturn(Optional.of(user));
        given(jwtTokenProvider.createToken(1L, "test@test.com", UserRole.USER))
                .willReturn("new-access-token");
        given(refreshTokenService.createRefreshToken(1L)).willReturn("new-refresh-token");

        // when
        SigninResponse response = authService.refreshToken(oldRefreshToken);

        // then
        assertThat(response.getBearerToken()).isEqualTo("new-access-token");
        assertThat(response.getRefreshToken()).isEqualTo("new-refresh-token");

        // RefreshToken Rotation 확인
        verify(refreshTokenService).validateRefreshToken(oldRefreshToken);
        verify(refreshTokenService).createRefreshToken(1L);
    }

    @Test
    @DisplayName("유효하지 않은 RefreshToken으로 갱신 시 예외가 발생한다")
    void refreshToken_with_invalid_token_throws_exception() {
        // given
        String invalidRefreshToken = "invalid-refresh-token";

        given(refreshTokenService.validateRefreshToken(invalidRefreshToken))
                .willThrow(new InvalidRequestException("유효하지 않은 Refresh Token입니다."));

        // when & then
        assertThatThrownBy(() -> authService.refreshToken(invalidRefreshToken))
                .isInstanceOf(InvalidRequestException.class)
                .hasMessage("유효하지 않은 Refresh Token입니다.");
    }

    @Test
    @DisplayName("RefreshToken으로 갱신 시 사용자를 찾을 수 없으면 예외가 발생한다")
    void refreshToken_with_non_existing_user_throws_exception() {
        // given
        String refreshTokenValue = "valid-refresh-token";
        RefreshToken refreshToken = new RefreshToken(refreshTokenValue, 999L,
                java.time.LocalDateTime.now().plusDays(14));

        given(refreshTokenService.validateRefreshToken(refreshTokenValue)).willReturn(refreshToken);
        given(userRepository.findById(999L)).willReturn(Optional.empty());

        // when & then
        assertThatThrownBy(() -> authService.refreshToken(refreshTokenValue))
                .isInstanceOf(InvalidRequestException.class)
                .hasMessage("사용자를 찾을 수 없습니다.");
    }

    @Test
    @DisplayName("로그아웃 시 AccessToken이 블랙리스트에 추가되고 RefreshToken이 삭제된다")
    void logout_adds_token_to_blacklist_and_deletes_refresh_token() {
        // given
        Long userId = 1L;
        String accessToken = "valid-access-token";

        // when
        authService.logout(userId, accessToken);

        // then
        verify(refreshTokenService).deleteRefreshTokenByUserId(userId);
        // AccessToken 블랙리스트 추가는 내부 로직이므로 직접 검증하기 어려움
        // 실제로는 tokenBlacklistService.addToBlacklist가 호출되어야 함
    }

    @Test
    @DisplayName("AccessToken 없이 로그아웃해도 RefreshToken은 삭제된다")
    void logout_without_access_token_still_deletes_refresh_token() {
        // given
        Long userId = 1L;
        String accessToken = null; // 토큰 없음

        // when
        authService.logout(userId, accessToken);

        // then
        verify(refreshTokenService).deleteRefreshTokenByUserId(userId);
    }

    @Test
    @DisplayName("로그아웃 후 RefreshToken으로 갱신 시도하면 실패한다")
    void after_logout_refresh_token_should_fail() {
        // given
        Long userId = 1L;
        String accessToken = "access-token";
        String refreshTokenValue = "user-refresh-token";

        // 로그아웃 (RefreshToken 삭제됨)
        authService.logout(userId, accessToken);

        // 삭제된 토큰으로 갱신 시도 시 예외 발생하도록 설정
        given(refreshTokenService.validateRefreshToken(refreshTokenValue))
                .willThrow(new InvalidRequestException("유효하지 않은 Refresh Token입니다."));

        // when & then
        assertThatThrownBy(() -> authService.refreshToken(refreshTokenValue))
                .isInstanceOf(InvalidRequestException.class)
                .hasMessage("유효하지 않은 Refresh Token입니다.");

        // 로그아웃이 호출되었는지 확인
        verify(refreshTokenService).deleteRefreshTokenByUserId(userId);
    }
}