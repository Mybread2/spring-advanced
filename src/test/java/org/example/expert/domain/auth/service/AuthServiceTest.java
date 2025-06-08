package org.example.expert.domain.auth.service;

import org.example.expert.config.security.JwtTokenProvider;
import org.example.expert.domain.auth.dto.request.SigninRequest;
import org.example.expert.domain.auth.dto.request.SignupRequest;
import org.example.expert.domain.auth.dto.response.SigninResponse;
import org.example.expert.domain.auth.dto.response.SignupResponse;
import org.example.expert.domain.auth.entity.RefreshToken;
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
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

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
                .willReturn("Bearer access-token");
        given(refreshTokenService.createRefreshToken(1L)).willReturn("refresh-token-uuid");

        // when
        SignupResponse response = authService.signup(request);

        // then
        assertThat(response.getBearerToken()).isEqualTo("Bearer access-token");
        assertThat(response.getRefreshToken()).isEqualTo("refresh-token-uuid");

        verify(refreshTokenService).createRefreshToken(1L);
    }

    @Test
    @DisplayName("로그인 시 AccessToken과 RefreshToken이 모두 생성된다")
    void signin_creates_both_tokens() {
        // given
        SigninRequest request = new SigninRequest("test@test.com", "password123");

        User user = new User("test@test.com", "encodedPassword", UserRole.USER);
        ReflectionTestUtils.setField(user, "id", 1L);

        given(userRepository.findByEmail("test@test.com")).willReturn(Optional.of(user));
        given(passwordEncoder.matches("password123", "encodedPassword")).willReturn(true);
        given(jwtTokenProvider.createToken(1L, "test@test.com", UserRole.USER))
                .willReturn("Bearer access-token");
        given(refreshTokenService.createRefreshToken(1L)).willReturn("refresh-token-uuid");

        // when
        SigninResponse response = authService.signin(request);

        // then
        assertThat(response.getBearerToken()).isEqualTo("Bearer access-token");
        assertThat(response.getRefreshToken()).isEqualTo("refresh-token-uuid");

        verify(refreshTokenService).createRefreshToken(1L);
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
                .willReturn("Bearer new-access-token");
        given(refreshTokenService.createRefreshToken(1L)).willReturn("new-refresh-token");

        // when
        SigninResponse response = authService.refreshToken(oldRefreshToken);

        // then
        assertThat(response.getBearerToken()).isEqualTo("Bearer new-access-token");
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
    @DisplayName("로그아웃 시 사용자의 RefreshToken이 삭제된다")
    void logout_deletes_user_refresh_tokens() {
        // given
        Long userId = 1L;

        // when
        authService.logout(userId);

        // then
        verify(refreshTokenService).deleteRefreshTokenByUserId(userId);
    }

    @Test
    @DisplayName("로그아웃 후 RefreshToken으로 갱신 시도하면 실패한다")
    void after_logout_refresh_token_should_fail() {
        // given
        Long userId = 1L;
        String refreshToken = "user-refresh-token";

        // 로그아웃 (RefreshToken 삭제됨)
        authService.logout(userId);

        // 삭제된 토큰으로 갱신 시도 시 예외 발생하도록 설정
        given(refreshTokenService.validateRefreshToken(refreshToken))
                .willThrow(new InvalidRequestException("유효하지 않은 Refresh Token입니다."));

        // when & then
        assertThatThrownBy(() -> authService.refreshToken(refreshToken))
                .isInstanceOf(InvalidRequestException.class)
                .hasMessage("유효하지 않은 Refresh Token입니다.");

        // 로그아웃이 호출되었는지 확인
        verify(refreshTokenService).deleteRefreshTokenByUserId(userId);
    }
}