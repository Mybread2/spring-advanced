package org.example.expert.domain.auth.service;

import org.example.expert.config.security.JwtTokenProvider;
import org.example.expert.domain.auth.dto.request.SigninRequest;
import org.example.expert.domain.auth.dto.request.SignupRequest;
import org.example.expert.domain.auth.dto.response.SigninResponse;
import org.example.expert.domain.auth.dto.response.SignupResponse;
import org.example.expert.domain.auth.entity.RefreshToken;
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
    @DisplayName("회원가입이 정상 동작한다")
    void signup_works() {
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
    }

    @Test
    @DisplayName("로그인이 정상 동작한다")
    void signin_works() {
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
    }

    @Test
    @DisplayName("토큰 갱신이 정상 동작한다")
    void refreshToken_works() {
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
    }

    @Test
    @DisplayName("로그아웃이 정상 동작한다")
    void logout_works() {
        // given
        Long userId = 1L;
        String accessToken = "access-token";

        // when
        authService.logout(userId, accessToken);

        // then
        verify(tokenBlacklistService).addTokenToBlacklist(accessToken, userId);
        verify(refreshTokenService).deleteRefreshTokenByUserId(userId);
    }

    // 테스트 헬퍼 메서드
    private User createUser() {
        User user = new User("test@test.com", "encodedPassword", UserRole.USER);
        ReflectionTestUtils.setField(user, "id", 1L);
        return user;
    }
}