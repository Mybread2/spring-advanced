package org.example.expert.domain.auth.service;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.expert.config.security.JwtTokenProvider;
import org.example.expert.domain.auth.dto.request.SigninRequest;
import org.example.expert.domain.auth.dto.request.SignupRequest;
import org.example.expert.domain.auth.dto.response.SigninResponse;
import org.example.expert.domain.auth.dto.response.SignupResponse;
import org.example.expert.domain.auth.entity.RefreshToken;
import org.example.expert.domain.auth.exception.AuthException;
import org.example.expert.domain.common.exception.InvalidRequestException;
import org.example.expert.domain.user.entity.User;
import org.example.expert.domain.user.enums.UserRole;
import org.example.expert.domain.user.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistService tokenBlacklistService;

    @Transactional
    public SignupResponse signup(SignupRequest signupRequest) {

        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            throw new InvalidRequestException("이미 존재하는 이메일입니다.");
        }

        UserRole userRole = UserRole.of(signupRequest.getUserRole());

        String encodedPassword = passwordEncoder.encode(signupRequest.getPassword());

        User newUser = new User(
                signupRequest.getEmail(),
                encodedPassword,
                userRole
        );
        User savedUser = userRepository.save(newUser);

        String bearerToken = jwtTokenProvider.createToken(savedUser.getId(), savedUser.getEmail(), userRole);
        String refreshToken = refreshTokenService.createRefreshToken(savedUser.getId());

        return new SignupResponse(bearerToken, refreshToken);
    }

    @Transactional
    public SigninResponse signin(SigninRequest signinRequest) {

        User user = userRepository.findByEmail(signinRequest.getEmail())
                .orElseThrow(() -> new AuthException("이메일 또는 비밀번호가 올바르지 않습니다."));

        if (!passwordEncoder.matches(signinRequest.getPassword(), user.getPassword())) {
            throw new AuthException("이메일 또는 비밀번호가 올바르지 않습니다.");
        }

        String accessToken= jwtTokenProvider.createToken(user.getId(), user.getEmail(), user.getUserRole());
        String refreshToken = refreshTokenService.createRefreshToken(user.getId());

        return new SigninResponse(accessToken, refreshToken);
    }

    @Transactional
    public SigninResponse refreshToken(String refreshTokenValue) {
        // 1. RefreshToken 유효성 검증
        RefreshToken refreshToken = refreshTokenService.validateRefreshToken(refreshTokenValue);

        // 2. 사용자 정보 조회
        User user = userRepository.findById(refreshToken.getUserId())
                .orElseThrow(() -> new InvalidRequestException("사용자를 찾을 수 없습니다."));

        // 3. 새 AccessToken 생성
        String newAccessToken = jwtTokenProvider.createToken(
                user.getId(),
                user.getEmail(),
                user.getUserRole()
        );

        // 4. 새 RefreshToken 생성 (Refresh Token Rotation)
        String newRefreshToken = refreshTokenService.createRefreshToken(user.getId());

        return new SigninResponse(newAccessToken, newRefreshToken);
    }

    @Transactional
    public void logout(Long userId) {
        // 사용자의 모든 RefreshToken 삭제
        refreshTokenService.deleteRefreshTokenByUserId(userId);
    }

    @Transactional
    public void logout(Long userId, String accessToken) {
        try {
            // 1. Access Token 블랙리스트 추가 (토큰이 있는 경우만)
            if (StringUtils.hasText(accessToken)) {
                addAccessTokenToBlacklist(accessToken, userId);
            }

            // 2. Refresh Token 삭제 (항상 실행)
            refreshTokenService.deleteRefreshTokenByUserId(userId);

        } catch (Exception e) {
            log.error("로그아웃 처리 중 오류 발생: userId={}", userId, e);

            // 실패해도 RefreshToken은 삭제 (보안상 중요)
            refreshTokenService.deleteRefreshTokenByUserId(userId);

            throw new RuntimeException("로그아웃 처리 중 오류가 발생했습니다.", e);
        }
    }

    // Access Token을 블랙리스트에 추가하는 내부 메서드
    private void addAccessTokenToBlacklist(String accessToken, Long userId) {
        try {
            Claims claims = jwtTokenProvider.parseToken(accessToken);
            String jti = claims.getId();

            if (StringUtils.hasText(jti)) {
                LocalDateTime expiresAt = jwtTokenProvider.getExpirationTime(claims);

                // 아직 만료되지 않은 토큰만 블랙리스트에 추가
                if (expiresAt.isAfter(LocalDateTime.now())) {
                    tokenBlacklistService.addToBlacklist(jti, userId, expiresAt);
                }
            }

        } catch (Exception e) {
            // 블랙리스트 추가 실패해도 로그아웃은 계속 진행
            log.warn("Access Token 블랙리스트 추가 실패: userId={}", userId);
        }
    }
}
