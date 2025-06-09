package org.example.expert.domain.auth.service;

import lombok.RequiredArgsConstructor;
import org.example.expert.domain.auth.entity.RefreshToken;
import org.example.expert.domain.auth.repository.RefreshTokenRepository;
import org.example.expert.domain.common.exception.InvalidRequestException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    @Transactional
    public String createRefreshToken(Long userId) {

        refreshTokenRepository.deleteByUserId(userId);

        String token = UUID.randomUUID().toString();
        LocalDateTime expiresAt = LocalDateTime.now().plusDays(14);

        RefreshToken refreshToken = new RefreshToken(token, userId, expiresAt);
        refreshTokenRepository.save(refreshToken);

        return token;
    }

    @Transactional(readOnly = true)
    public RefreshToken validateRefreshToken(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new InvalidRequestException("유효하지 않은 Refresh Token 입니다."));

        if (refreshToken.isExpired()) {
            throw new InvalidRequestException("만료된 Refresh Token 입니다.");
        }

        return refreshToken;
    }

    @Transactional
    public void deleteRefreshTokenByUserId(Long userId) { // ← 이 메서드 추가
        refreshTokenRepository.deleteByUserId(userId);
    }
}