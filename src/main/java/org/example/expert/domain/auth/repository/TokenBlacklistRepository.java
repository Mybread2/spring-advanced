package org.example.expert.domain.auth.repository;

import org.example.expert.domain.auth.entity.TokenBlacklist;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;

public interface TokenBlacklistRepository extends JpaRepository<TokenBlacklist, String> {

    // JTI 로 블랙리스트된 토큰 존재 여부 확인 (만료되지 않은 것만)
    boolean existsByJtiAndExpiresAtAfter(String jti, LocalDateTime now);

    // 만료된 토큰들을 배치로 삭제
    @Modifying
    @Query("DELETE FROM TokenBlacklist t WHERE t.expiresAt < :expiredTime")
    void deleteExpiredTokens(@Param("expiredTime") LocalDateTime expiredTime);
}