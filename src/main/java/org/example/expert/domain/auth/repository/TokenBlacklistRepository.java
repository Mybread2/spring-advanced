package org.example.expert.domain.auth.repository;

import org.example.expert.domain.auth.entity.TokenBlacklist;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;

public interface TokenBlacklistRepository extends JpaRepository<TokenBlacklist, String> {

    // 기존 메서드들...
    boolean existsByJtiAndExpiresAtAfter(String jti, LocalDateTime now);

    @Modifying
    @Query("DELETE FROM TokenBlacklist t WHERE t.expiresAt < :expiredTime")
    void deleteExpiredTokens(@Param("expiredTime") LocalDateTime expiredTime);
}