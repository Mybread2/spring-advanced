package org.example.expert.domain.auth.repository;

import org.example.expert.domain.auth.entity.TokenBlacklist;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;

public interface TokenBlacklistRepository extends JpaRepository<TokenBlacklist, String> {

    // JTI 로 블랙리스트된 토큰 존재 여부 확인 (만료되지 않은 것만)
    @Query("SELECT COUNT(t) > 0 FROM TokenBlacklist t WHERE t.jti = :jti AND t.expiresAt > :now")
    boolean existsByJtiAndNotExpired(@Param("jti") String jti, @Param("now") LocalDateTime now);

    // 사용자의 모든 블랙리스트 토큰 조회 (관리용)
    @Query("SELECT t FROM TokenBlacklist t WHERE t.userId = :userId AND t.expiresAt > :now")
    java.util.List<TokenBlacklist> findActiveTokensByUserId(@Param("userId") Long userId, @Param("now") LocalDateTime now);

    // 만료된 토큰들을 배치로 삭제 @return 삭제된 토큰 개수
    @Modifying
    @Query("DELETE FROM TokenBlacklist t WHERE t.expiresAt < :expiredTime")
    int deleteExpiredTokens(@Param("expiredTime") LocalDateTime expiredTime);

    // 특정 시간 이후의 활성 토큰 개수 조회 (모니터링용)
    @Query("SELECT COUNT(t) FROM TokenBlacklist t WHERE t.expiresAt > :now")
    long countActiveTokens(@Param("now") LocalDateTime now);

    // 사용자별 활성 블랙리스트 토큰 개수
    @Query("SELECT COUNT(t) FROM TokenBlacklist t WHERE t.userId = :userId AND t.expiresAt > :now")
    long countActiveTokensByUserId(@Param("userId") Long userId, @Param("now") LocalDateTime now);
}