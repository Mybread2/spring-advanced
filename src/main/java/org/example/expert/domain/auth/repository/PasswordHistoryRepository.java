package org.example.expert.domain.auth.repository;

import org.example.expert.domain.auth.entity.PasswordHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface PasswordHistoryRepository extends JpaRepository<PasswordHistory, Long> {

    // 비밀번호 재사용 방지를 위해 최근 N개 비밀번호 조회
    @Query("""
        SELECT ph FROM PasswordHistory ph
        WHERE ph.userId = :userId
        ORDER BY ph.createdAt DESC
        LIMIT :limit
        """)
    List<PasswordHistory> findRecentPasswordsByUserId(@Param("userId") Long userId,
                                                      @Param("limit") int limit);

    // 최근 N개를 제외한 나머지 삭제
    @Modifying
    @Query("""
        DELETE FROM PasswordHistory ph
        WHERE ph.userId = :userId
        AND ph.id NOT IN (
            SELECT ph2.id FROM PasswordHistory ph2
            WHERE ph2.userId = :userId 
            ORDER BY ph2.createdAt DESC 
            LIMIT :keepCount
        )
        """)
    void deleteOldPasswords(@Param("userId") Long userId, @Param("keepCount") int keepCount);

    // 특정 기간 내 비밀번호 변경 횟수
    @Query("""
        SELECT COUNT(ph) FROM PasswordHistory ph
        WHERE ph.userId = :userId
        AND ph.createdAt >= :startDate
        """)
    long countPasswordChangesSince(@Param("userId") Long userId,
                                   @Param("startDate") LocalDateTime startDate);

    // 사용자별 비밀번호 변경 통계
    @Query("""
        SELECT ph.userId, COUNT(ph), MIN(ph.createdAt), MAX(ph.createdAt)
        FROM PasswordHistory ph
        WHERE ph.createdAt >= :startDate
        GROUP BY ph.userId
        HAVING COUNT(ph) >= :minChangeCount
        ORDER BY COUNT(ph) DESC
        """)
    List<Object[]> findUsersWithFrequentPasswordChanges(@Param("startDate") LocalDateTime startDate,
                                                        @Param("minChangeCount") int minChangeCount);

    // 마지막 비밀번호 변경일 조회
    @Query("""
        SELECT MAX(ph.createdAt) FROM PasswordHistory ph
        WHERE ph.userId = :userId
        """)
    LocalDateTime findLastPasswordChangeDate(@Param("userId") Long userId);

    // 오래된 히스토리 전체 삭제
    @Modifying
    @Query("""
        DELETE FROM PasswordHistory ph
        WHERE ph.createdAt < :cutoffDate
        """)
    int deleteHistoriesOlderThan(@Param("cutoffDate") LocalDateTime cutoffDate);




    List<PasswordHistory> findByUserIdOrderByCreatedAtDesc(Long userId);

    boolean existsByUserIdAndPasswordHash(Long userId, String passwordHash);

    void deleteByUserId(Long userId);

}
