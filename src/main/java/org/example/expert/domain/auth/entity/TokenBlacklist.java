package org.example.expert.domain.auth.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "token_blacklist",
        indexes = {
                @Index(name = "idx_jti", columnList = "jti"),
                @Index(name = "idx_expires_at", columnList = "expiresAt")
        })
@Getter
@NoArgsConstructor
public class TokenBlacklist {

    @Id
    @Column(length = 36)
    private String jti;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    public TokenBlacklist(String jti, Long userId, LocalDateTime expiresAt) {
        this.jti = jti;
        this.userId = userId;
        this.expiresAt = expiresAt;
    }
}