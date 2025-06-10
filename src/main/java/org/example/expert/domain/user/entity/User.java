package org.example.expert.domain.user.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.example.expert.domain.common.entity.Timestamped;
import org.example.expert.domain.user.enums.UserRole;

import java.time.LocalDateTime;

@Getter
@Entity
@NoArgsConstructor
@Table(name = "users")
public class User extends Timestamped {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String email;

    private String password;

    @Enumerated(EnumType.STRING)
    private UserRole userRole;

    @Column(name = "last_password_change")
    private LocalDateTime lastPasswordChange;

    public User(String email, String password, UserRole userRole) {
        this.email = email;
        this.password = password;
        this.userRole = userRole;
        this.lastPasswordChange = LocalDateTime.now();
    }

    public void changePassword(String password) {
        this.password = password;
        this.lastPasswordChange = LocalDateTime.now(); // 🔥 추가
    }

    public void updateRole(UserRole userRole) {
        this.userRole = userRole;
    }
}
