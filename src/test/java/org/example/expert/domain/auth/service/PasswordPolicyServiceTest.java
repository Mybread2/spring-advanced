package org.example.expert.domain.auth.service;

import org.example.expert.domain.auth.repository.PasswordHistoryRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Collections;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.BDDMockito.*;

@ExtendWith(MockitoExtension.class)
class PasswordPolicyServiceTest {

    @Mock
    private PasswordHistoryRepository passwordHistoryRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private PasswordPolicyService passwordPolicyService;

    @Test
    @DisplayName("비밀번호 재사용 검증 - 히스토리가 없는 경우 성공")
    void validatePasswordReuse_should_succeed_when_no_history() {
        // given
        Long userId = 1L;
        String newPassword = "FirstPassword123!";

        given(passwordHistoryRepository.findRecentPasswordsByUserId(userId, 5))
                .willReturn(Collections.emptyList());

        // when & then
        assertThatCode(() -> passwordPolicyService.validatePasswordReuse(newPassword, userId))
                .doesNotThrowAnyException();

        verify(passwordHistoryRepository).findRecentPasswordsByUserId(userId, 5);
        verify(passwordEncoder, never()).matches(anyString(), anyString());
    }

    @Test
    @DisplayName("비밀번호 히스토리 저장 - 정상 저장")
    void savePasswordHistory_should_save_successfully() {
        // given
        Long userId = 1L;
        String passwordHash = "encodedPasswordHash";

        // when
        passwordPolicyService.savePasswordHistory(userId, passwordHash);

        // then
        verify(passwordHistoryRepository).save(argThat(history ->
                history.getUserId().equals(userId) &&
                        history.getPasswordHash().equals(passwordHash)
        ));
        verify(passwordHistoryRepository).deleteOldPasswords(userId, 5);
    }

    @Test
    @DisplayName("비밀번호 만료 확인 - 만료된 경우")
    void isPasswordExpired_should_return_true_when_expired() {
        // given
        LocalDateTime expiredDate = LocalDateTime.now().minusDays(100); // 90일 기준으로 만료

        // when
        boolean result = passwordPolicyService.isPasswordExpired(expiredDate);

        // then
        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("비밀번호 만료 확인 - 만료되지 않은 경우")
    void isPasswordExpired_should_return_false_when_not_expired() {
        // given
        LocalDateTime recentDate = LocalDateTime.now().minusDays(30); // 아직 유효

        // when
        boolean result = passwordPolicyService.isPasswordExpired(recentDate);

        // then
        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("비밀번호 만료 확인 - null인 경우 만료로 처리")
    void isPasswordExpired_should_return_true_when_null() {
        // when
        boolean result = passwordPolicyService.isPasswordExpired(null);

        // then
        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("비밀번호 만료까지 남은 일수 계산")
    void getDaysUntilPasswordExpiry_should_calculate_correctly() {
        // given
        LocalDateTime passwordChangeDate = LocalDateTime.now().minusDays(60); // 60일 전 변경

        // when
        long daysLeft = passwordPolicyService.getDaysUntilPasswordExpiry(passwordChangeDate);

        // then
        assertThat(daysLeft).isEqualTo(30); // 90 - 60 = 30일 남음
    }

    @Test
    @DisplayName("비밀번호 만료까지 남은 일수 - 이미 만료된 경우 0 반환")
    void getDaysUntilPasswordExpiry_should_return_zero_when_expired() {
        // given
        LocalDateTime expiredDate = LocalDateTime.now().minusDays(100);

        // when
        long daysLeft = passwordPolicyService.getDaysUntilPasswordExpiry(expiredDate);

        // then
        assertThat(daysLeft).isEqualTo(0);
    }

    @Test
    @DisplayName("의심스러운 비밀번호 변경 패턴 감지 - 정상적인 경우")
    void isSuspiciousPasswordChangePattern_should_return_false_when_normal() {
        // given
        Long userId = 1L;

        given(passwordHistoryRepository.countPasswordChangesSince(eq(userId), any(LocalDateTime.class)))
                .willReturn(1L); // 1시간 내 1번 변경

        // when
        boolean result = passwordPolicyService.isSuspiciousPasswordChangePattern(userId);

        // then
        assertThat(result).isFalse();
        verify(passwordHistoryRepository).countPasswordChangesSince(eq(userId), any(LocalDateTime.class));
    }

    @Test
    @DisplayName("의심스러운 비밀번호 변경 패턴 감지 - 의심스러운 경우")
    void isSuspiciousPasswordChangePattern_should_return_true_when_suspicious() {
        // given
        Long userId = 1L;

        given(passwordHistoryRepository.countPasswordChangesSince(eq(userId), any(LocalDateTime.class)))
                .willReturn(5L); // 1시간 내 5번 변경 (의심스러움)

        // when
        boolean result = passwordPolicyService.isSuspiciousPasswordChangePattern(userId);

        // then
        assertThat(result).isTrue();
        verify(passwordHistoryRepository).countPasswordChangesSince(eq(userId), any(LocalDateTime.class));
    }
}