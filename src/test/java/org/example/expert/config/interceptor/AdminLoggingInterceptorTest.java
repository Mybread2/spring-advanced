package org.example.expert.config.interceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.expert.domain.auth.exception.AuthException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
class AdminLoggingInterceptorTest {

    @InjectMocks
    private AdminLoggingInterceptor interceptor;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Test
    @DisplayName("어드민 사용자는 통과")
    void admin_user_pass() {
        // Given
        given(request.getAttribute("userRole")).willReturn("ADMIN");
        given(request.getAttribute("userId")).willReturn(1L);
        given(request.getRequestURI()).willReturn("/admin/test");

        // When
        boolean result = interceptor.preHandle(request, response, new Object());

        // Then
        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("일반 사용자는 차단")
    void user_blocked() {
        // Given
        given(request.getAttribute("userRole")).willReturn("USER");
        given(request.getAttribute("userId")).willReturn(2L);
        given(request.getRequestURI()).willReturn("/admin/test");

        // When & Then
        assertThatThrownBy(() -> interceptor.preHandle(request, response, new Object()))
                .isInstanceOf(AuthException.class)
                .hasMessage("관리자 권한이 필요합니다.");
    }
}
