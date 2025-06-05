package org.example.expert.config.aop;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.reflect.MethodSignature;
import org.example.expert.config.annotation.AdminAudit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class AdminApiLoggingAspectTest {

    @InjectMocks
    private AdminApiLoggingAspect aspect;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private ProceedingJoinPoint joinPoint;

    @Test
    @DisplayName("AOP 로깅이 정상 동작")
    void aop_logging_works() throws Throwable {
        // Given
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute("userId", 1L);
        request.setMethod("DELETE");
        request.setRequestURI("/admin/comments/1");

        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        MethodSignature signature = mock(MethodSignature.class);
        Method method = this.getClass().getMethod("testMethod");
        given(signature.getMethod()).willReturn(method);
        given(joinPoint.getSignature()).willReturn(signature);
        given(joinPoint.getArgs()).willReturn(new Object[]{1L});
        given(joinPoint.proceed()).willReturn(null);
        given(objectMapper.writeValueAsString(any())).willReturn("[1]");

        // When
        Object result = aspect.logAdminApi(joinPoint);

        // Then
        assertThat(result).isNull();
        verify(joinPoint).proceed();
    }

    @Test
    @AdminAudit(description = "테스트")
    public void testMethod() {
    }
}