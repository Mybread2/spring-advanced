package org.example.expert.config.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestPropertySource(properties = {
        "app.jwt.secret-key=dGVzdFNlY3JldEtleUZvckpXVEhhc2hpbmdBbGdvcml0aG1UaGF0SXNMb25nRW5vdWdoRm9yMjU2Qml0cw==",
        "app.jwt.expiration-time=7200000",
        "app.jwt.issuer=test-app",
        "app.jwt.bearer-prefix=Bearer "
})
class JwtPropertiesTest {

    @Autowired
    private JwtProperties jwtProperties;

    @Test
    @DisplayName("JwtProperties 빈이 정상적으로 주입되는지 확인")
    void jwtPropertiesBeanInjection() {
        assertThat(jwtProperties).isNotNull();
    }

    @Test
    @DisplayName("application.properties의 JWT 설정이 정상적으로 매핑되는지 확인")
    void jwtPropertiesMapping() {
        assertThat(jwtProperties.getSecretKey()).isEqualTo("dGVzdFNlY3JldEtleUZvckpXVEhhc2hpbmdBbGdvcml0aG1UaGF0SXNMb25nRW5vdWdoRm9yMjU2Qml0cw==");
        assertThat(jwtProperties.getExpirationTime()).isEqualTo(7200000L);
        assertThat(jwtProperties.getIssuer()).isEqualTo("test-app");
        assertThat(jwtProperties.getBearerPrefix()).isEqualTo("Bearer ");
    }

    @Test
    @DisplayName("기본값이 정상적으로 적용되는지 확인")
    void defaultValues() {
        JwtProperties defaultProperties = new JwtProperties();

        assertThat(defaultProperties.getExpirationTime()).isEqualTo(900_000L); // 15분
        assertThat(defaultProperties.getIssuer()).isEqualTo("expert-app");
        assertThat(defaultProperties.getBearerPrefix()).isEqualTo("Bearer ");
        assertThat(defaultProperties.getSecretKey()).isNull(); // 기본값 없음
    }
}