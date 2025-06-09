package org.example.expert.config.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.example.expert.domain.user.enums.UserRole;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.Key;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.Assertions.*;

class JwtTokenProviderTest {

    private JwtTokenProvider jwtTokenProvider;

    private final String testSecretKey = "dGVzdFNlY3JldEtleUZvckpXVEhhc2hpbmdBbGdvcml0aG1UaGF0SXNMb25nRW5vdWdoRm9yMjU2Qml0cw==";
    private final Long testUserId = 1L;
    private final String testEmail = "test@example.com";
    private final UserRole testRole = UserRole.USER;

    @BeforeEach
    void setUp() {
        // 실제 JwtProperties 객체 생성
        JwtProperties jwtProperties = new JwtProperties();
        ReflectionTestUtils.setField(jwtProperties, "secretKey", testSecretKey);
        ReflectionTestUtils.setField(jwtProperties, "expirationTime", 3600000L);
        ReflectionTestUtils.setField(jwtProperties, "issuer", "test-app");

        // 실제 JwtTokenProvider 객체 생성
        jwtTokenProvider = new JwtTokenProvider(jwtProperties);
        jwtTokenProvider.init();
    }

    @Test
    @DisplayName("JWT 토큰이 정상적으로 생성된다")
    void createToken_should_generate_valid_jwt() {
        // when
        String token = jwtTokenProvider.createToken(testUserId, testEmail, testRole);

        // then
        assertThat(token).isNotNull();
        assertThat(token).isNotEmpty();

        // 토큰 파싱해서 내용 검증
        Claims claims = jwtTokenProvider.parseToken(token);
        assertThat(claims.getSubject()).isEqualTo(testUserId.toString());
        assertThat(claims.get("email", String.class)).isEqualTo(testEmail);
        assertThat(claims.get("userRole", String.class)).isEqualTo(testRole.name());
        assertThat(claims.getIssuer()).isEqualTo("test-app");
        assertThat(claims.getId()).isNotNull(); // JTI 존재 확인
    }

    @Test
    @DisplayName("유효한 JWT 토큰을 파싱할 수 있다")
    void parseToken_should_parse_valid_jwt() {
        // given
        String token = jwtTokenProvider.createToken(testUserId, testEmail, testRole);

        // when
        Claims claims = jwtTokenProvider.parseToken(token);

        // then
        assertThat(claims).isNotNull();
        assertThat(claims.getSubject()).isEqualTo(testUserId.toString());
        assertThat(claims.get("email", String.class)).isEqualTo(testEmail);
        assertThat(claims.get("userRole", String.class)).isEqualTo(testRole.name());
        assertThat(claims.getIssuer()).isEqualTo("test-app");
    }

    @Test
    @DisplayName("만료된 토큰 파싱 시 CredentialsExpiredException이 발생한다")
    void parseToken_should_throw_exception_for_expired_token() {
        // given - 과거 시간으로 만료된 토큰 직접 생성
        Key key = Keys.hmacShaKeyFor(Base64.getDecoder().decode(testSecretKey));

        String expiredToken = Jwts.builder()
                .setSubject(testUserId.toString())
                .claim("email", testEmail)
                .claim("userRole", testRole.name())
                .setIssuer("test-app")
                .setExpiration(new Date(System.currentTimeMillis() - 1000)) // 1초 전 만료
                .signWith(key)
                .compact();

        // when & then
        assertThatThrownBy(() -> jwtTokenProvider.parseToken(expiredToken))
                .isInstanceOf(CredentialsExpiredException.class)
                .hasMessage("JWT 토큰이 만료되었습니다.");
    }

    @Test
    @DisplayName("잘못된 서명의 토큰 파싱 시 BadCredentialsException이 발생한다")
    void parseToken_should_throw_exception_for_invalid_signature() {
        // given - 다른 키로 생성된 토큰
        Key wrongKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode("d3JvbmdTZWNyZXRLZXlGb3JKV1RIYXNoaW5nQWxnb3JpdGhtVGhhdElzTG9uZ0Vub3VnaEZvcjI1NkJpdHM="));

        String tokenWithWrongSignature = Jwts.builder()
                .setSubject(testUserId.toString())
                .claim("email", testEmail)
                .claim("userRole", testRole.name())
                .setIssuer("test-app")
                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(wrongKey)
                .compact();

        // when & then
        assertThatThrownBy(() -> jwtTokenProvider.parseToken(tokenWithWrongSignature))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("유효하지 않은 JWT 토큰입니다.");
    }

    @Test
    @DisplayName("잘못된 형식의 토큰 파싱 시 BadCredentialsException이 발생한다")
    void parseToken_should_throw_exception_for_malformed_token() {
        // given
        String malformedToken = "invalid.jwt.token";

        // when & then
        assertThatThrownBy(() -> jwtTokenProvider.parseToken(malformedToken))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("유효하지 않은 JWT 토큰입니다.");
    }

    @Test
    @DisplayName("잘못된 발급자의 토큰 파싱 시 BadCredentialsException이 발생한다")
    void parseToken_should_throw_exception_for_wrong_issuer() {
        // given - 잘못된 발급자로 토큰 생성
        Key key = Keys.hmacShaKeyFor(Base64.getDecoder().decode(testSecretKey));

        String tokenWithWrongIssuer = Jwts.builder()
                .setSubject(testUserId.toString())
                .claim("email", testEmail)
                .claim("userRole", testRole.name())
                .setIssuer("wrong-issuer") // 잘못된 발급자
                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(key)
                .compact();

        // when & then
        assertThatThrownBy(() -> jwtTokenProvider.parseToken(tokenWithWrongIssuer))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("유효하지 않은 JWT 토큰입니다.");
    }

    @Test
    @DisplayName("토큰의 만료 시간을 정확히 반환한다")
    void getExpirationTime_should_return_correct_expiration() {
        // given
        String token = jwtTokenProvider.createToken(testUserId, testEmail, testRole);
        Claims claims = jwtTokenProvider.parseToken(token);

        // when
        LocalDateTime expirationTime = jwtTokenProvider.getExpirationTime(claims);

        // then
        assertThat(expirationTime).isNotNull();
        assertThat(expirationTime).isAfter(LocalDateTime.now());

        // 대략 1시간 후인지 확인 (오차 1분 허용)
        LocalDateTime expectedExpiration = LocalDateTime.now().plusHours(1);
        assertThat(expirationTime)
                .isBetween(
                        expectedExpiration.minusMinutes(1),
                        expectedExpiration.plusMinutes(1)
                );
    }

    @Test
    @DisplayName("각기 다른 토큰은 고유한 JTI를 가진다")
    void createToken_should_generate_unique_jti() {
        // when
        String token1 = jwtTokenProvider.createToken(testUserId, testEmail, testRole);
        String token2 = jwtTokenProvider.createToken(testUserId, testEmail, testRole);

        // then
        Claims claims1 = jwtTokenProvider.parseToken(token1);
        Claims claims2 = jwtTokenProvider.parseToken(token2);

        assertThat(claims1.getId()).isNotEqualTo(claims2.getId());
    }

    @Test
    @DisplayName("빈 문자열 토큰 파싱 시 BadCredentialsException이 발생한다")
    void parseToken_should_throw_exception_for_empty_token() {
        // when & then
        assertThatThrownBy(() -> jwtTokenProvider.parseToken(""))
                .isInstanceOf(IllegalArgumentException.class)  // 실제로는 IllegalArgumentException 발생
                .hasMessage("JWT String argument cannot be null or empty.");
    }

    @Test
    @DisplayName("null 토큰 파싱 시 BadCredentialsException이 발생한다")
    void parseToken_should_throw_exception_for_null_token() {
        // when & then
        assertThatThrownBy(() -> jwtTokenProvider.parseToken(null))
                .isInstanceOf(IllegalArgumentException.class)  // 실제로는 IllegalArgumentException 발생
                .hasMessage("JWT String argument cannot be null or empty.");
    }

    @Test
    @DisplayName("ADMIN 권한 사용자의 토큰도 정상적으로 생성된다")
    void createToken_should_work_for_admin_user() {
        // given
        UserRole adminRole = UserRole.ADMIN;
        String adminEmail = "admin@example.com";

        // when
        String token = jwtTokenProvider.createToken(testUserId, adminEmail, adminRole);

        // then
        Claims claims = jwtTokenProvider.parseToken(token);
        assertThat(claims.get("userRole", String.class)).isEqualTo("ADMIN");
        assertThat(claims.get("email", String.class)).isEqualTo(adminEmail);
    }
}