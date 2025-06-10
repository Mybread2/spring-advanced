# SPRING ADVANCED

# TODO Expert 

> **높은 보안을 갖춘 할일 관리 시스템**  
> Spring Boot 3.x + JWT + Redis 기반의 프로덕션 레디 애플리케이션

## 프로젝트 개요

**인증/인가 시스템**에 중점을 두어 실제 서비스에서 바로 사용할 수 있는 수준으로 구현하기 위해 노력했습니다.

- **높은 보안**: 실무에서 요구되는 보안 기능 구현
- **고성능**: Redis 캐싱과 최적화된 쿼리로 빠른 응답 속도
- **견고함**: 포괄적인 예외 처리와 검증 로직

## 주요 기능

### 고급 인증/인가 시스템

#### JWT 기반 이중 토큰 시스템
- **Access Token**: 짧은 만료시간(15분)으로 보안 강화
- **Refresh Token**: 자동 갱신으로 사용자 편의성 제공
- **토큰 블랙리스트**: 로그아웃된 토큰 무효화 (Redis + DB)

```http
POST /auth/signin
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}

# Response
{
  "success": true,
  "data": {
    "bearerToken": "eyJhbGciOiJIUzI1NiJ9...",
    "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
  },
  "message": "로그인이 완료되었습니다."
}
```

#### 무차별 대입 공격 방어
- **레이트 리미팅**: 5회 실패 시 15분 차단
- **자동 복구**: 차단 시간 만료 시 자동 해제

#### 고급 비밀번호 정책
- **복잡도 검증**: 대소문자, 숫자, 특수문자 필수 포함
- **재사용 방지**: 최근 5개 비밀번호 재사용 금지
- **변경 패턴 분석**: 1시간 내 3회 이상 변경 시 의심 활동 감지
- **만료 정책**: 90일마다 비밀번호 변경 권장

### 아키텍처 특징

#### 캐싱 전략
```java
@Cacheable(value = "todoLists", key = "'page_' + #page + '_size_' + #size")
public Page<TodoResponse> getTodos(int page, int size) {
    // Redis를 통한 빠른 응답
}
```

#### AOP 기반 감사 로깅
```java
@AdminAudit(description = "사용자 권한 변경")
@PatchMapping("/admin/users/{userId}")
public void changeUserRole(@PathVariable long userId, 
                          @RequestBody UserRoleChangeRequest request) {
    // 모든 관리자 행위 자동 로깅
}
```

#### 트랜잭션 최적화
```java
@Transactional(readOnly = true)  // 읽기 전용 최적화
@Transactional                   // 쓰기 작업 격리
```

### 보안 기능

#### 다층 방어 시스템
1. **입력 검증**: Bean Validation으로 데이터 무결성 보장
2. **인증 필터**: JWT 토큰 검증 및 사용자 컨텍스트 설정
3. **인가 제어**: Role 기반 엔드포인트 접근 제어
4. **출력 보호**: 민감 정보 마스킹 및 안전한 응답

#### 예외 처리 표준화
```java
// 일관된 API 응답 형식
{
  "success": false,
  "message": "로그인이 일시적으로 차단되었습니다.",
  "code": "E2006",
  "timestamp": "2025-06-10T15:30:45"
}
```

## 시작하기

### 사전 요구사항
- Java 17+
- Redis Server
- MySQL 8.0+ (또는 H2 for development)

### 설치 및 실행

**환경 변수 설정**
```bash
# application-local.properties 생성
JWT_SECRET_KEY=your-256-bit-secret-key-here
REDIS_HOST=localhost
REDIS_PORT=6379
DATABASE_URL=jdbc:mysql://localhost:3306/todo_expert
```

## API 문서

### 인증 API

#### 회원가입
```http
POST /auth/signup
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "userRole": "USER"
}
```

#### 토큰 갱신
```http
POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
}
```

#### 안전한 로그아웃
```http
POST /auth/logout
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
```

### 할일 관리 API

#### 할일 목록 조회 (캐싱 적용)
```http
GET /todos?page=1&size=10
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
```

#### 할일 등록
```http
POST /todos
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
Content-Type: application/json

{
  "title": "프로젝트 완료하기",
  "contents": "모든 기능 구현 및 테스트 완료"
}
```

### 관리자 API (감사 로깅 적용)

#### 사용자 권한 변경
```http
PATCH /admin/users/{userId}
Authorization: Bearer admin-jwt-token
Content-Type: application/json

{
  "role": "ADMIN"
}
```

## 🔧 기술 스택

### Backend Core
- **Spring Boot 3.3.3**: 최신 프레임워크
- **Spring Security 6**: 최신 보안 아키텍처
- **Spring Data JPA**: ORM 및 쿼리 최적화
- **MySQL**: 프로덕션 데이터베이스

### 캐싱 & 성능
- **Redis**: 분산 캐싱 및 세션 스토어
- **Spring Cache**: 선언적 캐싱
- **JPA Entity Graph**: N+1 문제 해결

### 보안 & 인증
- **JWT (jjwt 0.11.5)**: 최신 JWT 라이브러리
- **BCrypt**: 강력한 해시 알고리즘
- **Bean Validation**: 입력 데이터 검증

### 개발 도구
- **Lombok**: 코드 간소화
- **AOP**: 횡단 관심사 분리

## 아키텍처

### 계층형 아키텍처
```
┌─────────────────────────────────────┐
│           Presentation Layer        │  ← Controller, Exception Handler
├─────────────────────────────────────┤
│             Service Layer           │  ← Business Logic, Transaction
├─────────────────────────────────────┤
│           Repository Layer          │  ← Data Access, JPA Repository
├─────────────────────────────────────┤
│            Database Layer           │  ← MySQL, Redis
└─────────────────────────────────────┘
```

### 보안 아키텍처
```
┌─────────────┐     ┌─────────────┐    ┌─────────────┐
│   Client    │───▶│ JWT Filter  │───▶│ Controller  │
└─────────────┘     └─────────────┘    └─────────────┘
                          │                    │
                          ▼                    ▼
                   ┌─────────────┐    ┌─────────────┐
                   │Rate Limiter │    │AOP Logging  │
                   └─────────────┘    └─────────────┘
                          │                    │
                          ▼                    ▼
                   ┌─────────────┐    ┌─────────────┐
                   │   Redis     │    │  Database   │
                   └─────────────┘    └─────────────┘
```

## 테스트

### 주요 테스트 케이스
- **JWT 토큰 생성/검증**: 토큰 라이프사이클 테스트
- **레이트 리미팅**: 무차별 대입 공격 시뮬레이션
- **비밀번호 정책**: 복잡도 및 재사용 방지 검증
- **블랙리스트**: 토큰 무효화 및 캐싱 동작

## 보안 고려사항

### 프로덕션 배포 체크리스트
- [ ] JWT 비밀키를 환경변수로 설정
- [ ] HTTPS 적용
- [ ] Redis AUTH 설정
- [ ] 데이터베이스 접근 제한

### 보안 모니터링
- **로그인 실패 추적**: 의심스러운 활동 감지
- **관리자 행위 로깅**: 모든 관리 작업 감사
- **토큰 블랙리스트**: 무효화된 토큰 사용 시도 차단

## 성능 최적화

### 캐싱 전략
- **Application Level**: Spring Cache + Redis
- **Database Level**: JPA 2차 캐시
- **Query Level**: Entity Graph로 N+1 해결

### 메모리 관리
- **Connection Pool**: HikariCP 최적화
- **JVM Tuning**: G1GC 사용 권장
- **Redis Memory**: TTL 기반 자동 정리
---
