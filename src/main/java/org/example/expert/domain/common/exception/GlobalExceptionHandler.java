package org.example.expert.domain.common.exception;

import org.example.expert.domain.auth.exception.AuthException;
import org.example.expert.domain.auth.exception.RateLimitException;
import org.example.expert.domain.common.dto.ApiResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(InvalidRequestException.class)
    public ResponseEntity<ApiResponse<Void>> handleInvalidRequest(InvalidRequestException ex) {
        ApiResponse<Void> response = ApiResponse.failure(ex.getMessage(), "E1001");
        return ResponseEntity.badRequest().body(response);
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<ApiResponse<Void>> handleAuthException(AuthException ex) {
        ApiResponse<Void> response = ApiResponse.failure(ex.getMessage(), "E2001");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(RateLimitException.class)
    public ResponseEntity<ApiResponse<Map<String, Object>>> handleRateLimitException(RateLimitException ex) {
        Map<String, Object> data = new HashMap<>();
        data.put("remainingTimeMinutes", ex.getRemainingTimeMinutes());
        data.put("retryAfter", ex.getRemainingTimeMinutes() * 60);

        ApiResponse<Map<String, Object>> response = ApiResponse.failure(ex.getMessage(), "E2006");
        // data 필드에 추가 정보 포함
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(response);
    }

    @ExceptionHandler(ServerException.class)
    public ResponseEntity<ApiResponse<Void>> handleServerException(ServerException ex) {
        ApiResponse<Void> response = ApiResponse.failure(ex.getMessage(), "E5000");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }

    // Validation 에러 처리
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> handleValidationException(
            MethodArgumentNotValidException ex) {

        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        ApiResponse<Map<String, String>> response = ApiResponse.failure("입력값이 올바르지 않습니다.", "E1002");
        return ResponseEntity.badRequest().body(response);
    }

    // 기타 예외 처리
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleGenericException() {
        ApiResponse<Void> response = ApiResponse.failure("서버 내부 오류가 발생했습니다.", "E5000");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }
}