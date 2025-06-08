package org.example.expert.domain.common.exception;

import org.example.expert.domain.auth.exception.AuthException;
import org.example.expert.domain.auth.exception.RateLimitException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(InvalidRequestException.class)
    public ResponseEntity<Map<String, Object>> invalidRequestExceptionException(InvalidRequestException ex) {
        HttpStatus status = HttpStatus.BAD_REQUEST;
        return getErrorResponse("E1001", ex.getMessage(), status);
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuthException(AuthException ex) {
        HttpStatus status = HttpStatus.UNAUTHORIZED;
        return getErrorResponse("E2001", ex.getMessage(), status);
    }

    @ExceptionHandler(RateLimitException.class)
    public ResponseEntity<Map<String, Object>> handleRateLimitException(RateLimitException ex) {
        HttpStatus status = HttpStatus.TOO_MANY_REQUESTS;

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("code", "E2006");
        errorResponse.put("message", ex.getMessage());
        errorResponse.put("status", status.name());
        errorResponse.put("timestamp", LocalDateTime.now());
        errorResponse.put("remainingTimeMinutes", ex.getRemainingTimeMinutes());
        errorResponse.put("retryAfter", ex.getRemainingTimeMinutes() * 60);

        return new ResponseEntity<>(errorResponse, status);
    }

    @ExceptionHandler(ServerException.class)
    public ResponseEntity<Map<String, Object>> handleServerException(ServerException ex) {
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
        return getErrorResponse("E5000", ex.getMessage(), status);
    }

    public ResponseEntity<Map<String, Object>> getErrorResponse(String code, String message, HttpStatus status) {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("code", code);
        errorResponse.put("message", message);
        errorResponse.put("status", status.name());
        errorResponse.put("timestamp", LocalDateTime.now());

        return new ResponseEntity<>(errorResponse, status);
    }
}