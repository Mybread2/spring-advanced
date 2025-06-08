package org.example.expert.domain.common.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse<T> {

    private final boolean success;
    private final String message;
    private final T data;
    private final LocalDateTime timestamp;
    private final String code;

    // 성공 응답 생성자
    private ApiResponse(T data, String message) {
        this.success = true;
        this.message = message;
        this.data = data;
        this.timestamp = LocalDateTime.now();
        this.code = null;
    }

    // 실패 응답 생성자
    private ApiResponse(String message, String code) {
        this.success = false;
        this.message = message;
        this.data = null;
        this.timestamp = LocalDateTime.now();
        this.code = code;
    }

    // 성공 - 데이터 있음
    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>(data, "요청이 성공적으로 처리되었습니다.");
    }

    // 성공 - 데이터 있음 + 커스텀 메시지
    public static <T> ApiResponse<T> success(T data, String message) {
        return new ApiResponse<>(data, message);
    }

    // 성공 - 데이터 없음 (예: 삭제, 업데이트)
    public static <Void> ApiResponse<Void> success() {
        return new ApiResponse<>(null, "요청이 성공적으로 처리되었습니다.");
    }

    // 성공 - 데이터 없음 + 커스텀 메시지
    public static <Void> ApiResponse<Void> success(String message) {
        return new ApiResponse<>(null, message);
    }

    // 실패
    public static <T> ApiResponse<T> failure(String message, String code) {
        return new ApiResponse<>(message, code);
    }
}