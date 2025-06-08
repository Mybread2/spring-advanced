package org.example.expert.domain.auth.exception;

import lombok.Getter;

@Getter
public class RateLimitException extends RuntimeException {

    private final long remainingTimeMinutes;

    public RateLimitException(String message, long remainingTimeMinutes) {
        super(message);
        this.remainingTimeMinutes = remainingTimeMinutes;
    }

}