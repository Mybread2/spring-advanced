package org.example.expert.domain.auth.dto.response;

import lombok.Getter;

@Getter
public class SignupResponse {

    private final String bearerToken;
    private final String refreshToken;

    public SignupResponse(String bearerToken, String refreshToken) {
        this.bearerToken = bearerToken;
        this.refreshToken = refreshToken;
    }
}
