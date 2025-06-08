package org.example.expert.domain.auth.dto.response;

import lombok.Getter;

@Getter
public class SigninResponse {

    private final String bearerToken;
    private final String refreshToken; // ← 추가

    public SigninResponse(String bearerToken, String refreshToken) {
        this.bearerToken = bearerToken;
        this.refreshToken = refreshToken;
    }
}
