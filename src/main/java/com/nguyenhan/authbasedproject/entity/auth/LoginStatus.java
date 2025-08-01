package com.nguyenhan.authbasedproject.entity.auth;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.Instant;

@Data
@NoArgsConstructor
public class LoginStatus implements Serializable {
    private static final long serialVersionUID = 1L;

    @JsonProperty("failedAttempts")
    private int failedAttempts;

    @JsonProperty("lastFailed")
    private Instant lastFailed;

    @JsonProperty("lockUntil")
    private Instant lockUntil;

    // Jackson constructor for proper deserialization
    @JsonCreator
    public LoginStatus(
            @JsonProperty("failedAttempts") int failedAttempts,
            @JsonProperty("lastFailed") Instant lastFailed,
            @JsonProperty("lockUntil") Instant lockUntil) {
        this.failedAttempts = failedAttempts;
        this.lastFailed = lastFailed;
        this.lockUntil = lockUntil;
    }
}
