package com.nguyenhan.authbasedproject.entity;


import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "refresh_tokens")
@Getter@Setter
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String token;

    @Column(nullable = false)
    private Instant expiryDate;

    @Column(nullable = false)
    private Instant createdAt;

    @OneToOne
    @JoinColumn(name = "user_id", referencedColumnName = "id")
    private User user;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
            name = "used_refresh_tokens",
            joinColumns = @JoinColumn(name = "refresh_token_id")
    )
    @Column(name = "used_token", columnDefinition = "TEXT")
    private List<String> usedTokens = new ArrayList<>();

    public RefreshToken() {
        this.createdAt = Instant.now();
    }

    public void addUsedToken(String token) {
        if (this.usedTokens == null) {
            this.usedTokens = new ArrayList<>();
        }
        this.usedTokens.add(token);
    }

    public boolean isTokenUsed(String token) {
        return this.usedTokens != null && this.usedTokens.contains(token);
    }

}
