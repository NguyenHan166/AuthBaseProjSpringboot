package com.nguyenhan.authbasedproject.repository;

import com.nguyenhan.authbasedproject.entity.RefreshToken;
import com.nguyenhan.authbasedproject.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    Optional<RefreshToken> findByUser(User user);
    
    @Modifying
    @Transactional
    int deleteByUser(User user);

}
