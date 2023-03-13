package com.cos.jwtex01.repository;

import com.cos.jwtex01.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * packageName    : com.cos.jwtex01.repository
 * fileName       : RefreshTokenRepository
 * author         : 드림포원 디자이너2
 * date           : 2023-03-13
 * description    :
 * ===========================================================
 * DATE              AUTHOR             NOTE
 * -----------------------------------------------------------
 * 2023-03-13        드림포원 디자이너2       최초 생성
 */
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByRefreshToken(String refreshToken);
    boolean existsByKeyEmail(String userEmail);
    void deleteByKeyEmail(String userEmail);
}