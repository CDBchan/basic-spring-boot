package springboot.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import springboot.domain.RefreshToken;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken,Long> {
	Optional<RefreshToken> findByRefreshToken(String refreshToken);
	Optional<RefreshToken> findByUserId(Long userId);
}
