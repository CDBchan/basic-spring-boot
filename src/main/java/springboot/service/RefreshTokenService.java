package springboot.service;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import springboot.domain.RefreshToken;
import springboot.repository.RefreshTokenRepository;

@RequiredArgsConstructor
@Service
public class RefreshTokenService {

	private final RefreshTokenRepository refreshTokenRepository;

	public RefreshToken findByRefreshToken(String refreshToken) {
		return refreshTokenRepository.findByRefreshToken(refreshToken)
			.orElseThrow(() -> new IllegalArgumentException("Unexpected token"));
	}
}
