package springboot.service;

import java.time.Duration;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import springboot.config.jwt.TokenProvider;
import springboot.domain.User;

@RequiredArgsConstructor
@Service
public class TokenService {

	private final TokenProvider tokenProvider;
	private final RefreshTokenService refreshTokenService;
	private final UserService userService;

	public String createNewAccessToken(String refreshToken) {
		if(!tokenProvider.validToken(refreshToken)) {
			throw new IllegalArgumentException("Invalid refresh token");
		}
		Long userId = refreshTokenService.findByRefreshToken(refreshToken).getUserId();
		User user = userService.findById(userId);

		return tokenProvider.generateToken(user, Duration.ofHours(2));
	}

}
