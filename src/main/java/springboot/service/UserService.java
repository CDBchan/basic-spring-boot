package springboot.service;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.val;
import springboot.domain.User;
import springboot.dto.AddUserRequest;
import springboot.repository.UserRepository;

@RequiredArgsConstructor
@Service
public class UserService {

	private final UserRepository userRepository;

	public Long save(AddUserRequest dto){
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

		return userRepository.save(User.builder()
			.email(dto.getEmail())
			.password(encoder.encode(dto.getPassword()))
			.build()).getId();
	}

	public User findById(Long userId) {
		return userRepository.findById(userId)
			.orElseThrow(() -> new IllegalArgumentException("User not found"));
	}

	public User findByEmail(String email) {
		return userRepository.findByEmail(email)
			.orElseThrow(() -> new IllegalArgumentException("User not found"));
	}
}
