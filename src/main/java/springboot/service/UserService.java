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
	private final BCryptPasswordEncoder bCryptPasswordEncoder;

	public Long save(AddUserRequest dto){
		return userRepository.save(User.builder()
			.email(dto.getEmail())
			.password(bCryptPasswordEncoder.encode(dto.getPassword()))
			.build()).getId();
	}
}
