package springboot.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import springboot.domain.User;
import springboot.dto.AddUserRequest;
import springboot.service.UserService;

@RequiredArgsConstructor
@Controller
@Slf4j
public class UserApiController {

	private final UserService userService;

	@PostMapping("/user")
	public String signUp(AddUserRequest request) {
		log.info("email : {}, pw : {}", request.getEmail(), request.getPassword());
		userService.save(request);
		return "redirect:/login";
	}

	@GetMapping("/logout")
	public String logout(HttpServletRequest request, HttpServletResponse response) {
		new SecurityContextLogoutHandler().logout(request, response, SecurityContextHolder.getContext().getAuthentication());
		return "redirect:/login";
	}
}
