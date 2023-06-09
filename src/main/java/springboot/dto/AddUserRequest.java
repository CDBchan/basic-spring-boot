package springboot.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@Getter
@Setter
public class AddUserRequest {
	private String email;
	private String password;

}
