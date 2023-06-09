package springboot.domain;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Table(name = "users")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
@Entity
public class User implements UserDetails {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "id", updatable = false)
	private Long id;

	@Column(name = "email",nullable = false,unique = true)
	private String email;

	@Column(name = "password")
	private String password;

	@Builder
	public User(String email, String password,String Auth) {
		this.email = email;
		this.password = password;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return List.of(new SimpleGrantedAuthority("user"));
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return email;
	}

	@Override
	public boolean isAccountNonExpired() {
		//true -> 계정이 만료되지 않았다.
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		//true -> 계정이 잠금되지 않았다.
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		// true -> 패스워드가 만료되지 않았다.
		return true;
	}

	@Override
	public boolean isEnabled() {
		// true -> 계정이 사용 가능하다.
		return true;
	}
}
