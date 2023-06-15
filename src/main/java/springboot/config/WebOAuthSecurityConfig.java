package springboot.config;

import lombok.RequiredArgsConstructor;
import springboot.config.jwt.TokenProvider;
import springboot.config.oauth.OAuth2AuthorizationRequestBasedOnCookieRepository;
import springboot.config.oauth.OAuth2SuccessHandler;
import springboot.config.oauth.OAuth2UserCustomService;
import springboot.repository.RefreshTokenRepository;
import springboot.service.UserService;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console;

@RequiredArgsConstructor
@Configuration
public class WebOAuthSecurityConfig {

	private final OAuth2UserCustomService oAuth2UserCustomService;
	private final TokenProvider tokenProvider;
	private final RefreshTokenRepository refreshTokenRepository;
	private final UserService userService;

	// 스프링 시큐리티 기능을 비활성화 할 부분 설정
	@Bean
	public WebSecurityCustomizer configure() {
		return (web) -> web.ignoring()
			.requestMatchers(toH2Console())
			.requestMatchers("/img/**", "/css/**", "/js/**");
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		//토큰 방식을 사용할거기 떄문에, form 로그인 및 세션 비활성화
		http.csrf().disable()
			.httpBasic().disable()
			.formLogin().disable()
			.logout().disable();

		http.sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		// 헤더에 있는 토큰 정보가 유효한지 확인
		http.addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

		// 토큰 재발급 URL은 인증 없이 접근 가능하도록 설정 (나머지 URL은 인증을 해야 접근 가능)
		http.authorizeRequests()
			.requestMatchers("/api/token").permitAll()
			.requestMatchers("/api/**").authenticated()
			.anyRequest().permitAll();

		//OAuth2로 로그인을 하겠다.
		http.oauth2Login()
			//사용자가 로그인을 위해 이동해야하는 로그인 페이지
			.loginPage("/login")
			//인증 요청 저장소를 설정한다. 여기서는 쿠키를 기반으로 인증요청을 저장하고 제거하는 Repository를 설정한 것이다.
			.authorizationEndpoint()
			.authorizationRequestRepository(oAuth2AuthorizationRequestBasedOnCookieRepository())
			//로그인 성공후 시작할 로직을 설정한다.
			.and()
			.successHandler(oAuth2SuccessHandler())
			.userInfoEndpoint()
			.userService(oAuth2UserCustomService);

		http.logout()
			.logoutSuccessUrl("/login");

		// /api 로 시작하는 url인 경우 인증 실패시 401상태 코드를 반환하도록 예외 처리
		http.exceptionHandling()
			.defaultAuthenticationEntryPointFor(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
				new AntPathRequestMatcher("/api/**"));


		return http.build();
	}


	@Bean
	public OAuth2SuccessHandler oAuth2SuccessHandler() {
		return new OAuth2SuccessHandler(tokenProvider,
			refreshTokenRepository,
			oAuth2AuthorizationRequestBasedOnCookieRepository(),
			userService
		);
	}

	@Bean
	public TokenAuthenticationFilter tokenAuthenticationFilter() {
		return new TokenAuthenticationFilter(tokenProvider);
	}

	@Bean
	public OAuth2AuthorizationRequestBasedOnCookieRepository oAuth2AuthorizationRequestBasedOnCookieRepository() {
		return new OAuth2AuthorizationRequestBasedOnCookieRepository();
	}

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
