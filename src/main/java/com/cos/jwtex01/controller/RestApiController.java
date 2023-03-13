package com.cos.jwtex01.controller;

import java.util.List;
import java.util.Map;

import com.cos.jwtex01.config.jwt.JwtProvider;
import com.cos.jwtex01.model.Token;
import com.cos.jwtex01.service.JwtService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.cos.jwtex01.config.auth.PrincipalDetails;
import com.cos.jwtex01.model.User;
import com.cos.jwtex01.repository.UserRepository;

import lombok.RequiredArgsConstructor;

import javax.servlet.http.Cookie;

@RestController
@RequestMapping("api/v1")
@RequiredArgsConstructor
@Slf4j
// @CrossOrigin  // CORS 허용 
public class RestApiController {
	
	private final UserRepository userRepository;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;
	private final JwtProvider jwtTokenProvider;
	private final JwtService jwtService;
	
	// 모든 사람이 접근 가능
	@GetMapping("home")
	public String home() {
		return "<h1>home</h1>";
	}
	
	// Tip : JWT를 사용하면 UserDetailsService를 호출하지 않기 때문에 @AuthenticationPrincipal 사용 불가능.
	// 왜냐하면 @AuthenticationPrincipal은 UserDetailsService에서 리턴될 때 만들어지기 때문이다.
	
	// 유저 혹은 매니저 혹은 어드민이 접근 가능
	@GetMapping("user")
	public String user(Authentication authentication) {
		PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("principal : "+principal.getUser().getId());
		System.out.println("principal : "+principal.getUser().getUsername());
		System.out.println("principal : "+principal.getUser().getPassword());
		
		return "<h1>user</h1>";
	}
	
	// 매니저 혹은 어드민이 접근 가능
	@GetMapping("manager/reports")
	public String reports() {
		return "<h1>reports</h1>";
	}
	
	// 어드민이 접근 가능
	@GetMapping("admin/users")
	public List<User> users(){
		return userRepository.findAll();
	}
	
	@PostMapping("join")
	public String join(@RequestBody User user) {
		user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
		user.setRoles("ROLE_USER");
		userRepository.save(user);
		return "회원가입완료";
	}

	@GetMapping("/securetest")
	public void sucureTest(@RequestParam Cookie cookie){

	}

	// 로그인
	@PostMapping("/pagelogin")
	public Token login(@RequestBody Map<String, String> user) {
		log.info("user email = {}", user.get("userEmail"));
		User member = userRepository.findByUsername2(user.get("userEmail"))
				.orElseThrow(() -> new IllegalArgumentException("가입되지 않은 E-MAIL 입니다."));

		Token tokenDto = jwtTokenProvider.createAccessToken(member.getUsername(), member.getRoles());
		log.info("getroleeeee = {}", member.getRoles());
		jwtService.login(tokenDto);
		return tokenDto;
	}
	
}











