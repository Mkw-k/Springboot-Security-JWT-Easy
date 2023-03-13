package com.cos.jwtex01.config.jwt;

import java.io.IOException;
import java.time.Instant;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.cos.jwtex01.model.RefreshToken;
import com.cos.jwtex01.model.Token;
import com.cos.jwtex01.repository.RefreshTokenRepository;
import com.cos.jwtex01.service.JwtService;
import lombok.NoArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwtex01.config.auth.PrincipalDetails;
import com.cos.jwtex01.dto.LoginRequestDto;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

/**
 * 최초 토큰 생성 해주는 필터로 보임 - 로그인
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{

	private final AuthenticationManager authenticationManager;
	private final JwtService jwtService;

	// Authentication 객체 만들어서 리턴 => 의존 : AuthenticationManager
	// 인증 요청시에 실행되는 함수 => /login
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		
		System.out.println("JwtAuthenticationFilter : 진입");
		
		// request에 있는 username과 password를 파싱해서 자바 Object로 받기
		ObjectMapper om = new ObjectMapper();
		LoginRequestDto loginRequestDto = null;
		try {
			loginRequestDto = om.readValue(request.getInputStream(), LoginRequestDto.class);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		System.out.println("JwtAuthenticationFilter : "+loginRequestDto);
		
		// 유저네임패스워드 토큰 생성
		UsernamePasswordAuthenticationToken authenticationToken = 
				new UsernamePasswordAuthenticationToken(
						loginRequestDto.getUsername(), 
						loginRequestDto.getPassword());
		
		System.out.println("JwtAuthenticationFilter : 토큰생성완료");
		
		// authenticate() 함수가 호출 되면 인증 프로바이더가 유저 디테일 서비스의
		// loadUserByUsername(토큰의 첫번째 파라메터) 를 호출하고
		// UserDetails를 리턴받아서 토큰의 두번째 파라메터(credential)과
		// UserDetails(DB값)의 getPassword()함수로 비교해서 동일하면
		// Authentication 객체를 만들어서 필터체인으로 리턴해준다.
		
		// Tip: 인증 프로바이더의 디폴트 서비스는 UserDetailsService 타입
		// Tip: 인증 프로바이더의 디폴트 암호화 방식은 BCryptPasswordEncoder
		// 결론은 인증 프로바이더에게 알려줄 필요가 없음.
		Authentication authentication = 
				authenticationManager.authenticate(authenticationToken);
		
		PrincipalDetails principalDetailis = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("Authentication : "+principalDetailis.getUser().getUsername());
		return authentication;
	}

	// JWT Token 생성해서 response에 담아주기
	// 위에 로그인 Authentication에 성공했을경우 이 메서드를 타게된다
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
											Authentication authResult) throws IOException, ServletException {
		
		PrincipalDetails principalDetailis = (PrincipalDetails) authResult.getPrincipal();
		
		String accessToken = JWT.create()
				.withSubject(principalDetailis.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME))
				.withClaim("id", principalDetailis.getUser().getId())
				.withClaim("username", principalDetailis.getUser().getUsername())
				.sign(Algorithm.HMAC512(JwtProperties.SECRET));

		String refreshToken = JWT.create()
				.withSubject(principalDetailis.getUsername())
				.withIssuedAt(Date.from(Instant.now()))
				.withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.REFRESH_EXPIRATION_TIME))
				.withClaim("id", principalDetailis.getUser().getId())
				.withClaim("username", principalDetailis.getUser().getUsername())
				.sign(Algorithm.HMAC512(JwtProperties.REFRESH_SECRET));

		response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX+accessToken);
		response.addHeader(JwtProperties.REFRESH_TOKEN_STRING, JwtProperties.TOKEN_PREFIX+refreshToken);

		Token token = Token.builder()
				.refreshToken(refreshToken)
				.accessToken(accessToken)
				.key(principalDetailis.getUser().getUsername())
				.build();

		//로그인 처리 - username에 해당하는 refresh Token이 존재할경우 삭제후 생성하여 DB에 저장
		//없을경우 그대로 저장
		jwtService.login(token);
	}


	
}
