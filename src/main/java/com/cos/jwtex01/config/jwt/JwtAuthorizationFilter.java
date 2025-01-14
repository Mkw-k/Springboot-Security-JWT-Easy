package com.cos.jwtex01.config.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.cos.jwtex01.service.JwtService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwtex01.config.auth.PrincipalDetails;
import com.cos.jwtex01.model.User;
import com.cos.jwtex01.repository.UserRepository;

/**
 * 인가
 * 확인헤서 토큰이 정상여부 확인 및 후처리
 * 다른 비즈니스 로직들 요청시
 *
 * Access Token 만료시 또는 불일치 할경우 
 * */
public class JwtAuthorizationFilter extends BasicAuthenticationFilter{
	
	private UserRepository userRepository;
	private JwtService jwtService;
	
	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository,
								  JwtService jwtService) {
		super(authenticationManager);
		this.userRepository = userRepository;
		this.jwtService = jwtService;
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		String username = "";
		String header = request.getHeader(JwtProperties.HEADER_STRING);
		if(header == null || !header.startsWith(JwtProperties.TOKEN_PREFIX)) {
			chain.doFilter(request, response);
                        return;
		}
		System.out.println("header : "+header);
		
		//헤더에서 AccessToken값을 불러온뒤 Bearer를 제거해준다
		String token = request.getHeader(JwtProperties.HEADER_STRING)
				.replace(JwtProperties.TOKEN_PREFIX, "");
		
		// 토큰 검증 (이게 인증이기 때문에 AuthenticationManager도 필요 없음)
		// 내가 SecurityContext에 집적접근해서 세션을 만들때 자동으로 UserDetailsService에 있는 loadByUsername이 호출됨.
//		Algorithm algorithm = Algorithm.HMAC512(JwtProperties.SECRET);
//		JWTVerifier verifier = JWT.require(algorithm).build();
//		DecodedJWT decodedJWT = verifier.verify(token);
//		String username = decodedJWT.getClaim("username").toString();;

//		String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(token)
//				.getClaim("username").asString();

		//토큰 디코딩 - 시간 만료시 디코딩 도중에 예외가 발생한다
		//https://velog.io/@devmin/JWT-token-expired-date-with-timedelta
		DecodedJWT decodedJWT = null;

		try {
			decodedJWT = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(token);
		} catch (TokenExpiredException e) {

			logger.info("Access 토큰 시간 만료!!");
			try {
			String refreshToken = request.getHeader(JwtProperties.REFRESH_TOKEN_STRING).replace(JwtProperties.TOKEN_PREFIX, "");

			// 정상 토큰인지 확인하기 위해 디코딩 진행
			DecodedJWT refreshDecodedJWT = JWT.require(Algorithm.HMAC512(JwtProperties.REFRESH_SECRET)).build().verify(refreshToken);
			username = refreshDecodedJWT.getClaim("username").asString();

			//refreshToken 검증
			jwtService.validateRefreshToken(refreshToken, response);

			} catch (Exception e2) {
				logger.info("Refresh 토큰 시간 만료!!");
				throw new RuntimeException(e2);
			}

		}

		//Access Token이 살아있을경우에만
		if(decodedJWT != null){
			username = decodedJWT.getClaim("username").asString();
		}


		//username값이 존재할경우
		if(username != null) {
			// 토큰이 만료되었을경우 - refreshToken 검증 - 위에서 진행완료
			/*if(!decodedJWT.getExpiresAt().before(new Date())){
				String refreshToken = request.getHeader(JwtProperties.REFRESH_TOKEN_STRING);
				try {
					//refreshToken 검증
					jwtService.validateRefreshToken(refreshToken, response);
				} catch (Exception e) {
					throw new RuntimeException(e);
				}
			}*/

			User user = userRepository.findByUsername(username);
			
			// 인증은 토큰 검증시 끝. 인증을 하기 위해서가 아닌 스프링 시큐리티가 수행해주는 권한 처리를 위해 
			// 아래와 같이 토큰을 만들어서 Authentication 객체를 강제로 만들고 그걸 세션에 저장!
			PrincipalDetails principalDetails = new PrincipalDetails(user);
			Authentication authentication =
					new UsernamePasswordAuthenticationToken(
							principalDetails, //나중에 컨트롤러에서 DI해서 쓸 때 사용하기 편함.
							null, // 패스워드는 모르니까 null 처리, 어차피 지금 인증하는게 아니니까!!
							principalDetails.getAuthorities());

			// 강제로 시큐리티의 세션에 접근하여 값 저장
			SecurityContextHolder.getContext().setAuthentication(authentication);
		}
	
		chain.doFilter(request, response);
	}
	
}
