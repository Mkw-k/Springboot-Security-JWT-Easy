package com.cos.jwtex01.config.jwt;

public interface JwtProperties {
	String SECRET = "조익현"; // 우리 서버만 알고 있는 비밀값
	String REFRESH_SECRET = "가나다";
	int EXPIRATION_TIME = 60000; // 1분
	int REFRESH_EXPIRATION_TIME = 864000000; // 10일 (1/1000초)
	String TOKEN_PREFIX = "Bearer ";
	String HEADER_STRING = "Authorization";
	String REFRESH_TOKEN_STRING = "ReAuthorization";
}
