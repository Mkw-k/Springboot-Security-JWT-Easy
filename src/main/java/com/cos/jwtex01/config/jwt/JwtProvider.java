package com.cos.jwtex01.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.cos.jwtex01.config.auth.PrincipalDetails;
import com.cos.jwtex01.model.RefreshToken;
import com.cos.jwtex01.model.Token;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.security.auth.Subject;
import java.util.Date;
import java.util.List;

/**
 * packageName    : com.cos.jwtex01.config.jwt
 * fileName       : JwtProvider
 * author         : 드림포원 디자이너2
 * date           : 2023-03-13
 * description    :
 * ===========================================================
 * DATE              AUTHOR             NOTE
 * -----------------------------------------------------------
 * 2023-03-13        드림포원 디자이너2       최초 생성
 *
 * https://velog.io/@jkijki12/Jwt-Refresh-Token-%EC%A0%81%EC%9A%A9%EA%B8%B0
 */
@Component
@RequiredArgsConstructor
public class JwtProvider {

    @Autowired
    ObjectMapper objectMapper;


    public Subject getSubject(String atk) throws JsonProcessingException {
        DecodedJWT decodedJwt = JWT.decode(atk);
        String subjectStr = decodedJwt.getSubject();

        return objectMapper.readValue(subjectStr, Subject.class);
    }

    public String validateRefreshToken(RefreshToken refreshTokenObj){

        // refresh 객체에서 refreshToken 추출
        String refreshToken = refreshTokenObj.getRefreshToken();

        try {
            // 검증 : HMAC512 써야함 HMAC256 도 있음 주의!!
            Algorithm algorithm = Algorithm.HMAC512(JwtProperties.REFRESH_SECRET);
            JWTVerifier verifier = JWT.require(algorithm).build();
            DecodedJWT decodedJWT = verifier.verify(refreshToken);

            //refresh 토큰의 만료시간이 지나지 않았을 경우, 새로운 access 토큰을 생성합니다.
            if (!decodedJWT.getExpiresAt().before(new Date())) {
                Claim userEmailClaim = decodedJWT.getClaim("username");
                String userEmail = userEmailClaim.asString();
                Claim userIdClaim = decodedJWT.getClaim("id");
                String userId = userEmailClaim.asString();
//                Claim rolesClaim = decodedJWT.getClaim("roles");
//                List<String> roles = rolesClaim.asList(String.class);
                return recreationAccessToken(userEmail, userId);
            }
        } catch (JWTVerificationException exception){
            //refresh 토큰이 만료되었을 경우, 로그인이 필요합니다.
            //TODO
            return null;
        }

        return null;
    }

    public String recreationAccessToken(String userEmail, String id){

        String accessToken = JWT.create()
                .withSubject(userEmail)
                .withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME))
                .withClaim("id", id)
                .withClaim("username", userEmail)
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

        return accessToken;
    }

    public Token createAccessToken(String userEmail, String id) {

        Algorithm accessAlgorithm = Algorithm.HMAC256(JwtProperties.SECRET);
        Algorithm refreshAlgorithm = Algorithm.HMAC256(JwtProperties.REFRESH_SECRET);

        String accessToken = JWT.create()
                .withSubject(userEmail)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME))
                .withClaim("id", id)
                .sign(accessAlgorithm);

        String refreshToken = JWT.create()
                .withSubject(userEmail)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME))
                .withClaim("id", id)
                .sign(refreshAlgorithm);

        return Token.builder().accessToken(accessToken).refreshToken(refreshToken).key(userEmail).build();
    }

}