package com.cos.jwtex01.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.cos.jwtex01.model.User;
import com.cos.jwtex01.repository.UserRepository;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.security.auth.Subject;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

/**
 * packageName    : com.cos.jwtex01.config.jwt
 * fileName       : JwtRefreshAuthenticationFilter
 * author         : 드림포원 디자이너2
 * date           : 2023-03-13
 * description    :
 * ===========================================================
 * DATE              AUTHOR             NOTE
 * -----------------------------------------------------------
 * 2023-03-13        드림포원 디자이너2       최초 생성
 */
public class JwtRefreshAuthenticationFilter extends OncePerRequestFilter {
    private JwtProvider jwtProvider;
    private UserRepository userRepository;

    public void JwtAuthenticationFilter(JwtProvider jwtProvider, UserRepository userRepository) {
        this.jwtProvider = jwtProvider;
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorization = request.getHeader("Authorization");
        if (!Objects.isNull(authorization)) {
            String atk = authorization.substring(7);
            try {
                DecodedJWT jwt = JWT.decode(atk);
                String email = jwt.getSubject();
                String requestURI = request.getRequestURI();
                if (jwt.getClaim("type").asString().equals("RTK") && !requestURI.equals("/account/reissue")) {
                    throw new JWTVerificationException("토큰을 확인하세요.");
                }
                User user = userRepository.findByUsername(email);
                Authentication token = new UsernamePasswordAuthenticationToken(user, "", user.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(token);
            } catch (TokenExpiredException e) {
                request.setAttribute("exception", "토큰이 만료되었습니다.");
            } catch (JWTVerificationException e) {
                request.setAttribute("exception", e.getMessage());
            }
        }
        filterChain.doFilter(request, response);
    }
}
