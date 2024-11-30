package me.shinsunyoung.springbootdeveloper.config.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import me.shinsunyoung.springbootdeveloper.domain.User;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Collections;
import java.util.Date;
import java.util.Set;

@RequiredArgsConstructor
@Service
public class TokenProvider {

    private final JwtProperties jwtProperties;

    /**
    * 예시 호출 코드
    * User user = new User("user@example.com", 123);
    * Duration expiredAt = Duration.ofHours(1); // 1시간 후 만료
    * */
    public String generateToken(User user, Duration expiredAt) {
        Date now = new Date(); // 현재 시간 (예: 2024-11-30 12:00:00)
        return makeToken(new Date(now.getTime() + expiredAt.toMillis()), user);
    }

    private String makeToken(Date expiry, User user) {
        Date now = new Date();

//      Jwt 라이브러리 builder 생성자로 jwt토큰을 생성.
        return Jwts.builder()
                .setHeaderParam(Header.TYPE, Header.JWT_TYPE)
                .setIssuer(jwtProperties.getIssuer())
                .setIssuedAt(now) // 발급 시간: 2024-11-30 12:00:00
                .setExpiration(expiry) // 만료 시간: 2024-11-30 13:00:00
                .setSubject(user.getEmail()) // 주제: user@example.com
                /* 사용자 정의 클레임, 그래서 파라미터를 보면 클레임 이름으로 "id"를 지정*/
                .claim("id", user.getId()) // 사용자 ID: 123
                .signWith(SignatureAlgorithm.HS256, jwtProperties.getSecretKey())
                .compact(); // 최종 JWT 문자열 생성
                            // ex) eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIiwiaWF0IjoxNjE1MTYzMDQ1LCJleHBpcmVkX3RpbWUiOjE2MTUxNjM0MDUsImlkIjoxMjM0NTY3ODkwfQ
    }

    /**
     * 토큰 유효성 검증을 하든, 인증 정보를 가져오든, 유저 ID를 가져오든, claim을 가져오든
     * 토큰 기반으로 가져오기때문에 파라미터로 token 문자열을 받아와야 한다.
     * */
    public boolean validToken(String token) {
        try {
            Jwts.parser()
                    .setSigningKey(jwtProperties.getSecretKey())
                    .parseClaimsJws(token);

            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public Authentication getAuthentication(String token) {
        Claims claims = getClaims(token);
        Set<SimpleGrantedAuthority> authorities = Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"));

        return new UsernamePasswordAuthenticationToken(new org.springframework.security.core.userdetails.User(claims.getSubject
                (), "", authorities), token, authorities);
    }

    public Long getUserId(String token) {
        Claims claims = getClaims(token);
        return claims.get("id", Long.class);
    }

    private Claims getClaims(String token) {
        return Jwts.parser()
                .setSigningKey(jwtProperties.getSecretKey())
                .parseClaimsJws(token)
                .getBody();
    }
}
