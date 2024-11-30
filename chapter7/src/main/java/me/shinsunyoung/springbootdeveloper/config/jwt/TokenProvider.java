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

    public String generateToken(User user, Duration expiredAt) {
        Date now = new Date();
        return makeToken(new Date(now.getTime() + expiredAt.toMillis()), user);
    }

    /**
     * 토큰 생성 메서드.
     * 인자는 만료 시간, 유저 정보를 받는다.
     * set 계열의 메서드를 통해 여러 값을 지정한다.
     * 헤더는 typ(타입), 내용은 iss(발급자), iat(발급일시), exp(만료일시), sub(토큰 제목), 클레임에는 유저 ID를 지정
     * 토큰을 만들 때에는 프로퍼티즈 파일에 선언해둔 비밀값(secret_key)와 함께 HS256 방식으로 암호화된다.
     * */
    private String makeToken(Date expiry, User user) {
        Date now = new Date();

        return Jwts.builder()
                /**
                 * {
                 *  "typ":"JWT",
                 *  "alg": "HS256"
                 *  }
                 *  */
                .setHeaderParam(Header.TYPE, Header.JWT_TYPE) // 헤더 typ : JWT
                /**
                 * {
                 *  "iss": "csh091456743@gmail.com",
                 *  "iat": 발급일시
                 *  "exp": 만료일시
                 *  "sub": 토큰 제목(발행자)
                 *  "email": 이메일
                 *  클레임 id : 유저 id (?)*/
                .setIssuer(jwtProperties.getIssuer()) // 내용 iss : csh091456743@gmail.com(application.yml에서 설정한 값 - Jwt에서 불러와서 사용)
                .setIssuedAt(now) // 내용 iat : 현재 시간
                .setExpiration(expiry) // 내용 exp : expiry 멤버 변숫값
                .setSubject(user.getEmail()) // 내용 sub : 유저 이메일
                .claim("id", user.getId()) // 클레임 id : 유저 ID
                // 서명 : 비밀값(application.yml에서 설정한 값 - jwtproperties에서 불러오기)과 함께 해시값을 HS256방식으로 암호화
                .signWith(SignatureAlgorithm.HS256, jwtProperties.getSecretKey())
                .compact();
    }

    /**
     * 토큰이 유효한지 검증하는 메서드
     * 프로퍼티즈 파일에 선언한 비밀값과 함께 토큰 복호화 진행
     * 만약 복호화 과정에서 에러가 발생하면 유효하지 않은 토큰이므로 false를 반환
     * 아무 에러도 발생하지 않으면 true 반환
     * */
    // JWT 토큰 유효성 검증 메서드
    public boolean validToken(String token) {
        try {
            Jwts.parser()
                    .setSigningKey(jwtProperties.getSecretKey()) // 비밀값으로 복호화
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) { // 복호화 과정에서 에러가 나면 유효하지 않은 토큰
            return false;
        }
    }

    /**
     * 토큰을 받아인증 정보를 담은 객체 Authentication을 반환하는 메서드.
     * 프로퍼티즈 파일에 저장한 비밀값으로 토큰을 복호화한 뒤 클레임을 가져오는 private 메서드인 getClaims()를 호출해서
     * 클레임 정보를 반환받아 사용자 이메일이 들어있는 토큰 제목 sub와 토큰 기반으로 인증 정보를 생성한다.
     * 이때 UsernamePasswordAuthenticationToken의 첫 인자로 들어가는 user는 프로젝트에서 만든 User 클래스가 아닌,
     * 스프링 시큐리티에서 제공하는 객체인 user 클래스를 임포트해야한다.
     * */
    // 토큰 기반 인증 정보를 가져오는 메서드
    public Authentication getAuthentication(String token) {
        Claims claims = getClaims(token);
        Set<SimpleGrantedAuthority> authorities = Collections.singleton(new SimpleGrantedAuthority(("ROLE_USER")));

        return new UsernamePasswordAuthenticationToken(new org.springframework.security.core.userdetails.User(claims.getSubject()
        , "", authorities), token, authorities);
    }

    /**
     * 토큰 기반으로 사용자 ID를 가져오는 메서드이다.
     * 프로퍼티즈 파일에 저장한 비밀값으로 토큰을 복호화한 다음 클레임을 가져오는 private 메서드인 getClaims()를 호출해서 클레임 정보를 반환받고
     * 클레임에서 id 키로 저장된 값을 가져와 반환한다.
     */
    private Claims getClaims(String token) {
        return Jwts.parser() // 클레임 조회
                .setSigningKey(jwtProperties.getSecretKey()) // secret key 를 가지고 복호화
                .parseClaimsJws(token)
                .getBody();
    }
}
