package me.shinsunyoung.springbootdeveloper.config.jwt;

import io.jsonwebtoken.Jwts;
import me.shinsunyoung.springbootdeveloper.domain.User;
import me.shinsunyoung.springbootdeveloper.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Duration;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
public class TokenProviderTest {
    @Autowired
    private TokenProvider tokenProvider;

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private JwtProperties jwtProperties;

    // generateToken() 검증 테스트

    /**
     * 토큰 생성 메서드 테스트:
     * given: 토큰에 유저 정보를 추가하기 위한 테스트 유저를 만든다.
     * when: 토큰 제공자의 "generateToken()"메서드를 호출해 토큰을 만든다
     * then: jjwt 라이브러리를 사용해 토큰을 복호화한다. 토큰을 만들 때 클레임을 ㅗ넣어둔 id 값이
     * given절에서 만든 유저 ID와 동일한지 확인한다.
     */
    @DisplayName("generateToken() : 유저 정보 만료 기간을 전달해 토큰을 만들 수 있다.")
    @Test
    void generateToken() {
        // given
        User testUser = userRepository.save(User.builder()
                .email("user@gmail.com")
                .password("test")
                .build());
        // when
        String token = tokenProvider.generateToken(testUser, Duration.ofDays(14));
        // then
        Long userId = Jwts.parser()
                .setSigningKey(jwtProperties.getSecretKey())
                .parseClaimsJws(token)
                .getBody()
                .get("id", Long.class);

        assertThat(userId).isEqualTo(testUser.getId());
    }

    // validToken() 검증 테스트
    // case 1) 만료된 토큰인 경우

    /**
     * given: jjwt 라이브러리를 사용해 토큰을 생성한다. 이때 만료 시간은 1970년 1월 1일부터
     * 현재 시간을 밀리초 단위로 치환한 값(new Date().getTime())에 1000을 빼, 이미 만료된 토큰을 생성한다.
     * <p>
     * when: 토큰 제공자의 "validToken()" 메서드를 호출해 유효한 토큰인지 검증한 뒤 결괏값을 반환받는다.
     * then: 반환값이 false(유효한 토큰이 아님)인 것을 확인한다.
     */
    @DisplayName("validToken(): 만료된 토큰인 때에 유효성 검증에 실패한다.")
    @Test
    void validToken_invalidToken() {
        // given : 만료된 토큰 생성
        String token = JwtFactory.builder()
                .expiration(new Date(new Date().getTime() - Duration.ofDays(7)
                        .toMillis())).build()
                .createToken(jwtProperties);
        // when : 토큰 유효한지 확인
        boolean result = tokenProvider.validToken(token);
        // then : 반환값이 false인지 확인
        assertThat(result).isFalse();
    }

    // validToken() 검증 테스트
    // case 2) 유효한 토큰인 경우
    @DisplayName("validToken(): 유효한 토큰인 때에 유효성 검증에 성공한다.")
    @Test
    void validToken_validToken() {
        // given : 유효한 토큰 생성
        String token = JwtFactory.withDefaultValues()
                .createToken(jwtProperties);
        // when : 토큰 유효한지 확인
        boolean result = tokenProvider.validToken(token);
        // then : 반환값이 false인지 확인
        assertThat(result).isTrue();
    }

    /**
     * 토큰을 전달받아 인증 정보를 담은 객체 Authentication을 반환하는 메서드인 "getAuthentication()"를 테스트
     */
    @DisplayName("getAuthentication(): 토큰 기반으로 인증 정보를 가져올 수 있다.")
    @Test
    void getAuthentication() {
        // given : 토큰 생성
        String userEmail = "user@email.com";
        String token = JwtFactory.builder()
                .subject(userEmail)
                .build()
                .createToken(jwtProperties);
        // when : 토큰에 담긴 Authentication객체 반환
        Authentication authentication = tokenProvider.getAuthentication(token);
        // then : Authentication객체에 principal(주체)의 username(email)과 given에서 받은 userEmail이 같은지 확인
        assertThat(((UserDetails) authentication.getPrincipal()).getUsername()).isEqualTo(userEmail);
    }

    /**
     * 토큰을 프로퍼티즈 파일에 저장한 비밀값으로 복호화한 뒤 클레임을 가져오는 prviate 메서드인 getClaims()를 호출해서
     * 클레임 정보를 반환받아 클레임에서 id키로 저장된 값을 가져와 반환
     * */
    // getUserId() 검증
    @DisplayName("getUserId(): 토큰으로 유저 ID를 가져올 수 있다.")
    @Test
    void getUserId() {
        // given : 유저 Id가 담긴 토큰 생성
        Long userId = 1L;
        String token = JwtFactory.builder()
                .claims(Map.of("id", userId))
                .build()
                .createToken(jwtProperties);
        // when
        Long userIdByToken = tokenProvider.getUserId(token);
        // then
        assertThat(userIdByToken).isEqualTo(userId);
    }
}
