package me.shinsunyoung.springbootdeveloper.config.jwt;


import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

// application.yml에서 이슈 발급자, 비밀키를 설정했다.
// 이 값들을 변수로 접근하는데 사용할 클래스이다.
@Setter
@Getter
@Component
/**
 * @ConfigurationProperties("jwt") :
 * 이 어노테이션은 application.yml 또는 application.properties 파일에서
 * jwt라는 접두사로 시작하는 프로퍼티들을 이 클래스의 필드에 자동으로 바인딩합니다.
 * */
@ConfigurationProperties("jwt") // 자바 클래스에 프로퍼티값을 가져와서 사용하는 어노테이션
public class JwtProperties {
    private String issuer;
    private String secretKey;
}
