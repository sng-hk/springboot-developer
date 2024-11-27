package me.shinsunyoung.springbootdeveloper.config;

import lombok.RequiredArgsConstructor;
import me.shinsunyoung.springbootdeveloper.service.UserDetailService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console;

@Configuration
@RequiredArgsConstructor
public class WebSecurityConfig {

    private final UserDetailService userService;

    // 스프링 시큐리티 비활성화
    @Bean
    public WebSecurityCustomizer configure() {
        return (web) -> web.ignoring() // 아래 대상들은 스프링 시큐리티 비활성화
                //
                .requestMatchers("/static/**"); // 스태틱 하위 경로에 있는 리소스
//                .requestMatchers(toH2Console()); // h2-console하위 url
    }

    // 특정 http 요청에 대한 웹 기반 보안 구성
    @Bean
    public SecurityFilterChain fileterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeRequests() // 인증, 인가 설정
                .requestMatchers("/login", "/signup", "/user").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin() // 폼 기반 로그인 설정
                    .loginPage("/login") // 로그인 페이지 경로 설정
                    .defaultSuccessUrl("/articles") // 로그인이 완료되었을 때 이동할 경로
                .and()
                .logout() // 로그아웃 설정
                .logoutSuccessUrl("/login") // 로그아웃이 완료되었을 때 경로
                .invalidateHttpSession(true) // 로그아웃 이후 세션을 전체 삭제할지 여부를 설정
                .and()
                .csrf().disable() // csrf 비활성화
                .build();
    }

    // 인증 관리자 관련 설정
    // 사용자 정보를 가져올 서비스를 재정의, 인증 방법 (ex. ldap, jdbc 기반 인증)
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http,
                                                       BCryptPasswordEncoder bCryptPasswordEncoder, UserDetailService userDetailService)
            throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .userDetailsService(userService) // 사용자 정보 서비스 설정
                .passwordEncoder(bCryptPasswordEncoder)
                .and()
                .build();
    }

    // 패스워드 인코더로 사용할 빈 등록
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}