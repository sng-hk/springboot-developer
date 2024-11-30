package me.shinsunyoung.springbootdeveloper.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import me.shinsunyoung.springbootdeveloper.config.jwt.TokenProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * 필터는 실제로 각종 요청을 처리하기 위한 로직으로 전달되기 전후에 URL 패턴에 맞는
 * 모든 요청을 처리하는 기능을 제공한다.
 * 요청이 오면 헤더값을 비교해서 토큰이 있는지 확인하고 유효 토큰이면 시큐리티 콘텍스트 홀더에
 * 인증 정보를 저장한다.
 * 시큐리티 컨텍스트는 인증 객체가 저장되는 보관소이다. 여기서 인증 정보가 필요할 때 언제든지
 * 인증 객체를 꺼내서 쓸 수 있다.
 * 이 클래스는 스레드마다 공간을 할당하는 즉, 스레드 로컬에 저장되므로 코드의 아무곳에서나 참조할 수 있고,
 * 다른 스레드와 공유하지 않으므로 독립적으로 사용할 수 있다. 그리고 이러한 시큐리티 객체를 저장하는
 * 객체가 시큐리티 콘텍스트 홀더이다.
 * ----------------------------------------------
 * 이 필터는 액세스 토큰값이 담긴 Authorization 헤더값을 가져온 뒤
 * 액세스 토큰이 유효하다면 인증 정보를 설정한다.
 */
@RequiredArgsConstructor
public class TokenAuthenticationFilter extends OncePerRequestFilter {
    private final TokenProvider tokenProvider;

    // http 요청 헤더 authorization값을 가져오기 위함
    private final static String HEADER_AUTHORIZATION = "Authorization";

    // 접두사 Bearer 을 substring한 뒤 가져오기 위함
    private final static String TOKEN_PREFIX = "Bearer ";

    /**
     * 요청 헤더에 키가 'Authorization'인 필드의 값을 가져온 다음 토큰의 접두사 Bearer를 제외
     * 한 값을 얻는다.
     * 만약 'Authorization'필드가 null이거나 Bearer로 시작하지 않으면 null을 반환.
     * 이어서 bearer로 가져온 토큰이 유효한지 확인을 하고,
     * 토큰이 유효하다면 인증정보를 관리하는 시큐리티 컨텍스트에 인증 정보를 설정한다.
     * 인증 정보가 설정된 이후에 컨텍스트 홀더에서 getAuthentication() 메서드를 사용해 인증 정보를
     * 가져오면 유저 객체가 반환된다.
     * 유저 객체에는 유저 이름과 권한 목록과 같은 인증 정보가 포함된다.
     * */
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        // 요청 헤더의 Authorization 키의 값 조회
        String authorizationHeader = request.getHeader(HEADER_AUTHORIZATION);
        // 가져온 값에서 접두사 제거
        String token = getAccessToken(authorizationHeader);

        // 가져온 토큰이 유효한지 확인하고, 유효한 때는 인증 정보 설정
        // SecurityContextHolder는 인증 객체가 저장되는 보관소. 스레드마다 저장공간 할당.
        // 즉 스레드 로컬에 저장됨. 즉 코드 아무곳에서 참조할 수 있고, 다른 스레드와 공유하지 않음.

        if (tokenProvider.validToken(token)) { // 유효한 경우 (즉, 서명이 올바르고 만료되지 않은 경우) 다음 단계로 진행합니다.
            // 토큰 인증 정보 설정
            Authentication authentication = tokenProvider.getAuthentication(token);
            // 시큐리티 컨텍스트 홀더 : 그러한 시큐리티 컨텍스트를 저장하는 객체
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        // 현재 필터가 요청을 처리한 후, 다음 필터로 요청과 응답 객체를 전달
        filterChain.doFilter(request, response);
        // 위 호출이 없으면 필터 체인이 중단되므로,
        // 이후의 필터나 최종 요청 처리기(예: 컨트롤러)가 호출되지 않습니다.
        // 즉, 요청이 더 이상 처리되지 않게 됩니다.
    }

    // 요청헤더의 Authorization의 값중에서 "Bearer " 접두사 제거
    private String getAccessToken(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith(TOKEN_PREFIX)) {
            return authorizationHeader.substring(TOKEN_PREFIX.length());
        }
        return null;
    }

}
