package dongwoongkim.jwtserver.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import dongwoongkim.jwtserver.auth.PrincipalDetails;
import dongwoongkim.jwtserver.dto.LoginRequestDto;
import dongwoongkim.jwtserver.repo.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.Date;


// 스프링 시큐리티 UsernamePasswordAuthenticationFilter가 있음
// /login 요청해서 username, password post 전송 시 동작
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        // 1. ID, PW를 받아서
        ObjectMapper om = new ObjectMapper();
        LoginRequestDto loginRequestDto = null;
        try {
            loginRequestDto = om.readValue(request.getInputStream(), LoginRequestDto.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // 2. UsernamePasswordAuthentication Token 생성
        UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(loginRequestDto.getUsername(),loginRequestDto.getPassword());

        // AuthenticationManager에서 authenticate() 함수 호출 시
        // 내부적으로 AuthenticationProvicder 아래 작업들을 수행합니다.
        // 3-1. UserDetailsService의 loadUserByUsername(토큰의 첫번째 파라메터) 를 호출
        // 3-2. UserDetails를 리턴받아서
        // 3-3. 토큰의 두번째 파라미터(credential)과 UserDetails(DB값)의 getPassword()함수로 비교 후 동일하면
        // Authentication 객체를 만들어서 리턴해줍니다.
        Authentication authentication = authenticationManager.authenticate(authenticationToken);



        // Tip: 인증 프로바이더의 디폴트 서비스 : UserDetailsService 타입
        // Tip: 인증 프로바이더의 디폴트 암호화 방식 : BCryptPasswordEncoder
        // 결론은 인증 프로바이더에게 별도로 어떤 Service 타입을 사용하고 어떤 방식으로 암호화 할지 알려줄 필요가 없음.
        // authentication 객체가 session 영역에 저장됨 => 로그인 성공
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

        return authentication;
    }


    // 4. JWT 토큰 생성 및 응답
    // attempt 함수가 실행 후 인증 완료시 실행
    // jwt 토큰을 만들어서 request요청한 사용자에게 jwt토큰을 response해주면 됨.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX+jwtToken);
    }
}
