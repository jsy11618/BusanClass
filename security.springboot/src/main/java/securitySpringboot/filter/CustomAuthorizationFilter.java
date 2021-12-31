package securitySpringboot.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.*;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;


@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    //오버라이드 메소드
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(request.getServletPath().equals("/api/login")){
            filterChain.doFilter(request, response);
        }else{
            String authorizationHeader = request.getHeader(AUTHORIZATION);
            //(아래)찾는 회원 없을 때 예외처리 하는 것
           if(authorizationHeader !=null && authorizationHeader.startsWith("Bearer")){
               try{
                   //이제 토큰을 만들꺼임.
                   String token = authorizationHeader.substring("Bearer". length());
                   //토큰 발행은 우리가 안하고 jwt가 할껀데 그러니까 이제 우리는 뭐 해야하지? jwt.io 사이트 들어가서 encoded보고 decoded보면
                   //이거 양방향으로 되어야 하는데 직접 만드는 거 힘드니까 받아온 토큰을 이제부터 풀어내보자.
                   Algorithm algorithm = Algorithm.HMAC256("secret".getBytes()); //아무것도 없는 겟바이츠 쓰기
                   //JWT이제 호출할 것
                   JWTVerifier verifier = JWT.require(algorithm).build();
                   //받아온 값을 기준에 맞게 들어가고 jwt기준에 맞게 디코드해줄 거야
                   DecodedJWT decodedJWT =verifier.verify(token);
                   //알고리즘 안뜨면 implementation 'com.auth0:java-jwt:3.18.2' 이거 붙여줘야 함. 확인필요
                   //이제 롤(ROLE) 처리할 꺼임
                   String userName = decodedJWT.getSubject();
                   //여기까지가 이름처리


                   String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
                   //이제 호출
                   Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
                   //아래 스트림 설정하는 방법 틀렸음.
                   Arrays.stream(roles).forEach((role -> {
                       authorities.add(new SimpleGrantedAuthority(role));
                   }));
                   //여기까지가 롤처리

                   //이제부터 패스워드처리
                   UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userName, null, authorities);
                   SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                   filterChain.doFilter(request, response);
                   //여기까지가 1단계 처리
               }
               //예외처리
               catch(Exception exception){
                   log.error("Error logging in : {}", exception.getMessage());
                   response.setHeader("error", exception.getMessage());
                   response.setStatus(FORBIDDEN.value()); //서버에서 프론트한테 원하는 데로 메세지 날릴 수 있음.
                   //response.setStatus(org.springframework.http.HttpStatus.Forbiddenvalue 치면됨 그러고 애드);
                   Map<String , String > error = new HashMap<>();
                   error.put("error_message", exception.getMessage());
                   response.setContentType(APPLICATION_JSON_VALUE);
                   //이제 아래에 생성만해주면 됨.
                   new ObjectMapper().writeValue(response.getOutputStream(),error);
               } //여기까지가 커스텀 authorize가 완성
               //트라이를 했는데 안되면 캐치로 가라 라는 거임.




           }else{
               filterChain.doFilter(request, response);   //주소가 같지만 들어온 값이 아닐때 처리??????????????? 뫄아???
           }
        }
    }
}
