package test.test.filter.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import test.test.dto.LoginDto;
import test.test.signature.SecuritySigner;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private HttpSecurity httpSecurity;
    private SecuritySigner securitySigner;
    private JWK jwk;

    /**
     * 알고리즘과 SINGER를 추상적으로 받아 처리
     * */
    public JwtAuthenticationFilter(HttpSecurity httpSecurity, SecuritySigner securitySigner, JWK jwk) {
        this.httpSecurity = httpSecurity;
        this.securitySigner = securitySigner;
        this.jwk = jwk;
    }

    /**
     * username과 password를 받아 해결
     * */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        AuthenticationManager authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);

        ObjectMapper objectMapper = new ObjectMapper();
        LoginDto loginDto = null;
        try {

            loginDto = objectMapper.readValue(request.getInputStream(), LoginDto.class);

        } catch (Exception e) {
            e.printStackTrace();
        }
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());
        Authentication authentication = authenticationManager.authenticate(authenticationToken);

        return authentication;
    }

    /**
     * 토큰을 발행하는 코드 작성
     * */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws ServletException, IOException {

        User user = (User) authResult.getPrincipal();

        String jwtToken;
        try {

            //securitySigner를 통해 jwk 토큰을 받아옴
            jwtToken = securitySigner.getJwtToken(user, jwk);

            //발행받은 토큰을 response 헤더에 담아 응답
            response.addHeader("Authorization", "Bearer " + jwtToken);
        } catch (JOSEException e) {
            e.printStackTrace();
        }
    }
}
