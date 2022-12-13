package test.test.filter.authorization;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.UUID;

/**
 * Bearer 토큰을 RSA 알고리즘에 의해 검증하며 검증 성공시 인증 및 인가를 처리하는 필터
 */
public class JwtAuthorizationRsaFilter extends JwtAuthorizationFilter {

    private RSAKey jwk;

    public JwtAuthorizationRsaFilter(RSAKey rsaKey) {
        this.jwk = rsaKey;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        /**
         * 헤더가 유효성 검사에 실패하면 다음 필터로 이동
         */
        if (tokenResolve(request, response, chain)){
            chain.doFilter(request,response);
            return;
        }

        /**
         * Bearer를 제거한 토큰 값만 추출(header + payload + signature)
         * */
        String token = getToken(request);

        SignedJWT signedJWT;
        try {

            /**
             * header와 payload와 signature 값이 속성으로 매핑됨
             */
            signedJWT = SignedJWT.parse(token);

            RSASSAVerifier jwsVerifier = new RSASSAVerifier(jwk.toRSAPublicKey());
            /**
             * 검증 로직
             * 여러 verifier 종류가 존재하는데 주입 받은 값으로 검증
             */
            boolean verify = signedJWT.verify(jwsVerifier);
            System.out.println("verify = " + verify);

            if (verify) {
                /**
                 * 인증 처리시 username과 authority가 필요
                 * 토큰 발행시 username과 authority는 claim 정보에 포함시켰음
                 * 따라서 claim 정보로부터 username과 authority를 가져올 수 있음
                 */
                String username = signedJWT.getJWTClaimsSet().getClaim("username").toString();
                List<String> authority = (List)signedJWT.getJWTClaimsSet().getClaim("authority");

                /**
                 * 사용자 정보를 만들어서 인증 객체 생성 후 Security Context에 보관
                 * */
                if (username != null) {

                    UserDetails user = User.builder().username(username)
                            .password(UUID.randomUUID().toString())
                            .authorities(authority.get(0))
                            .build();
                    //권한이 하나밖에 없으므로 get(0)

                    Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        chain.doFilter(request, response);
    }

    /**
     * Authorization 헤더 명으로 값이 넘어옴
     */
    protected String getToken(HttpServletRequest request) {
        return request.getHeader("Authorization").replace("Bearer ", "");
    }

    /**
     * 헤더 유효성 검상
     */
    protected boolean tokenResolve(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String header = request.getHeader("Authorization");
        return header == null || !header.startsWith("Bearer ");
    }
}
