package test.test.signature;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

public abstract class SecuritySigner {

    /**
     * jwk 안에는 대칭키와 비대칭 키 정보가 존재
     * 대칭키 비대칭키와 관계없이 이 메소드를 통해 토큰 발행
     */
    public String getJwtTokenInternal(JWSSigner jwsSigner, UserDetails user, JWK jwk) throws JOSEException {

        JWSHeader header= new JWSHeader.Builder((JWSAlgorithm) jwk.getAlgorithm()).keyID(jwk.getKeyID()).build();

        List<String> authority = user.getAuthorities().stream().map(auth -> auth.getAuthority()).collect(Collectors.toList());
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject("user")
                .issuer("http://localhost:8081")
                .claim("username", user.getUsername())
                .claim("authority", authority)
                .expirationTime(new Date(new Date().getTime() + 60 * 1000 * 60))
                .build();

        /**
         * jwk에서 jws 알고리즘, ketId 가져올 수 있고 이를 통해 Header 구성
         * playload는 jwtClaimSet으로 가져올 수 있음
         * 따라서 최종 서명 객체가 SignedJWT 객체
         */
        SignedJWT signedJWT = new SignedJWT(header, jwtClaimsSet);
        signedJWT.sign(jwsSigner);
        String jwtToken = signedJWT.serialize();

        //서명에 성공하면 JWT 토큰 발행
        return jwtToken;
    }

    //UserDetails가 UserDetailsService 에서 반환된 User 객체
    public abstract String getJwtToken(UserDetails user, JWK jwk) throws JOSEException;
}
