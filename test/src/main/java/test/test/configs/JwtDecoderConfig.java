package test.test.configs;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

@Configuration
public class JwtDecoderConfig {


    /**
     * PublicKey 기반 JwtDecoder 생성
     * 비대칭키 방식으로 생성된 토큰을 검증하기 위해 JWK를 상속한 RSAKey로 PublicKey 기반 JwtDecoder를 생성
     * 따라서 ConditionalOnProperty 조건에 해당하면 해당 JWTDecoder 빈 생성
     * 클라이언트가 토큰을 리소스 서버로 보내면 리소스 서버는 JWTDecoder를 가지고 검증하게 됨
     */
    @Bean
    @ConditionalOnProperty(prefix = "spring.security.oauth2.resourceserver.jwt", name = "jws-algorithms", havingValue = "RS512", matchIfMissing = false)
    public JwtDecoder jwtDecoderByPublicKeyValue(RSAKey rsaKey, OAuth2ResourceServerProperties properties) throws JOSEException {
        //public 키 기반으로 검증하는 JWTDecoder 객체 생성, 토큰이 private 키로 암호화 되어 있으므로
        return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey())
                .signatureAlgorithm(SignatureAlgorithm.from(properties.getJwt().getJwsAlgorithms().get(0)))
                .build();
    }
}
