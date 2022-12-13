package test.test.configs;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import test.test.signature.RSASecuritySigner;

/**
 * jwk를 생성해주는 config
 */
@Configuration
public class SignatureConfig {

    @Bean
    public RSASecuritySigner rsaSecuritySigner() {
        return new RSASecuritySigner();
    }

    /**
     * 알고리즘과 키 id를 정의해서 빈 생성
     * 비공개 키도 생성
     * 비대칭 키를 위해 jwk 객체를 빈으로 생성
     * */
    @Bean
    public RSAKey rsaKey256() throws JOSEException {
        return new RSAKeyGenerator(2048)
                .keyID("rsaKey")
                .algorithm(JWSAlgorithm.RS512)
                .generate();
    }
}