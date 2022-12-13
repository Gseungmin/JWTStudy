package test.test.signature;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * RSA 방식의 토큰을 서명하고 발행하는 역할
 */
public class RSASecuritySigner extends SecuritySigner {

    public String getJwtToken(UserDetails user, JWK jwk) throws JOSEException {

        //개인키로 서명히고 부모에게 전달
        RSASSASigner jwsSigner = new RSASSASigner(((RSAKey)jwk).toRSAPrivateKey());
        return getJwtTokenInternal(jwsSigner, user, jwk);
    }
}
