package test.test.filter.authorization;

import com.nimbusds.jose.jwk.JWK;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * OncePerRequestFilter는 동일한 요청에 대해서 한번만 실행되도록 처리하는 필터
 * */
public abstract class JwtAuthorizationFilter extends OncePerRequestFilter {

	private JWK jwk;

	/**
	 * 대칭 키 또는 비대칭 키를 추상화하기 위한 생성자
	 */

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

    }
}
