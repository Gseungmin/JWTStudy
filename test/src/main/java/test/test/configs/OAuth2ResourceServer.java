package test.test.configs;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import test.test.filter.authentication.JwtAuthenticationFilter;
import test.test.filter.authorization.JwtAuthorizationFilter;
import test.test.filter.authorization.JwtAuthorizationRsaFilter;
import test.test.signature.RSASecuritySigner;
import test.test.web.service.CustomUserDetailsService;

import java.util.Arrays;

@EnableWebSecurity
public class OAuth2ResourceServer {

    @Autowired
    private RSASecuritySigner rsaSecuritySigner;

    @Autowired
    private RSAKey rsaKey;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.authorizeRequests((requests) -> requests.antMatchers("/login","/").permitAll().anyRequest().authenticated());

        /**
         * 모든 과정을 시큐리티에 맡김
         * jwtDecoder가 생성되어 인가서버로부터 jwtSet을 가지고 옴
         * jwtSet안에서 토큰을 검증할 수 있는 Public 키를 가지고 옴
         * 그리고 선택된 Public 키를 가지고 검증
         */
        //사용자 정보 로드해서 객체 생성
        http.userDetailsService(userDetailsService);

        http.oauth2ResourceServer().jwt();
        //인증 필터
        http.addFilterBefore(new JwtAuthenticationFilter(http, rsaSecuritySigner, rsaKey), UsernamePasswordAuthenticationFilter.class);
        //토큰 검증 필터
//        http.addFilterBefore(new JwtAuthorizationRsaFilter(rsaKey), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

//    @Bean
//    public JwtAuthorizationFilter jwtAuthorizationFilter(RSAKey rsaKey) {
//        return new JwtAuthorizationRsaFilter(rsaKey);
//    }

//    private UserDetailsService getUserDetailsService() {
//        User user = new User("user", "1234", Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));
//        InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager(user);
//        return userDetailsManager;
//    }

    //패스워드 인코드 하지 않음
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
