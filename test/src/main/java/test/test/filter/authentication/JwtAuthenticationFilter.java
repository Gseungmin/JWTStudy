package test.test.filter.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.googleapis.util.Utils;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import lombok.SneakyThrows;
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
import javax.servlet.http.HttpSession;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.util.Collections;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private HttpSecurity httpSecurity;
    private SecuritySigner securitySigner;
    private JWK jwk;

    private static Integer GOOGLE = 0;
    private static Integer KAKAO = 1;
    private static Integer BASIC = 2;

    private String email;
    private String password;

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
    @SneakyThrows
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        /**로그인 방식 Check*/
        Integer Case = loginCaseCheck(request);

        if (Case == GOOGLE) {

            /**idToken Check Function*/
            GoogleIdToken idToken = checkGoogleIdToken(request);

            if (idToken != null) {
                GoogleIdToken.Payload payload = idToken.getPayload();

                //user identifier
                String userId = payload.getSubject();
                // Get profile information from payload
                String name = payload.getEmail();

                email = name;
                password = userId;
            } else {
                throw new IllegalArgumentException("Invalid ID token.");
            }
        } else if (Case == KAKAO) {

            String reqURL = "https://kapi.kakao.com/v2/user/me";

            String accessToken = request.getHeader("Authorization");
            System.out.println("accessToken = " + accessToken);

            try {
                URL url = new URL(reqURL);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();

                conn.setRequestMethod("POST");
                conn.setDoOutput(true);
                conn.setRequestProperty("Authorization", "Bearer " + accessToken);

                BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                String line = "";
                String result = "";

                while ((line = br.readLine()) != null) {
                    result += line;
                }

                System.out.println("response body : " + result);

                JsonElement element = JsonParser.parseString(result);

                String id = element.getAsJsonObject().get("kakao_account").getAsJsonObject().get("email").getAsString();

                email = id;
                password = "117069320589700689011";

                br.close();
            } catch (IOException exception) {
                exception.printStackTrace();
            }
        } else if (Case == BASIC) {
            ObjectMapper objectMapper = new ObjectMapper();
            LoginDto loginDto = null;
            try {

                loginDto = objectMapper.readValue(request.getInputStream(), LoginDto.class);

                email = loginDto.getUsername();
                password = loginDto.getPassword();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        AuthenticationManager authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(email, password);
        Authentication authentication = authenticationManager.authenticate(authenticationToken);

        return authentication;
    }

    private Integer loginCaseCheck(HttpServletRequest request) {
        String value = request.getHeader("LoginCase").toString();
        if (value.equals("google")) {
            System.out.println("google login start");
            return 0;
        } else if (value.equals("kakao")) {
            System.out.println("kakao login start");
            return 1;
        }
        System.out.println("basic login start");
        return 2;
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


    /**
     * Check Google Id Token
     * */
    public GoogleIdToken checkGoogleIdToken(HttpServletRequest request) throws GeneralSecurityException, IOException {

        HttpTransport transport = Utils.getDefaultTransport();
        JsonFactory jsonFactory = Utils.getDefaultJsonFactory();

        GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(transport, jsonFactory)
                .setAudience(Collections.singletonList("162441855133-gd4n562pio08v1jtjrcnlrvo7o35d0c7.apps.googleusercontent.com"))
                .build();

        String token = request.getHeader("Authorization");
        GoogleIdToken idToken = verifier.verify(token);

        return idToken;
    }
}
