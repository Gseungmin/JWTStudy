package test.test.web.service;

import com.nimbusds.jose.JOSEException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import test.test.web.repository.MemberRepository;

import java.util.ArrayList;
import java.util.List;

//@Service
//@Transactional
//@RequiredArgsConstructor
//public class MemberService {
//
//    private final MemberRepository memberRepository;
//    private final AuthenticationManagerBuilder authenticationManagerBuilder;
//
//
//    public JwtTokenDto login(String memberId, String password) throws JOSEException {
//
//        Optional<Member> findMember = memberRepository.findByMemberId(memberId);
//        if (findMember.isEmpty()) {
//            List<String> roles = new ArrayList<>();
//            roles.add("USER");
//            Member member = new Member(memberId, password, roles);
//            memberRepository.save(member);
//        }
//
//        // 1. Login ID/PW 를 기반으로 Authentication 객체 생성
//        // 이때 authentication 는 인증 여부를 확인하는 authenticated 값이 false
//        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(memberId, password);
//
//        System.out.println("authenticationToken = " + authenticationToken);
//
//        // 2. 실제 검증 (사용자 비밀번호 체크)이 이루어지는 부분
//        // authenticate 매서드가 실행될 때 CustomUserDetailsService 에서 만든 loadUserByUsername 메서드가 실행
//        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
//
//        System.out.println("authentication = " + authentication);
//
//        // 3. 인증 정보를 기반으로 JWT 토큰 생성
//        JwtTokenDto jwt= jwtTokenProvider.generateToken(authentication);
//
//        System.out.println("jwt = " + jwt);
//
//        return jwt;
//    }
//}
