package sopt.miminar.security.domain.user.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import sopt.miminar.security.domain.jwt.dto.AccessTokenDto;
import sopt.miminar.security.domain.jwt.provider.JwtTokenProvider;
import sopt.miminar.security.domain.user.controller.dto.UserRegisterDto;
import sopt.miminar.security.domain.user.model.User;
import sopt.miminar.security.domain.user.model.UserRepository;
import sopt.miminar.security.domain.user.model.property.Role;

import javax.transaction.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtTokenProvider jwtTokenProvider;
    private final BCryptPasswordEncoder passwordEncoder;

    @Transactional
    public User register(final UserRegisterDto userRegisterDto) throws Exception {
        if (userRepository.findByEmailAndNickname(
                userRegisterDto.getEmail(), userRegisterDto.getNickname()).isPresent()) {
            throw new Exception("이미 존재하는 회원입니다.");
        }
        User user = User.builder()
                .email(userRegisterDto.getEmail())
                .password(userRegisterDto.getPassword())
                .nickname(userRegisterDto.getNickname())
                .role(Role.USER)
                .build();
        user.passwordEncode(passwordEncoder);
        return userRepository.save(user);
    }


    public AccessTokenDto login(String memberId, String password) {
        // 1. Login ID/PW 를 기반으로 Authentication 객체 생성
        // 이때 authentication 는 인증 여부를 확인하는 authenticated 값이 false
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(memberId, password);

        // 2. 실제 검증 (사용자 비밀번호 체크)이 이루어지는 부분
        // authenticate 매서드가 실행될 때 CustomUserDetailsService 에서 만든 loadUserByUsername 메서드가 실행
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        // 3. 인증 정보를 기반으로 JWT 토큰 생성
        AccessTokenDto tokenDto = jwtTokenProvider.generateAccessToken(authentication);

        return tokenDto;
    }
}
