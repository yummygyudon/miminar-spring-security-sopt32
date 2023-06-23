package sopt.miminar.security.domain.user.model;

import lombok.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import sopt.miminar.security.domain.user.model.property.Role;
import sopt.miminar.security.domain.oauth.provider.SocialPlatform;

import javax.persistence.*;

@Getter
@Entity
@Builder
//@Table(name = "USERS")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PROTECTED)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;


    private String email; // 이메일
    private String username;
    private String password; // 비밀번호
    private String nickname; // 닉네임

    @Enumerated(EnumType.STRING)
    private Role role;

    @Enumerated(EnumType.STRING)
    private SocialPlatform socialPlatform; // KAKAO, NAVER, GOOGLE

    // 로그인한 소셜 타입의 식별자 값 (일반 로그인인 경우 null)
    private String socialId;

    private String refreshToken; // 리프레시 토큰

    // 유저 권한 설정 메소드
    public void authorizeAdmin() {
        this.role = Role.ADMIN;
    }

    // 비밀번호 암호화 메소드
    public void passwordEncode(BCryptPasswordEncoder passwordEncoder) {
        this.password = passwordEncoder.encode(this.password);
    }
}
