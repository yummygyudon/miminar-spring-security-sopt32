package sopt.miminar.security.domain.oauth.provider.info;

import lombok.Builder;
import lombok.Getter;
import sopt.miminar.security.domain.oauth.provider.SocialPlatform;
import sopt.miminar.security.domain.user.model.User;
import sopt.miminar.security.domain.user.model.property.Role;

import java.util.Map;
import java.util.UUID;

@Getter
public class OAuth2Attributes {
    private String attributeKey; // OAuth2 로그인 진행 시 키가 되는 필드 값, PK와 같은 의미
    private OAuth2UserInfo oauth2UserInfo; // 소셜 타입별 로그인 유저 정보(닉네임, 이메일, 프로필 사진 등등)

    private OAuth2Attributes(String attributeKey, OAuth2UserInfo oauth2UserInfo) {
        this.attributeKey = attributeKey;
        this.oauth2UserInfo = oauth2UserInfo;
    }

    /**
     * SocialType에 맞는 메소드 호출하여 OAuthAttributes 객체 반환
     * 파라미터 : userNameAttributeName -> OAuth2 로그인 시 키(PK)가 되는 값 / attributes : OAuth 서비스의 유저 정보들
     * 소셜별 of 메소드(ofGoogle, ofKaKao, ofNaver)들은 각각 소셜 로그인 API에서 제공하는
     * 회원의 식별값(id), attributes, nameAttributeKey를 저장 후 build
     */
    @Builder
    public static OAuth2Attributes of(SocialPlatform socialPlatform
            , String userNameAttributeName
            , Map<String, Object> attributes) {

        if (socialPlatform == SocialPlatform.NAVER) {
            return ofNaver(userNameAttributeName, attributes);
        }
        if (socialPlatform == SocialPlatform.KAKAO) {
            return ofKakao(userNameAttributeName, attributes);
        }
        return ofGoogle(userNameAttributeName, attributes);
    }

    private static OAuth2Attributes ofKakao(String attributeKey, Map<String, Object> attributes) {
        return new OAuth2Attributes(attributeKey, new KakaoOAuth2UserInfo(attributes));
    }

    public static OAuth2Attributes ofGoogle(String attributeKey, Map<String, Object> attributes) {
        return new OAuth2Attributes(attributeKey,new GoogleOAuth2UserInfo(attributes));
    }

    public static OAuth2Attributes ofNaver(String attributeKey, Map<String, Object> attributes) {
        return new OAuth2Attributes(attributeKey, new NaverOAuth2UserInfo(attributes));
    }

    /**
     * OAuth2Attributes 객체 생성 이후
     * OAuth2UserInfo에서 socialId(식별값), nickname, email을 가져와서
     * User 로 Build
     * role은 GUEST로 설정
     */
    public User toUserEntity(SocialPlatform socialPlatform, OAuth2UserInfo oauth2UserInfo) {
        return User.builder()
                .socialPlatform(socialPlatform)
                .socialId(oauth2UserInfo.getProviderId())
                .email(UUID.randomUUID() + "@socialUser.com")
                .nickname(oauth2UserInfo.getName())
                .role(Role.USER)
                .build();
    }
}
