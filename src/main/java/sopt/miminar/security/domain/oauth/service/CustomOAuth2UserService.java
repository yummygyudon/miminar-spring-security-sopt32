package sopt.miminar.security.domain.oauth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import sopt.miminar.security.domain.oauth.provider.CustomOAuth2User;
import sopt.miminar.security.domain.oauth.provider.SocialPlatform;
import sopt.miminar.security.domain.oauth.provider.info.OAuth2Attributes;
import sopt.miminar.security.domain.user.model.User;
import sopt.miminar.security.domain.user.model.UserRepository;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;

    private SocialPlatform getSocialPlatform(String registrationId) {
        if("naver".equals(registrationId)) {
            return SocialPlatform.NAVER;
        }
        if("kakao".equals(registrationId)) {
            return SocialPlatform.KAKAO;
        }
        return SocialPlatform.GOOGLE;
    }

    private User getUser(OAuth2Attributes attributes, SocialPlatform socialPlatform) {
        User findedUser = userRepository.findBySocialPlatformAndSocialId(
                socialPlatform
                , attributes.getOauth2UserInfo().getProviderId()
        ).orElse(null);
        if (Objects.isNull(findedUser)) {
            return saveUser(attributes, socialPlatform);
        }
        return findedUser;
    }
    private User saveUser(OAuth2Attributes attributes, SocialPlatform socialPlatform) {
        User createdUser = attributes.toUserEntity(
                socialPlatform
                , attributes.getOauth2UserInfo()
        );
        return userRepository.save(createdUser);
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("CustomOAuth2UserService.loadUser() : OAuth2 로그인 요청");
        /**
         * - DefaultOAuth2UserService.loadUser(userRequest) -> DefaultOAuth2User 객체를 생성 & 반환
         *      - 소셜 로그인 API의 사용자 정보 제공 URI로 요청을 보내서 사용자 정보 취득 -> DefaultOAuth2User 객체를 생성 후 반환
         *      - OAuth2User : OAuth 서비스에서 가져온 유저 정보를 담고 있는 유저
         */
        OAuth2UserService<OAuth2UserRequest, OAuth2User> defaultOAuth2UserService = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = defaultOAuth2UserService.loadUser(userRequest);

        /**
         * userRequest -> registrationId 추출 & registrationId 을 통해 해당하는 SocialType 저장
         * ex. http://localhost:8080/oauth2/authorization/kakao -> registrationId : kakao
         *
         */
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        SocialPlatform socialPlatform = getSocialPlatform(registrationId);

        // 소셜 로그인에서 API가 제공하는 userInfo Json 값(유저 정보들)
        Map<String, Object> attributes = oAuth2User.getAttributes();
        /**
         * OAuth2 로그인 시 키(PK)가 되는 값 : userNameAttributeName
         * userNameAttributeName -> attributeKey로 설정된다.
         */
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails()
                .getUserInfoEndpoint()
                .getUserNameAttributeName();

        // socialType에 따라 유저 정보를 통해 OAuthAttributes 객체 생성
        OAuth2Attributes oAuth2Attributes = OAuth2Attributes.of(
                socialPlatform
                , userNameAttributeName
                , attributes
        );

        User oauthUser = getUser(oAuth2Attributes, socialPlatform); // getUser() 메소드로 User 객체 생성 후 반환

        // DefaultOAuth2User를 구현한 CustomOAuth2User 객체를 생성해서 반환
        return new CustomOAuth2User(
                // 가진 권한들로 이루어진 Set 객체를 생성
                Collections.singleton(new SimpleGrantedAuthority(oauthUser.getRole().getRole())),
                attributes,
                oAuth2Attributes.getAttributeKey(),
                oauthUser.getEmail(),
                oauthUser.getRole()
        );
    }

    /**
     * SocialType과 attributes에 들어있는 소셜 로그인의 식별값 id를 통해 회원을 찾아 반환하는 메소드
     * 만약 찾은 회원이 있다면, 그대로 반환하고 없다면 saveUser()를 호출하여 회원을 저장한다.
     */
//    private User getUser(OAuth2Attributes attributes, SocialPlatform socialPlatform) {
//        User findUser = userRepository.findBySocialPlatformAndSocialId(
//                socialPlatform
//                , attributes.getOauth2UserInfo().getProviderId()).orElse(null);
//
//        if(findUser == null) {
//            return saveUser(attributes, socialPlatform);
//        }
//        return findUser;
//    }

    /**
     * OAuthAttributes의 toEntity() 메소드를 통해 빌더로 User 객체 생성 후 반환
     * 생성된 User 객체를 DB에 저장 : socialType, socialId, email, role 값만 있는 상태
     */

}
