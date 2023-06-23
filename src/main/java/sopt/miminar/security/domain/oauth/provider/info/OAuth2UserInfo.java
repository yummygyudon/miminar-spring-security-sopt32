package sopt.miminar.security.domain.oauth.provider.info;

import sopt.miminar.security.domain.oauth.provider.SocialPlatform;

public interface OAuth2UserInfo {
    String getProviderId();

    SocialPlatform getProvider();

    String getEmail();

    String getName();
}
