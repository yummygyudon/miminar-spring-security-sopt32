package sopt.miminar.security.domain.user.model;

import org.springframework.data.jpa.repository.JpaRepository;
import sopt.miminar.security.domain.oauth.provider.SocialPlatform;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findBySocialPlatformAndSocialId(SocialPlatform socialPlatform, String socialId);

        Optional<User> findByUsername(String username);
    Optional<User> findByEmailAndNickname(String email, String nickName);
}
