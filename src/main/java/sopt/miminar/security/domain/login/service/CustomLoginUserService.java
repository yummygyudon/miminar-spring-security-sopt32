package sopt.miminar.security.domain.login.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import sopt.miminar.security.domain.login.model.CustomLoginUser;
import sopt.miminar.security.domain.user.model.User;
import sopt.miminar.security.domain.user.model.UserRepository;

@RequiredArgsConstructor
@Service
public class CustomLoginUserService implements UserDetailsService {

    private final UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException{
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다."));
        return new CustomLoginUser(user);
    }
}
