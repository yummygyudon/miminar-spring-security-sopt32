package sopt.miminar.security.domain.login.handler;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.util.StringUtils;
import sopt.miminar.security.domain.jwt.dto.AccessTokenDto;
import sopt.miminar.security.domain.jwt.dto.RefreshTokenDto;
import sopt.miminar.security.domain.jwt.provider.JwtTokenProvider;
import sopt.miminar.security.domain.user.model.UserRepository;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
@Slf4j
public class LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final JwtTokenProvider jwtTokenProvider;




    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request
            , HttpServletResponse response
            , Authentication authentication
    ) throws IOException, ServletException {
        String email = authentication.getPrincipal()
        String token = resolveToken(request);
        if (token != null
                && jwtTokenProvider.validateToken(token)){
            AccessTokenDto accessToken = jwtTokenProvider.generateAccessToken(authentication);
            RefreshTokenDto refreshToken = jwtTokenProvider.generateRefreshToken();
            response.setStatus(HttpServletResponse.SC_OK);

            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        userRepository.findByEmailAndNickname()

    }
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken)
                && bearerToken.startsWith("Bearer")) {
            return bearerToken.substring(6);
        }
        return null;
    }


}
