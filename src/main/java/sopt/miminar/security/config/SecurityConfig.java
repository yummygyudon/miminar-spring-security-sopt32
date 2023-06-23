package sopt.miminar.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.filter.CorsFilter;
import sopt.miminar.security.domain.jwt.filter.JwtAuthenticationFilter;
import sopt.miminar.security.domain.jwt.provider.JwtTokenProvider;
import sopt.miminar.security.domain.login.filter.CustomUsernamePasswordAuthenticationFilter;
import sopt.miminar.security.domain.login.service.CustomLoginUserService;
import sopt.miminar.security.domain.oauth.service.CustomOAuth2UserService;
import sopt.miminar.security.domain.user.model.UserRepository;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {
    private final CustomLoginUserService customLoginUserService;
//    private final JwtService jwtService;
    private final JwtTokenProvider jwtTokenProvider;
//    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;
//    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
//    private final OAuth2LoginFailureHandler oAuth2LoginFailureHandler;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final AuthenticationConfiguration authenticationConfiguration;
    private final CorsFilter corsFilter;

//    @Bean
//    public AuthenticationManager authenticationManager() throws Exception {
//        return authenticationConfiguration.getAuthenticationManager();
//    }
    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
//        provider.setPasswordEncoder(passwordEncoder());
        provider.setUserDetailsService(customLoginUserService);
        return new ProviderManager(provider);
    }

    /**
     * CustomUsernamePasswordAuthenticationFilter 빈 등록
     * 커스텀 필터를 사용하기 위해 만든 커스텀 필터를 Bean으로 등록
     *
     * setAuthenticationManager(authenticationManager())로
     * 위에서 등록한 AuthenticationManager(ProviderManager) 설정
     *
     * 로그인 성공 시 호출할 handler, 실패 시 호출할 handler로 위에서 등록한 handler 설정
     */
    @Bean
    public CustomUsernamePasswordAuthenticationFilter customUsernamePasswordAuthenticationFilter() throws Exception {
        CustomUsernamePasswordAuthenticationFilter customUsernamePasswordAuthenticationFilter
                = new CustomUsernamePasswordAuthenticationFilter(objectMapper);
        customUsernamePasswordAuthenticationFilter.setAuthenticationManager(authenticationManager());
//        customUsernamePasswordAuthenticationFilter.setAuthenticationSuccessHandler(loginSuccessHandler());
//        customUsernamePasswordAuthenticationFilter.setAuthenticationFailureHandler(loginFailureHandler());
        return customUsernamePasswordAuthenticationFilter;
    }

//    @Bean
//    public JwtAuthenticationFilter jwtAuthenticationProcessingFilter() {
//        return ;
//    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .formLogin().disable() // FormLogin 사용 X
                .httpBasic().disable() // httpBasic 사용 X
                .csrf().disable()
                .headers().frameOptions().disable()
                .and()// csrf 보안 사용 X
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(corsFilter)
                //== URL별 권한 관리 옵션 ==//
                .authorizeRequests()
                .antMatchers("/guest/**")
                .access("hasAnyRole('ROLE_USER','ROLE_GUEST')")
                .antMatchers("/user/**")
                .access("hasRole('ROLE_USER')")

                // 아이콘, css, js 관련
                // 기본 페이지, css, image, js 하위 폴더에 있는 자료들은 모두 접근 가능
                // h2-console까지 설정
//                .antMatchers("/","/css/**","/images/**","/js/**","/favicon.ico","/h2-console/**")
//                .permitAll()
                // 회원가입 접근 가능하도록
                // 설정 안하면 처음 서버 켰을 때 DB에 회원정보가 없을 뿐더러
                // DB 자원 접근 권한조차도 없어서 못들어갑니다.
//                .antMatchers("/register").permitAll()
//                .antMatchers("/login").permitAll()
//                .anyRequest().authenticated() // 위의 경로 이외에는 모두 인증된 사용자만 접근 가능
                .anyRequest().permitAll()
                .and()
                //== 소셜 로그인 설정 ==//
                .oauth2Login()
//                .successHandler(oAuth2LoginSuccessHandler) // 동의하고 계속하기를 눌렀을 때 Handler 설정
//                .failureHandler(oAuth2LoginFailureHandler) // 소셜 로그인 실패 시 핸들러 설정
                .userInfoEndpoint().userService(customOAuth2UserService)
                ;
        // 원래 스프링 시큐리티 필터 순서가 LogoutFilter 이후에 로그인 필터 동작
        // 따라서, LogoutFilter 이후에 우리가 만든 필터 동작하도록 설정
        // 순서 : LogoutFilter -> JwtAuthenticationProcessingFilter -> CustomJsonUsernamePasswordAuthenticationFilter
        http.addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class);
//        http.addFilterAfter(customUsernamePasswordAuthenticationFilter(), LogoutFilter.class);

        return http.build();
    }
}
