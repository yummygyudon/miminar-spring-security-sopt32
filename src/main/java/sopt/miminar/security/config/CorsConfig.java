package sopt.miminar.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                // 외부에서 들어오는 모든 URL 허용
                .allowedOrigins("/*")
                // 모든 HTTP Method 요청 허용
                .allowedMethods("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
                // 모든 헤더 요소 허용
                .allowedHeaders("*")
                // 모든 자격 증명 허용
                .allowCredentials(true)
                // 허용시간
                .maxAge(3600)
        ;
    }

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration configuration = new CorsConfiguration();
        // 본 서버가 응답을 할 때 Json을 JS에서 처리할 수 있도록 하는 설정
        configuration.setAllowCredentials(true);

        // 모든 IP에 응답 허용
        configuration.addAllowedOrigin("*");

        // 모든 Header에 응답 허용
        configuration.addAllowedHeader("*");

        // 모든 HTTP Method에 응답 허용
        configuration.addAllowedMethod("*");
        source.registerCorsConfiguration("/api/**", configuration);
        return new CorsFilter(source);
    }
}
