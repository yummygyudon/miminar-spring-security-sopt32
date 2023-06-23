package sopt.miminar.security.domain.jwt.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Builder
@Data
@AllArgsConstructor
public class RefreshTokenDto {
    private String grantType;
    private String refreshToken;
}
