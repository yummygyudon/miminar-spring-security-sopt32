package sopt.miminar.security.domain.jwt.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Builder
@Data
@AllArgsConstructor
public class AccessTokenDto {
    //grantType은 jwt에 대한 인증 타입, 여기선 bearer 사용 - 이에 대한 설명 더 덧붙이기
    private String grantType;
    private String accessToken;
}
