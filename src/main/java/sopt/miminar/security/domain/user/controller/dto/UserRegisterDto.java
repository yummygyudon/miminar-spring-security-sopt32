package sopt.miminar.security.domain.user.controller.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
public class UserRegisterDto {
    private String email;
    private String password;
    private String nickname;
}
