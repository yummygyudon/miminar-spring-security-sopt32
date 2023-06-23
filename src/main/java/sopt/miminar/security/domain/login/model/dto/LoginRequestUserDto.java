package sopt.miminar.security.domain.login.model.dto;


import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class LoginRequestUserDto {

    @JsonProperty("email")
    private String userId;
    private String password;
}
