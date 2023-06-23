package sopt.miminar.security.domain.user.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import sopt.miminar.security.domain.jwt.dto.AccessTokenDto;
import sopt.miminar.security.domain.login.model.dto.LoginRequestUserDto;
import sopt.miminar.security.domain.user.controller.dto.UserRegisterDto;
import sopt.miminar.security.domain.user.service.UserService;

@RequiredArgsConstructor
@RestController
@Slf4j
public class UserController {
    private final UserService userService;

    @PostMapping("/register")
    public String register(@RequestBody final UserRegisterDto userRegisterDto) throws Exception {
        userService.register(userRegisterDto);
        return "자체 플랫폼 회원가입 완료";
    }

    @PostMapping("/login")
    public AccessTokenDto login(@RequestBody LoginRequestUserDto loginRequestUserDto) {
        log.info("login Request Receive");
        String userId = loginRequestUserDto.getUserId();
        String password = loginRequestUserDto.getPassword();
        AccessTokenDto tokenDto = userService.login(userId, password);
        return tokenDto;
    }

    @GetMapping("/guest")
    public
}
