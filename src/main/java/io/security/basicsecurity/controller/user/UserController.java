package io.security.basicsecurity.controller.user;

import io.security.basicsecurity.domain.Account;
import io.security.basicsecurity.domain.AccountDto;
import io.security.basicsecurity.service.UserService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping(value = "/mypage")
    public String myPage() {
        return "user/mypage";
    }

    /**
     * 사용자 등록 페이지로 이동
     * @return 사용자 등록 페이지
     */
    @GetMapping(value = "/users")
    public String createUser() {
        return "user/login/register";
    }

    /**
     * 사용자 등록
     * @param accountDto 사용자 정보
     * @return 등록 후 메인페이지로 이동
     */
    @PostMapping(value = "/users")
    public String createUser(AccountDto accountDto) {

        ModelMapper modelMapper = new ModelMapper();
        Account account = modelMapper.map(accountDto, Account.class);
        account.setPassword(passwordEncoder.encode(account.getPassword())); // 입력 받은 비밀번호 암호화
        userService.createUser(account);

        return "redirect:/";
    }
}
