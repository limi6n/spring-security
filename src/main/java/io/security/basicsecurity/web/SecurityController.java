package io.security.basicsecurity.web;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index(HttpSession session) {

        // SecurityContextHolder 에서 확인 한 인증 객체
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // HttpSession 에 저장 된 SecruityContext 안에 있는 인증 객체
        SecurityContext context = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication1 = context.getAuthentication();

        // 두 인증 객체가 주소값이 같은 것을 확인 할 수 있었다.

        return "home";
    }

    @GetMapping("/thread")
    public String thread() {
        // 1. MODE_THREADLOCAL 일 때 부모-자식 간 스레드 참조 안되는 거 확인
        // 2. MODE_INHERITABLETHREADLOCAL 설정 후(SpringSecurity에서 설정) 확인
        new Thread( // 자식 스레드 생성
                new Runnable() {
                    @Override
                    public void run() {
                        // 1. 일 때, 결과 null
                        // 2. 일 때, 메인쓰레드에서 생성된 인증객체가 저장되어 있었음.
                        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                    }
                }
        ).start();
        return "thread";
    }
}
