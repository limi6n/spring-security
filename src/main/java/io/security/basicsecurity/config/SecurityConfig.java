package io.security.basicsecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //인가정책
        http
                .authorizeRequests()
                .anyRequest().authenticated();
        //인증정책
        // 로그인 성공 후 핸들러
        // 로그인 실패 후 핸들러
        http
                .formLogin()
//                .loginPage("/loginPage")                            // 사용자 정의 로그인 페이지
                .defaultSuccessUrl("/")                              // 로그인 성공 후 이동 페이지
                .failureForwardUrl("/login")                         // 로그인 실패 후 이동 페이지
                // UI 화면과 동일하게 구성 ==========================
                .usernameParameter("userId")                         // 아이디 파라미터명 설정
                .passwordParameter("passwd")                         // 패스워드 파라미터명 설정
                .loginProcessingUrl("/login_proc")                   // 로그인 Form Action Url
                // ============================================
                .successHandler((httpServletRequest, httpServletResponse, authentication) -> { // 로그인 성공 후 핸들러
                    System.out.println("authentication" + authentication.getName());
                    httpServletResponse.sendRedirect("/"); // 성공 후 이동 페이지
                })
                .failureHandler((httpServletRequest, httpServletResponse, e) -> { //로그인 실패 후 핸들러
                    System.out.println("exception" + e.getMessage());
                    httpServletResponse.sendRedirect("/login"); // 실패 후 이동 페이지
                })
                .permitAll() //loginPage 에 접근하는 사용자는 인증 없이 접근이 가능하도록 함
        ;
    }
}
