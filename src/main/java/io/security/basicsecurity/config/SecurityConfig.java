package io.security.basicsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;

import javax.servlet.http.HttpSession;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

   @Autowired
    private UserDetailsService userDetailsService;

    protected void configure(HttpSecurity http) throws Exception {
        // 인가정책
        http
                .authorizeRequests()
                .anyRequest().authenticated()
        // 인증정책
        .and()
                .formLogin()
//                .loginPage("/loginPage")                            // 사용자 정의 로그인 페이지
                .defaultSuccessUrl("/")                              // 로그인 성공 후 이동 페이지
                .failureForwardUrl("/login")                         // 로그인 실패 후 이동 페이지
                .usernameParameter("userId")                         // 아이디 파라미터명 설정
                .passwordParameter("passwd")                         // 패스워드 파라미터명 설정
                .loginProcessingUrl("/login_proc")                   // 로그인 Form Action Url
                .successHandler((httpServletRequest, httpServletResponse, authentication) -> { // 로그인 성공 후 핸들러
                    System.out.println("authentication" + authentication.getName());
                    httpServletResponse.sendRedirect("/"); // 성공 후 이동 페이지
                })
                .failureHandler((httpServletRequest, httpServletResponse, e) -> { //로그인 실패 후 핸들러
                    System.out.println("exception" + e.getMessage());
                    httpServletResponse.sendRedirect("/login"); // 실패 후 이동 페이지
                })
                .permitAll() //loginPage 에 접근하는 사용자는 인증 없이 접근이 가능하도록 함
        .and()
                .logout()                                       // 로그아웃 처리
                .logoutUrl("/logout")                           // 로그아웃 처리 URL
                .logoutSuccessUrl("/login")                     // 로그아웃 성공 후 이동페이지
                .deleteCookies("JESSONID", "remember-me")       // 로그아웃 후 쿠키 삭제
                .addLogoutHandler((httpServletRequest, httpServletResponse, authentication) -> { //로그아웃 핸들러
                    HttpSession httpSession = httpServletRequest.getSession();
                    httpSession.invalidate(); // 세션 무효화
                })
                .logoutSuccessHandler((httpServletRequest, httpServletResponse, authentication) -> { // 로그아웃 성공 후 핸들러
                    httpServletResponse.sendRedirect("/login"); // 로그아웃 후 이동페이지
                })
        .and()
                .rememberMe()
                .rememberMeParameter("remember")            // 기본 파라미터명은 remember-me
                .tokenValiditySeconds(3600)                 // 쿠키 만료 시간(Default 14일)
                .userDetailsService(userDetailsService);  // 리멤버 미 기능을 수행할 때 시스템에 있는 사용자 계정을 조회
    }
}
