package io.security.basicsecurity.security.configs;

import io.security.basicsecurity.security.common.FormAuthenticationDetailsSource;
import io.security.basicsecurity.security.factory.UrlResourcesMapFactoryBean;
import io.security.basicsecurity.security.filter.PermitAllFilter;
import io.security.basicsecurity.security.handler.FormAccessDeniedHandler;
import io.security.basicsecurity.security.metadatasource.UrlFilterInvocationSecurityMetadataSource;
import io.security.basicsecurity.security.provider.FormAuthenticationProvider;
import io.security.basicsecurity.security.voter.IpAddressVoter;
import io.security.basicsecurity.service.SecurityResourceService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@Slf4j
@Order(1)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private FormAuthenticationDetailsSource authenticationDetailsSource;

    @Autowired
    private AuthenticationSuccessHandler formAuthenticationSuccessHandler;

    @Autowired
    private AuthenticationFailureHandler formAuthenticationFailureHandler;

    @Autowired
    private SecurityResourceService securityResourceService;

    // 인증이나 인가가 필요없는 자원들 설정
    private String[] permitAllResources = {"/", "/login", "/user/login/**"};

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("*/**").permitAll()
                .anyRequest().authenticated()
        .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .authenticationDetailsSource(authenticationDetailsSource)
                .defaultSuccessUrl("/")
                .successHandler(formAuthenticationSuccessHandler)
                .failureHandler(formAuthenticationFailureHandler)
                .permitAll()
        .and()
                .addFilterBefore(customFilterSecurityInterceptor(), FilterSecurityInterceptor.class)
                .exceptionHandling()
                .accessDeniedPage("/denied")
                .accessDeniedHandler(accessDeniedHandler())

        ;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(authenticationProvider());
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        // 구현한 FormAuthenticationProvider 연결
        return new FormAuthenticationProvider(passwordEncoder());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // 평문을 암호화 해줌
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        FormAccessDeniedHandler accessDeniedHandler = new FormAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");
        return accessDeniedHandler;
    }

    @Bean
    public PermitAllFilter customFilterSecurityInterceptor() throws Exception {
        PermitAllFilter permitAllFilter = new PermitAllFilter(permitAllResources);
        permitAllFilter.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource());
        permitAllFilter.setAccessDecisionManager(affirmativeBased());
        permitAllFilter.setAuthenticationManager(authenticationManagerBean());
        return permitAllFilter;
    }

    private AccessDecisionManager affirmativeBased() {
        AffirmativeBased affirmativeBased = new AffirmativeBased(getAccessDecisionVoters());
        return affirmativeBased;

    }

    private List<AccessDecisionVoter<?>> getAccessDecisionVoters() {

        List<AccessDecisionVoter<? extends Object>> accessDecisionVoters = new ArrayList<>();
        accessDecisionVoters.add(new IpAddressVoter(securityResourceService)); // 허용 ip 여부 심사(가장먼저 있어야함)
        accessDecisionVoters.add(roleVoter()); // 설정한 권한 포맷팅 넣기

        return accessDecisionVoters;
    }

    @Bean
    public AccessDecisionVoter<? extends Object> roleVoter() {

        RoleHierarchyVoter roleHierarchyVoter = new RoleHierarchyVoter(roleHierarchy());
        return roleHierarchyVoter;
    }

    @Bean
    public RoleHierarchyImpl roleHierarchy() {
        // 구현체가 가지고 있는 메소드가 있기 때문에 Impl로 리턴(인터페이스에는 없음)
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        return roleHierarchy;
    }

    @Bean
    public UrlFilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource() throws Exception {
        return new UrlFilterInvocationSecurityMetadataSource(urlResourcesMapFactoryBean().getObject(), securityResourceService);
    }

    private UrlResourcesMapFactoryBean urlResourcesMapFactoryBean() {
        UrlResourcesMapFactoryBean urlResourcesMapFactoryBean = new UrlResourcesMapFactoryBean();
        urlResourcesMapFactoryBean.setSecurityResourceService(securityResourceService);

        return urlResourcesMapFactoryBean;
    }

}
