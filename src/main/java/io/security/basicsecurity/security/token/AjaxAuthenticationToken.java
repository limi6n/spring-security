package io.security.basicsecurity.security.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class AjaxAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal;
    private Object credentials;

    /**
     * 인증 받기 전 사용자가 입력하는 로그인 정보를 담는 생성자
     *
     * @param principal
     * @param credentials
     */
    public AjaxAuthenticationToken(Object principal, Object credentials) {
        super(null);
        this.principal = principal;
        this.credentials = credentials;
        setAuthenticated(false);
    }

    /**
     * 인증 이후 인증에 성공한 로그인 정보를 담는 생성자
     *
     * @param principal
     * @param credentials
     * @param authorities
     */
    public AjaxAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        super.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }
}
