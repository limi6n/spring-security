package io.security.basicsecurity.security.voter;

import io.security.basicsecurity.service.SecurityResourceService;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.util.Collection;
import java.util.List;

public class IpAddressVoter implements AccessDecisionVoter<Object> {

    private SecurityResourceService securityResourceService;

    public IpAddressVoter(SecurityResourceService securityResourceService) {
        this.securityResourceService = securityResourceService;
    }

    @Override
    public boolean supports(ConfigAttribute configAttribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return true;
    }

    /**
     * 심의 로직 구현
     *
     * @param authentication 사용자 인증정보
     * @param object 요청정보(FilterInvocation)
     * @param collection 자원에 접근을 위한 권한정보를 얻을 수 있음(FilterInvocationMetadataSource)
     * @return
     */
    @Override
    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> collection) {

        // 사용자 Ip 가져오기
        WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.getDetails();
        String remoteAddress = details.getRemoteAddress();

        List<String> accessIpList = securityResourceService.getAccessIpList();

        int result = ACCESS_DENIED;

        // 사용자 Ip와 허용 Ip 가 같을 경우
        for(String ipAddress : accessIpList) {
            if(remoteAddress.equals(ipAddress)) {
                return ACCESS_ABSTAIN;
            }
        }

        // 허용된 ip가 아닐 경우 예외 던짐
        if (result == ACCESS_DENIED) {
            throw new AccessDeniedException("Invalid IpAddress");
        }

        return result;
    }
}
