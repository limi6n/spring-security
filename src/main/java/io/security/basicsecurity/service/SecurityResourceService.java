package io.security.basicsecurity.service;

import io.security.basicsecurity.domain.entity.Resources;
import io.security.basicsecurity.repository.AccessIpRepository;
import io.security.basicsecurity.repository.ResourcesRepository;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

@Service
public class SecurityResourceService {

    private ResourcesRepository resourcesRepository;

    public SecurityResourceService(ResourcesRepository resourcesRepository) {
        this.resourcesRepository = resourcesRepository;
    }

    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList(){

        // DB로부터 권한정보를 가져와서 mapping
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result = new LinkedHashMap<>();
        List<Resources> resourcesList = resourcesRepository.findAllResources();
        resourcesList.forEach(re ->{
            List<ConfigAttribute> configAttributeList =  new ArrayList<>();
            re.getRoleSet().forEach(role -> configAttributeList.add(new SecurityConfig(role.getRoleName())));
            result.put(new AntPathRequestMatcher(re.getResourceName()),configAttributeList);

        });
        return result;
    }

}
