package io.security.basicsecurity.security.init;

import io.security.basicsecurity.service.RoleHierarchyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.stereotype.Component;

@Component
public class SecurityInitializer implements ApplicationRunner {

    @Autowired
    private RoleHierarchyService roleHierarchyService; // 디비로 부터 포맷팅 된 결과값 가져올 서비스

    @Autowired
    private RoleHierarchyImpl roleHierarchy; // 실제 규칙이 포맷팅 된 데이터를 가진 서비스

    @Override
    public void run(ApplicationArguments args) throws Exception {
        // 설정 한 규칙을 set
        String allHierarchy = roleHierarchyService.findAllHierarchy();
        roleHierarchy.setHierarchy(allHierarchy);
    }
}
