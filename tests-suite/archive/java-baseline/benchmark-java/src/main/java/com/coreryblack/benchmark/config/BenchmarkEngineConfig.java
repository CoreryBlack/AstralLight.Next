package com.coreryblack.benchmark.config;

import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.permission.port.AuthorizationReadPort;
import com.coreryblack.permission.port.PermissionRuleEvaluationPort;
import com.coreryblack.benchmark.baseline.CasbinAdapter;
import com.coreryblack.benchmark.baseline.CasbinCachedAdapter;
import com.coreryblack.benchmark.baseline.OpaAdapter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

@Configuration
public class BenchmarkEngineConfig {

    @Value("${benchmark.opa.url:http://localhost:8181}")
    private String opaUrl;

    @Primary
    @Bean
    public PolicyEngine benchmarkPolicyEngine(PermissionRuleEvaluationPort permissionRuleEvaluationPort,
                                                AuthorizationReadPort authorizationReadPort) {
        return new PolicyEngine(permissionRuleEvaluationPort, authorizationReadPort, null, null, null);
    }

    // ── Casbin ──
    @Bean
    public CasbinAdapter casbinAdapter() {
        return new CasbinAdapter(false);
    }

    @Bean
    public CasbinCachedAdapter casbinCachedAdapter() {
        return new CasbinCachedAdapter();
    }

    // ── OPA ──
    // opaAdapter: production config with OPA decision cache (disableCache=false)
    // OPA server must have nd_builtin_cache enabled (docker-compose OPA args)
    @Bean
    public OpaAdapter opaAdapter() {
        return new OpaAdapter(opaUrl, false, false);
    }

    // opaNoCacheAdapter: no-cache variant for appendix NoCache vs Cache comparison
    // NOTE: OPA REST API decision cache is controlled by server-side Cache-Control headers,
    // not by request body fields. The _cache_buster field in OpaAdapter has no effect on
    // OPA's built-in decision cache. This bean is retained for potential future use with
    // Cache-Control: no-cache header injection.
    @Bean
    public OpaAdapter opaNoCacheAdapter() {
        return new OpaAdapter(opaUrl, false, true);
    }
}
