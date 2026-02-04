package com.moirai.gateway.filter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.server.reactive.ServerHttpRequest;
import reactor.core.publisher.Mono;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class ResponseFilter {

    private final FilterUtils filterUtils;

    @Bean
    public GlobalFilter postGlobalFilter() {
        return (exchange, chain) -> {
            long startMs = System.currentTimeMillis();

            ServerHttpRequest req = exchange.getRequest();
            String method = req.getMethod() != null ? req.getMethod().name() : "UNKNOWN";
            String path = req.getURI().getPath();
            String cid = filterUtils.getCorrelationId(req.getHeaders());

            return chain.filter(exchange).then(Mono.fromRunnable(() -> {
                long tookMs = System.currentTimeMillis() - startMs;

                // 응답 헤더에 Correlation ID 추가
                if (cid != null && !cid.isBlank()) {
                    exchange.getResponse().getHeaders().set(FilterUtils.CORRELATION_ID, cid);
                }

                HttpStatusCode status = exchange.getResponse().getStatusCode();
                int code = status != null ? status.value() : 0;

                // 상태 코드별 로그 레벨 분리 (5xx: 서버 오류, 4xx: 클라이언트 오류)
                if (code >= 500) {
                    log.warn("[GW][POST] request completed with server error cid={} method={} path={} status={} latencyMs={}",
                            cid, method, path, code, tookMs);
                } else if (code >= 400) {
                    log.warn("[GW][POST] request completed with client error cid={} method={} path={} status={} latencyMs={}",
                            cid, method, path, code, tookMs);
                } else {
                    log.debug("[GW][POST] request completed cid={} method={} path={} status={} latencyMs={}",
                            cid, method, path, code, tookMs);
                }
            }));
        };
    }
}