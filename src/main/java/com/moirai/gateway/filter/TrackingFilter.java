package com.moirai.gateway.filter;

import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Order(Ordered.HIGHEST_PRECEDENCE) // 가장 먼저 실행 (Pre Filter)
@Component
@RequiredArgsConstructor
public class TrackingFilter implements GlobalFilter {

    private final FilterUtils filterUtils;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest req = exchange.getRequest();

        String method = (req.getMethod() != null) ? req.getMethod().name() : "UNKNOWN";
        String path = req.getURI().getPath();

        // 기존 Correlation ID가 있으면 전파, 없으면 생성
        String existingCid = filterUtils.getCorrelationId(req.getHeaders());
        boolean generated = (existingCid == null || existingCid.isBlank());

        String cid = generated ? UUID.randomUUID().toString() : existingCid;

        if (generated) {
            exchange = filterUtils.setCorrelationId(exchange, cid);
            // 추적 ID 생성 로그
            log.info("[GW][TRACE] correlationId generated cid={} method={} path={}", cid, method, path);
        } else {
            // 기존 cid 전파는 DEBUG로
            log.debug("[GW][TRACE] correlationId propagated cid={} method={} path={}", cid, method, path);
        }

        return chain.filter(exchange);
    }
}
