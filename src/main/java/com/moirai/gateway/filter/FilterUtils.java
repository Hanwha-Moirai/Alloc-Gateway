package com.moirai.gateway.filter;

import java.util.List;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

@Component
public class FilterUtils {

    // - 요청/응답 추적용
    public static final String CORRELATION_ID = "X-Correlation-Id";

    // Gateway에서 검증 후 내부로 전달하는 검증된 사용자 컨텍스트
    //클라이언트가 임의로 넣어도 Gateway에서 제거 후 재주입하므로 스푸핑 방지
    public static final String X_USER_ID = "X-User-Id";
    public static final String X_USER_ROLE = "X-User-Role";

    // 헤더에서 Correlation ID 조회
    public String getCorrelationId(HttpHeaders headers) {
        if (headers == null) return null;
        List<String> values = headers.get(CORRELATION_ID);
        return (values == null || values.isEmpty()) ? null : values.get(0);
    }

    // 요청에 Correlation ID 설정 (기존 값 제거 후 새로 설정)
    public ServerWebExchange setCorrelationId(ServerWebExchange exchange, String correlationId) {
        return exchange.mutate()
                .request(exchange.getRequest().mutate()
                        .headers(h -> {
                            h.remove(CORRELATION_ID);
                            h.add(CORRELATION_ID, correlationId);
                        })
                        .build())
                .build();
    }
}
