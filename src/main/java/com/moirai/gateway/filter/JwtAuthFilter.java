package com.moirai.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.util.List;
import javax.crypto.SecretKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Order(Ordered.HIGHEST_PRECEDENCE + 10) // TrackingFilter 다음 (Pre Filter)
@Component
public class JwtAuthFilter implements GlobalFilter {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String UNAUTHORIZED_BODY = "{\"message\":\"Unauthorized\"}";

    // 인증 없이 접근 가능한 경로 (Gateway로 들어오는 실제 path 기준)
    private static final List<String> PUBLIC_PATHS = List.of(
            "/actuator/**",
            "/api/auth/**"
    );

    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    private final SecretKey signingKey;

    public JwtAuthFilter(@Value("${jwt.secret}") String secretBase64) {
        byte[] keyBytes = Decoders.BASE64.decode(secretBase64);
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
        log.info("[GW][AUTH] jwt signing key initialized keyBytesLength={}", keyBytes.length);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest req = exchange.getRequest();

        // 항상 스푸핑 방지: 클라이언트가 임의로 넣은 사용자 헤더는 제거
        ServerHttpRequest sanitized = req.mutate().headers(h -> {
            h.remove(FilterUtils.X_USER_ID);
            h.remove(FilterUtils.X_USER_ROLE);
        }).build();
        if (sanitized != req) {
            exchange = exchange.mutate().request(sanitized).build();
            req = sanitized;
        }

        String method = (req.getMethod() != null) ? req.getMethod().name() : "UNKNOWN";
        String path = req.getURI().getPath();
        String cid = req.getHeaders().getFirst(FilterUtils.CORRELATION_ID);

        // CORS preflight(OPTIONS)는 인증 없이 통과
        // 브라우저는 cross-origin 요청 중 (커스텀 헤더/credentials 등) preflight가 필요하면
        // 실제 요청 전에 OPTIONS를 먼저 보낸다.
        // 여기서 401/403이 나면 preflight가 실패해서 브라우저가 실제 요청을 아예 보내지 않는다.
        if ("OPTIONS".equalsIgnoreCase(method)) {
            log.debug("[GW][AUTH] OPTIONS preflight bypassed cid={} path={}", cid, path);
            return chain.filter(exchange);
        }

        // 1) 공개 경로는 인증 없이 통과
        if (isPublicPath(path)) {
            log.debug("[GW][AUTH] public path bypassed cid={} method={} path={}", cid, method, path);
            return chain.filter(exchange);
        }

        // 2) Authorization 헤더 또는 accessToken 쿠키 확인
        String token = resolveToken(req);
        if (token == null || token.isBlank()) {
            log.warn("[GW][AUTH] missing or invalid auth token cid={} method={} path={}", cid, method, path);
            return unauthorized(exchange);
        }

        try {
            Claims claims = Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            // 3) refresh 토큰은 인증에 사용 금지
            String typ = claims.get("typ", String.class);
            if ("refresh".equals(typ)) {
                log.warn("[GW][AUTH] refresh token cannot be used for authorization cid={} method={} path={}",
                        cid, method, path);
                return unauthorized(exchange);
            }

            // 4) 사용자 컨텍스트 헤더 주입
            String userId = claims.getSubject();
            String role = claims.get("role", String.class);

            ServerHttpRequest mutated = req.mutate().headers(h -> {
                if (userId != null && !userId.isBlank()) h.add(FilterUtils.X_USER_ID, userId);
                if (role != null && !role.isBlank()) h.add(FilterUtils.X_USER_ROLE, role);
            }).build();

            exchange = exchange.mutate().request(mutated).build();

            log.debug("[GW][AUTH] token validated cid={} method={} path={} userId={} role={}",
                    cid, method, path, userId, role);

            return chain.filter(exchange);

        } catch (JwtException | IllegalArgumentException ex) {
            log.warn("[GW][AUTH] token validation failed cid={} method={} path={} reason={}",
                    cid, method, path, ex.getMessage());
            return unauthorized(exchange);
        }
    }

    private boolean isPublicPath(String path) {
        for (String pattern : PUBLIC_PATHS) {
            if (pathMatcher.match(pattern, path)) return true;
        }
        return false;
    }

    private String resolveToken(ServerHttpRequest req) {
        String authHeader = req.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
            return authHeader.substring(BEARER_PREFIX.length());
        }
        HttpCookie cookie = req.getCookies().getFirst("accessToken");
        if (cookie != null && cookie.getValue() != null && !cookie.getValue().isBlank()) {
            return cookie.getValue();
        }
        return null;
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        var response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        byte[] bytes = UNAUTHORIZED_BODY.getBytes(StandardCharsets.UTF_8);
        var buffer = response.bufferFactory().wrap(bytes);
        return response.writeWith(Mono.just(buffer));
    }
}
