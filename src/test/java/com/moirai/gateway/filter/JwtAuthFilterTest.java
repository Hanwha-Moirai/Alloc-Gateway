package com.moirai.gateway.filter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.util.Map;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;

class JwtAuthFilterTest {

    private static final String SECRET_BASE64 =
            "oTIu0wcG74gvm+AtU907bamJK3EraoAgcAia09SmWIZgsKUFipeU12DmPawCVPO8FZUf4PJGL5fXWrNDoVG4uQ==";

    private final SecretKey signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET_BASE64));
    private final JwtAuthFilter filter = new JwtAuthFilter(SECRET_BASE64);

    @Test
    @DisplayName("공개 경로는 토큰 없이 통과")
    void publicPath_allowsWithoutToken() {
        // 게이트웨이 실제 진입 경로 기준
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/auth/login").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        CapturingChain chain = new CapturingChain();

        filter.filter(exchange, chain).block();

        assertThat(chain.exchange).isNotNull();
    }

    @Test
    @DisplayName("OPTIONS 프리플라이트는 토큰 없이 통과")
    void options_preflight_allowsWithoutToken() {
        MockServerHttpRequest request = MockServerHttpRequest
                .method(HttpMethod.OPTIONS, "/api/projects")
                .header("Origin", "http://localhost:3000")
                .header("Access-Control-Request-Method", "GET")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        CapturingChain chain = new CapturingChain();

        filter.filter(exchange, chain).block();

        assertThat(chain.exchange).isNotNull();
        // OPTIONS bypass이므로 401이 아니어야 함(보통 status null 유지)
        assertThat(exchange.getResponse().getStatusCode()).isNotEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("토큰 없으면 401 반환")
    void missingToken_returnsUnauthorized() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/projects").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        CapturingChain chain = new CapturingChain();

        filter.filter(exchange, chain).block();

        assertThat(chain.exchange).isNull();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("Authorization 헤더 토큰이면 통과 + 사용자 헤더 주입")
    void authorizationHeader_tokenAccepted() {
        String token = createAccessToken("1");
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/projects")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        CapturingChain chain = new CapturingChain();

        filter.filter(exchange, chain).block();

        assertThat(chain.exchange).isNotNull();
        assertThat(chain.exchange.getRequest().getHeaders().getFirst(FilterUtils.X_USER_ID)).isEqualTo("1");
    }

    @Test
    @DisplayName("accessToken 쿠키 토큰이면 통과 + 사용자 헤더 주입")
    void accessTokenCookie_tokenAccepted() {
        String token = createAccessToken("2");
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/projects")
                .cookie(new HttpCookie("accessToken", token))
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        CapturingChain chain = new CapturingChain();

        filter.filter(exchange, chain).block();

        assertThat(chain.exchange).isNotNull();
        assertThat(chain.exchange.getRequest().getHeaders().getFirst(FilterUtils.X_USER_ID)).isEqualTo("2");
    }

    @Test
    @DisplayName("refresh 토큰은 인증에 사용 불가(401)")
    void refreshToken_isRejected() {
        String token = createRefreshToken("3");
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/projects")
                .cookie(new HttpCookie("accessToken", token))
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        CapturingChain chain = new CapturingChain();

        filter.filter(exchange, chain).block();

        assertThat(chain.exchange).isNull();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("X-CSRF-Token 헤더는 보존")
    void csrfHeader_isPreserved() {
        String token = createAccessToken("4");
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/projects")
                .header("X-CSRF-Token", "csrf-value")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        CapturingChain chain = new CapturingChain();

        filter.filter(exchange, chain).block();

        assertThat(chain.exchange).isNotNull();
        assertThat(chain.exchange.getRequest().getHeaders().getFirst("X-CSRF-Token"))
                .isEqualTo("csrf-value");
    }

    private String createAccessToken(String subject) {
        return Jwts.builder()
                .subject(subject)
                .claims(Map.of("role", "USER"))
                .signWith(signingKey)
                .compact();
    }

    private String createRefreshToken(String subject) {
        return Jwts.builder()
                .subject(subject)
                .claims(Map.of("typ", "refresh", "role", "USER"))
                .signWith(signingKey)
                .compact();
    }

    private static class CapturingChain implements org.springframework.cloud.gateway.filter.GatewayFilterChain {
        private ServerWebExchange exchange;

        @Override
        public Mono<Void> filter(ServerWebExchange exchange) {
            this.exchange = exchange;
            return Mono.empty();
        }
    }
}
