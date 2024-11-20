package com.gateway.apigetawaycontainer;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Value("${JWT_SECRET}")
    private String secretKey;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .csrf(csrf -> csrf.disable()) // Deshabilitar CSRF ya que JWT se usa para autenticación
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/auth/**").permitAll()  // Permitir las rutas de autenticación sin JWT
                        .anyExchange().authenticated()  // Todas las demás rutas requieren autenticación
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtDecoder(jwtDecoder()))  // Validación del JWT
                );
        return http.build();
    }

    @Bean
    public ReactiveJwtDecoder jwtDecoder() {
        // Usar la clave secreta para decodificar el JWT
        return NimbusReactiveJwtDecoder.withSecretKey(new javax.crypto.spec.SecretKeySpec(secretKey.getBytes(), "HmacSHA256")).build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOrigin("https://front-unlock-patrones.vercel.app"); // Dominio de producción del frontend
        configuration.addAllowedOrigin("http://localhost:4200"); // Dominio local para pruebas
        configuration.addAllowedMethod("*"); // Permitir todos los métodos HTTP (GET, POST, etc.)
        configuration.addAllowedHeader("*"); // Permitir todos los encabezados
        configuration.setAllowCredentials(true); // Permitir credenciales (cookies, tokens, etc.)

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // Aplicar configuración a todas las rutas
        return source;
    }
}

