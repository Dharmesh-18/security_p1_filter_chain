package com.security.security_p1_filter_chain.config;

import com.security.security_p1_filter_chain.filter.CustomHeaderAuthFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomSecurityHandlers customSecurityHandlers;

    public SecurityConfig(CustomSecurityHandlers customSecurityHandlers) {
        this.customSecurityHandlers = customSecurityHandlers;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/public").permitAll()
                        .requestMatchers("/api/admin").hasRole("ADMIN")
                        .requestMatchers("/api/user").hasAnyRole("USER", "ADMIN")
                        .anyRequest().authenticated()
                )
                // Apna filter UsernamePasswordAuthenticationFilter ke pehle inject karo
                .addFilterBefore(new CustomHeaderAuthFilter(), UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(customSecurityHandlers) // 401
                        .accessDeniedHandler(customSecurityHandlers)       // 403
                );

        return http.build();
    }
}