package com.example.jwt.config;

import com.example.jwt.filter.JwtAuthenticationFilter;
import com.example.jwt.filter.JwtAuthorizationFilter;
import com.example.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.CorsFilter;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;
    private final UserRepository userRepository;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }




    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,AuthenticationManager authenticationManager) throws Exception {
        http
                .addFilter(corsFilter)
                .csrf(csrf ->csrf.disable())
                .sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) //세션 비활성화
                .formLogin(login->login.disable())
                .httpBasic(basic->basic.disable())
                .addFilter(new JwtAuthenticationFilter(authenticationManager)) //AuthenticationManager
                .addFilter(new JwtAuthorizationFilter(authenticationManager,userRepository))
                .authorizeHttpRequests(authorize->authorize.
                        requestMatchers("/api/v1/user/**").hasAnyRole("ADMIN","MANAGER","USER").
                        requestMatchers("/api/v1/manager/**").hasAnyRole("ADMIN","MANAGER").
                        requestMatchers("/api/v1/admin/**").hasAnyRole("ADMIN").
                        anyRequest().permitAll()
                );


        return http. build();

    }
}
