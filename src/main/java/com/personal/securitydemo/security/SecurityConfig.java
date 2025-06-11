package com.personal.securitydemo.security;

import com.personal.securitydemo.enumeration.Role;
import com.personal.securitydemo.enumeration.RolePermission;
import com.personal.securitydemo.jwt.JwtLoginFilter;
import com.personal.securitydemo.jwt.TokenVerifyFilter;
import com.personal.securitydemo.repository.UserRepository;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity(
        securedEnabled = true, // Enable @Secured annotation
        jsr250Enabled = true, // Enable @RolesAllowed annotation
        prePostEnabled = true // Enable @PreAuthorize and @PostAuthorize annotations
)
public class SecurityConfig {

    private final PasswordEncoder passwordEncoder;
    private final AuthenticationConfiguration authenticationConfiguration;
    private final UserRepository userRepository;
    private final UserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable) // Disable CSRF protection for simplicity
                .addFilter(new JwtLoginFilter(authenticationManager(authenticationConfiguration), userRepository)) // Add JWT login filter
                .addFilterAfter(new TokenVerifyFilter(), JwtLoginFilter.class)
                .sessionManagement(config -> config
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/",
                                "index.html",
                                "/css/**",
                                "/js/**",
                                "/api/test/register"
                        )
                        .permitAll() // Allow access to the root path without authentication
//                        .requestMatchers("/api/test/**").hasRole(Role.ADMIN.name()) // Allow access to /api/test/admin for users by role
//                        .requestMatchers(HttpMethod.GET, "/api/test").hasAuthority(RolePermission.USER_READ.getDescription()) // Allow GET requests to /api/test for user by permission
//                        .requestMatchers(HttpMethod.GET, "/api/test/**").hasAuthority(RolePermission.ADMIN_WRITE.getDescription()) // Allow POST requests to /api/test/** for admins by permission
                        .anyRequest()
                        .authenticated() // All other requests require authentication
                )
                .exceptionHandling(eh -> eh
                        .accessDeniedHandler(new CustomAccessDeniedHandler())) // Configure exception handling for access denied to respond with a custom message 403

                .httpBasic(Customizer.withDefaults()) // <-- add this for Postman Basic Auth support
                .logout(LogoutConfigurer::permitAll);// Allow access to the login page without authentication);

        return http.build();
    }


//    // create user in memory for testing purposes
//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails user1 = User.builder()
//                .username("user1")
//                .password(passwordEncoder.encode("123"))
//                .authorities(Role.ADMIN.getAuthorities())
//                .build();
//        UserDetails user2 = User.builder()
//                .username("user2")
//                .password(passwordEncoder.encode("123"))
//                .authorities(Role.USER.getAuthorities())
//                .build();
//        return new InMemoryUserDetailsManager(user1, user2);
//    }

    // Create an AuthenticationManager
    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    //this function is used to configure the authentication manager
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(getAuthenticationProvider());
    }

    @Bean
    public AuthenticationProvider getAuthenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder);
        return authenticationProvider;
    }



}

