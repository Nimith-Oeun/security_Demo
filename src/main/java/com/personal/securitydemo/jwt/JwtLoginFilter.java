package com.personal.securitydemo.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;

@RequiredArgsConstructor
public class JwtLoginFilter extends UsernamePasswordAuthenticationFilter{

    private final AuthenticationManager authenticationManager;

    /**
     * Constructor for JwtLoginFilter.
     *
     * authenticationManager the AuthenticationManager to use for authentication
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {

        ObjectMapper mapper = new ObjectMapper();

        try {
            // Deserialize the request body to LoginRequest object
            LoginRequest loginRequest = mapper.readValue(
                    request.getInputStream(),
                    LoginRequest.class);

            // Create an authentication token using the provided username and password
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    loginRequest.getUsername(),
                    loginRequest.getPassword()
            );

            Authentication authenticate = authenticationManager.authenticate(authentication);

            return authenticate;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Called when authentication is successful.
     * This method is used to generate the token when the user is successfully authenticated
     * @param request the HttpServletRequest
     * @param response the HttpServletResponse
     * @param chain the FilterChain
     * @param authResult the Authentication result
     * @throws IOException if an I/O error occurs
     * @throws ServletException if a servlet error occurs
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {

        String secretKey = "0123456789abcdef0123456789abcdef";
        String token = Jwts.builder()
                .setSubject(authResult.getName()) // Set the subject of the token
                .setIssuedAt(new Date()) // Set the issue date of the token
                .claim("authorities", authResult.getAuthorities()) // Set the authorities of the token
                .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusDays(1))) // Set the expiration date of the token
                .setIssuer("Security Test") // Set the issuer of the token
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes())) // Set the signature of the token
                .compact();

//        // Fetch user details from the database
//        User user = userRepository.findByUserName(authResult.getName()).get();
//
//        // Map user details to LoginRespones
//        LoginRespones loginResponse = AuthMapper.INSTANCE.mapUserToLoginRequest(user);
//        loginResponse.setToken(token);
//        loginResponse.setAuthorities(authResult.getAuthorities().stream()
//                .map(GrantedAuthority::getAuthority)
//                .filter(authority -> authority.startsWith("ROLE_"))
//                .toArray(String[]::new));
//
//        // Write the LoginResponse object to the response body
//        response.setContentType("application/json");
//        response.getWriter().write(new ObjectMapper().writeValueAsString(loginResponse));

        // Set the token in the response header
        response.setHeader("Authorization", "Bearer  " + token);
    }
}
