///*
//    * This class is used to handle exceptions that occur during the execution of the filter chain.
// */
//package com.personal.securitydemo.jwt;
//
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.beans.factory.annotation.Qualifier;
//import org.springframework.stereotype.Component;
//import org.springframework.web.filter.OncePerRequestFilter;
//import org.springframework.web.servlet.HandlerExceptionResolver;
//import java.io.IOException;
//
//@Slf4j
//@Component
//public class FilterChainExceptionHandler extends OncePerRequestFilter {
//
//    @Autowired
//    @Qualifier("handlerExceptionResolver")
//    private HandlerExceptionResolver resolver;
//    @Override
//    protected void doFilterInternal(HttpServletRequest request,
//                                    HttpServletResponse response,
//                                    FilterChain filterChain) throws ServletException, IOException {
//        try {
//            filterChain.doFilter(request, response);
//        } catch (Exception e) {
//            log.error("Spring Security Filter Chain Exception:", e);
//            resolver.resolveException(request, response, null, e);
//        }
//    }
//}