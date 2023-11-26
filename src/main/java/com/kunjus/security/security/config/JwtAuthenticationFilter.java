package com.kunjus.security.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain //chain of responsibility design pattern --> list of other filters that we need to execute
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization"); //Authorization header contains jwt token.
        final String jwt;
        final String userEmail;

        //check for jwt token
        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request,response);
            return;
        }

        //extract the token from this header
        jwt = authHeader.substring(7);

        //extract userEmail from JWT token
        userEmail = jwtService.extractUsername(jwt);

        //if we have our userEmail and user is not authenticated,
        if(userEmail !=null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail); //get the userDetails from the database.
            if(jwtService.isTokenValid(jwt,userDetails)) { //check token and user is valid,
                //once our token is valid next we needed to update securityContext
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken( //this token is needed for update our security context.
                        userDetails,
                        null, //we don't have credential when we create a user.therefore it is given as null.
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                //update securityContextHolder
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        //always to pass hand to the next filters to be executed
        filterChain.doFilter(request,response);
    }
    //this filter needs to be active every time we get a request . so every time a user sends a req, we want our filter to get fired and do all the job that we wanted to do.

}
