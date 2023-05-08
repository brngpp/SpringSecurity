package com.alibou.security.config;

import com.alibou.security.token.TokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.beans.Transient;
import java.io.IOException;
import java.security.Security;

import jakarta.transaction.TransactionScoped;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter { //OncePerRequestFilter fa in modo che tutte 
                                                                    //le chiamate passino per il filter 

  private final JwtService jwtService;  //genera e valida i token
  private final UserDetailsService userDetailsService; // carica i dettagli dell utente
  private final TokenRepository tokenRepository;  //metodo per interagire con il token 

  @Override
  protected void doFilterInternal(  //metodo che viene eseguito su ogni richiesta del server 
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain filterChain
  ) throws ServletException, IOException {
    if (request.getServletPath().contains("/api/v1/auth")) { // eccezione per i casi di authentificazione 
      filterChain.doFilter(request, response);
      return;
    }
    final String authHeader = request.getHeader("Authorization"); //viene controllato che l header "authotization" sia prensete e che la stringa inizi con
    final String jwt;                                             //Bearer che indica un token validato 
    final String userEmail;
    if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
      filterChain.doFilter(request, response);
      return;
    }
    jwt = authHeader.substring(7);  //viene estratto il token da authorization togliendo bearer 
    userEmail = jwtService.extractUsername(jwt); //viene estratto l username (che può essere email , name, username a secondo del caso )
    if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
      UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail); //carichiamo l user usando l username 
      var isTokenValid = tokenRepository.findByToken(jwt)
          .map(t -> !t.isExpired() && !t.isRevoked())
          .orElse(false);
      if (jwtService.isTokenValid(jwt, userDetails) && isTokenValid) { //si verifica che il token non sia scaduto 
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(  //istanza dell utente con informazioni e autorizzazioni 
            userDetails,
            null,
            userDetails.getAuthorities()
        );
        authToken.setDetails( //autenticazione impostata su corretta 
            new WebAuthenticationDetailsSource().buildDetails(request)
        );
        SecurityContextHolder.getContext().setAuthentication(authToken);
      }
    }
    filterChain.doFilter(request, response); //la rispsota viene passata ai filtri successivi 
  }
}
