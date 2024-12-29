package uz.chelkatrao.learn_spring_security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class HexAuthenticationFilter extends OncePerRequestFilter {

    private final SecurityContextHolderStrategy securityContextHolderStrategy =
            SecurityContextHolder.getContextHolderStrategy();

    private final SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();

    private final AuthenticationManager authenticationManager;

    private final AuthenticationEntryPoint authenticationEntryPoint;

    public HexAuthenticationFilter(AuthenticationManager authenticationManager, AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationManager = authenticationManager;
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    @NotNull HttpServletResponse response,
                                    @NotNull FilterChain filterChain) throws ServletException, IOException {
        final var authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization != null && authorization.startsWith("Hex ")) {
            final var rowToken = authorization.replaceAll("^Hex ", "");
            final var token = new String(Hex.decode(rowToken), StandardCharsets.UTF_8);
            final var tokenParts = token.split(":");

            final var authenticationRequest = UsernamePasswordAuthenticationToken
                    .unauthenticated(tokenParts[0], tokenParts[1]);

            try {
                final Authentication authenticationResult = this.authenticationManager.authenticate(authenticationRequest);
                final SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
                context.setAuthentication(authenticationResult);

                this.securityContextHolderStrategy.setContext(context);
                this.securityContextRepository.saveContext(context, request, response);
            } catch (AuthenticationException e) {
                this.securityContextHolderStrategy.clearContext();
                this.authenticationEntryPoint.commence(request, response, e);
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    public static void main(String[] args) {
        char[] hexFormat = Hex.encode("chelkatrao:chelkatrao".getBytes());
        String s = String.valueOf(hexFormat);
        System.out.println(s);
    }

}
