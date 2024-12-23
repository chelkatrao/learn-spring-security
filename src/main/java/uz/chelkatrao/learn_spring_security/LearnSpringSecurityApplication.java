package uz.chelkatrao.learn_spring_security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerResponse;

import java.security.Principal;
import java.util.Map;
import java.util.Optional;

@SpringBootApplication
public class LearnSpringSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(LearnSpringSecurityApplication.class, args);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        BasicAuthenticationEntryPoint authenticationEntryPoint = new BasicAuthenticationEntryPoint();
        authenticationEntryPoint.setRealmName("Realm");
        return http
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .exceptionHandling(eh-> eh.authenticationEntryPoint(authenticationEntryPoint))
                .httpBasic(httpBasic -> {
                    httpBasic.authenticationEntryPoint((request, response, authException) -> {
                        authException.printStackTrace();
                        authenticationEntryPoint.commence(request, response, authException);
                    });
                })
                .build();
    }

    @Bean
    public RouterFunction<ServerResponse> routerFunction() {
        return RouterFunctions.route()
                .GET("/api/v4/greetings", request -> {
                    Optional<Principal> principal = request.principal();
                    UserDetails userDetails = principal
                            .map(Authentication.class::cast)
                            .map(Authentication::getPrincipal)
                            .map(UserDetails.class::cast)
                            .orElseThrow();
                    return ServerResponse.ok()
                            .contentType(MediaType.APPLICATION_JSON)
                            .body(Map.of("greeting", "Hello, %s! V4".formatted(userDetails.getUsername())));
                })
                .build();
    }

}
