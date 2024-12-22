package uz.chelkatrao.learn_spring_security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerResponse;

@SpringBootApplication
public class LearnSpringSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(LearnSpringSecurityApplication.class, args);
    }

    /***
     << Basic Authentication configuration >>
     @Bean public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
     return http
     .httpBasic().and()
     .authorizeHttpRequests()
     .anyRequest().authenticated().and()
     .build();
     }*/

    @Bean
    public RouterFunction<ServerResponse> routerFunction() {
//        return RouterFunctions.route()
//                .GET("/api/v4/greetings", request -> {
//
//                })
//                .build();
        return null;
    }

}
