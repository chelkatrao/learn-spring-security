package uz.chelkatrao.learn_spring_security;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

public class HexConfigurer extends AbstractHttpConfigurer<HexConfigurer, HttpSecurity> {

    private AuthenticationEntryPoint authenticationEntryPoint =
            (request, response, authException) -> {
                response.addHeader(HttpHeaders.WWW_AUTHENTICATE, "Hex");
                response.sendError(HttpStatus.UNAUTHORIZED.value());
            };

    @Override
    public void init(HttpSecurity builder) throws Exception {
        builder.exceptionHandling(c -> c.authenticationEntryPoint(this.authenticationEntryPoint));
    }

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        /*** Version 1.0 [HexAuthenticationFilter]
        AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);

        builder.addFilterBefore(
                new HexAuthenticationFilter(authenticationManager, this.authenticationEntryPoint),
                BasicAuthenticationFilter.class
        );*/

        //-----------------------------------------------------------------------------

        AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
        AuthenticationFilter authenticationFilter = new AuthenticationFilter(authenticationManager,
                new HexAuthenticationConvertor());
        authenticationFilter.setSuccessHandler((request, response, authentication) -> {});
        authenticationFilter.setFailureHandler(new AuthenticationEntryPointFailureHandler(this.authenticationEntryPoint));

        builder.addFilterBefore(authenticationFilter,
                BasicAuthenticationFilter.class);
    }

    public HexConfigurer setAuthenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
        return this;
    }

}
