package uz.chelkatrao.learn_spring_security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.nio.charset.StandardCharsets;

public class HexAuthenticationConvertor implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {
        final var authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization != null && authorization.startsWith("Hex ")) {
            final var rowToken = authorization.replaceAll("^Hex ", "");
            final var token = new String(Hex.decode(rowToken), StandardCharsets.UTF_8);
            final var tokenParts = token.split(":");

            return UsernamePasswordAuthenticationToken.unauthenticated(tokenParts[0], tokenParts[1]);
        }
        return null;
    }

}
