package uz.chelkatrao.learn_spring_security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.function.Function;

public class RefreshTokenFilter extends OncePerRequestFilter {

    private RequestMatcher requestMatcher = new AntPathRequestMatcher("/jwt/refresh", HttpMethod.POST.name());

    private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();

    private Function<Token, Token> accessTokenFactory;

    private Function<Token, String> accessTokenStringSerializer = Object::toString;

    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

    }

    public void setRequestMatcher(RequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
    }

    public void setSecurityContextRepository(SecurityContextRepository securityContextRepository) {
        this.securityContextRepository = securityContextRepository;
    }

    public void setAccessTokenFactory(Function<Token, Token> accessTokenFactory) {
        this.accessTokenFactory = accessTokenFactory;
    }

    public void setAccessTokenStringSerializer(Function<Token, String> accessTokenStringSerializer) {
        this.accessTokenStringSerializer = accessTokenStringSerializer;
    }

    public void setObjectMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }
}
