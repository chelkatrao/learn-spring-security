package uz.chelkatrao.learn_spring_security;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Objects;
import java.util.function.Function;

public class JwtAuthenticationConfigurer extends AbstractHttpConfigurer<JwtAuthenticationConfigurer, HttpSecurity> {

    private Function<Token, String> refreshTokenSerializer = o -> Objects.toString(o);

    private Function<Token, String> accessTokenSerializer = o -> Objects.toString(o);

    @Override
    public void init(HttpSecurity builder) throws Exception {
        var csrfConfigurer = builder.getConfigurer(CsrfConfigurer.class);
        if (csrfConfigurer != null) {
            csrfConfigurer.ignoringRequestMatchers(
                    new AntPathRequestMatcher("/jwt/tokens", HttpMethod.POST.name()));
        }

        super.init(builder);
    }

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        var filter = new RequestJwtTokensFilter();
        filter.setAccessTokenSerializer(this.accessTokenSerializer);
        filter.setRefreshTokenSerializer(this.refreshTokenSerializer);

        builder.addFilterAfter(filter, ExceptionTranslationFilter.class);

    }

    public JwtAuthenticationConfigurer accessTokenSerializer(Function<Token, String> accessTokenSerializer) {
        this.accessTokenSerializer = accessTokenSerializer;
        return this;
    }

    public JwtAuthenticationConfigurer refreshTokenSerializer(Function<Token, String> refreshTokenSerializer) {
        this.refreshTokenSerializer = refreshTokenSerializer;
        return this;
    }
}
