package uz.chelkatrao.learn_spring_security;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.time.Instant;

public class TokenAuthenticationUserDetailsService implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {
    @Override
    public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken authenticationToken) throws UsernameNotFoundException {
        if (authenticationToken.getPrincipal() instanceof Token token) {
            return new TokenUser(token.subject(),
                    "nopassword",
                    true,
                    true, //TODO  pasdagi qismini tekshirib ko'rish kerak
                    true,//token.expiresAt().isAfter(Instant.now()),
                    true,
                    token.authorities()
                            .stream()
                            .map(SimpleGrantedAuthority::new)
                            .toList(),
                    token);
        }
        throw new UsernameNotFoundException("Principal must be of type Token");
    }
}
