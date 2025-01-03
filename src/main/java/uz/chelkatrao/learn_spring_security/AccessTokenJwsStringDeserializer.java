package uz.chelkatrao.learn_spring_security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.UUID;
import java.util.function.Function;

public class AccessTokenJwsStringDeserializer implements Function<String, Token> {

    private static final Logger LOGGER = LoggerFactory.getLogger(AccessTokenJwsStringDeserializer.class);

    private final JWSVerifier jwsVerifier;

    public AccessTokenJwsStringDeserializer(JWSVerifier jwsVerifier) {
        this.jwsVerifier = jwsVerifier;
    }

    @Override
    public Token apply(String s) {
        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(s);
            if (signedJWT.verify(this.jwsVerifier)) {
                JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
                return new Token(
                        UUID.fromString(jwtClaimsSet.getJWTID()),
                        jwtClaimsSet.getSubject(),
                        jwtClaimsSet.getStringListClaim("authorities"),
                        jwtClaimsSet.getIssueTime().toInstant(),
                        jwtClaimsSet.getExpirationTime().toInstant()
                );
            }
        } catch (ParseException | JOSEException e) {
            LOGGER.error(e.getMessage(), e);
        }
        return null;
    }
}
