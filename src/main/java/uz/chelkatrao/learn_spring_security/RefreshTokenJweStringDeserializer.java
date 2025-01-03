package uz.chelkatrao.learn_spring_security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.UUID;
import java.util.function.Function;

public class RefreshTokenJweStringDeserializer implements Function<String, Token> {

    private static final Logger LOGGER = LoggerFactory.getLogger(RefreshTokenJweStringDeserializer.class);

    private final JWEDecrypter jweDecrypter;

    public RefreshTokenJweStringDeserializer(JWEDecrypter jweDecrypter) {
        this.jweDecrypter = jweDecrypter;
    }

    @Override
    public Token apply(String s) {
        EncryptedJWT encryptedJWT = null;
        try {
            encryptedJWT = EncryptedJWT.parse(s);
            encryptedJWT.decrypt(this.jweDecrypter);

            JWTClaimsSet jwtClaimsSet = encryptedJWT.getJWTClaimsSet();
            return new Token(
                    UUID.fromString(jwtClaimsSet.getJWTID()),
                    jwtClaimsSet.getSubject(),
                    jwtClaimsSet.getStringListClaim("authorities"),
                    jwtClaimsSet.getIssueTime().toInstant(),
                    jwtClaimsSet.getExpirationTime().toInstant()
            );
        } catch (ParseException | JOSEException e) {
            LOGGER.error(e.getMessage(), e);
        }
        return null;

    }

}
