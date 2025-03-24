package org.chakir.graphql;


import org.chakir.dtos.*;
import org.chakir.encryption.CryptoUtilImpl;
import org.springframework.graphql.data.method.annotation.*;
import org.springframework.stereotype.Controller;
import javax.crypto.spec.SecretKeySpec;

@Controller
public class CryptoGraphQLResolver {

    private final CryptoUtilImpl cryptoUtil = new CryptoUtilImpl();

    @MutationMapping
    public String rsaSign(@Argument SignInput input) throws Exception {
        var privateKey = cryptoUtil.privateKeyFromBase64(input.privateKeyBase64);
        return cryptoUtil.rsaSign(input.data.getBytes(), privateKey);
    }

    @QueryMapping
    public Boolean rsaVerify(@Argument VerifyInput input) throws Exception {
        var publicKey = cryptoUtil.publicKeyFromBase64(input.publicKeyBase64);
        return cryptoUtil.rsaSignVerify(input.signedData, publicKey);
    }

    @MutationMapping
    public String aesEncrypt(@Argument AesInput input) throws Exception {
        var secretKey = new SecretKeySpec(input.secretKey.getBytes(), "AES");
        return cryptoUtil.encryptAES(input.data.getBytes(), secretKey);
    }

    @MutationMapping
    public String aesDecrypt(@Argument AesInput input) throws Exception {
        var secretKey = new SecretKeySpec(input.secretKey.getBytes(), "AES");
        byte[] result = cryptoUtil.decryptAES(input.data, secretKey);
        return new String(result);
    }
}
