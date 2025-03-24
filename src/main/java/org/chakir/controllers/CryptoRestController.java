package org.chakir.controllers;



import org.chakir.dtos.*;
import org.chakir.encryption.CryptoUtilImpl;
import org.springframework.web.bind.annotation.*;
import javax.crypto.spec.SecretKeySpec;

@RestController
@RequestMapping("/api/crypto")
public class CryptoRestController {

    private final CryptoUtilImpl cryptoUtil = new CryptoUtilImpl();

    @PostMapping("/rsa/sign")
    public String rsaSign(@RequestBody SignInput input) throws Exception {
        var privateKey = cryptoUtil.privateKeyFromBase64(input.privateKeyBase64);
        return cryptoUtil.rsaSign(input.data.getBytes(), privateKey);
    }

    @PostMapping("/rsa/verify")
    public boolean rsaVerify(@RequestBody VerifyInput input) throws Exception {
        var publicKey = cryptoUtil.publicKeyFromBase64(input.publicKeyBase64);
        return cryptoUtil.rsaSignVerify(input.signedData, publicKey);
    }

    @PostMapping("/aes/encrypt")
    public String aesEncrypt(@RequestBody AesInput input) throws Exception {
        var secretKey = new SecretKeySpec(input.secretKey.getBytes(), "AES");
        return cryptoUtil.encryptAES(input.data.getBytes(), secretKey);
    }

    @PostMapping("/aes/decrypt")
    public String aesDecrypt(@RequestBody AesInput input) throws Exception {
        var secretKey = new SecretKeySpec(input.secretKey.getBytes(), "AES");
        byte[] result = cryptoUtil.decryptAES(input.data, secretKey);
        return new String(result);
    }
}

