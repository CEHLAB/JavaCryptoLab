package org.chakir.encryption;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.security.cert.Certificate;


public class CryptoUtilImpl{
    public String toBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }
    public byte[] fromBase64(String dataBase64) {
        return Base64.getDecoder().decode(dataBase64.getBytes());
    }
    public String toBase64URL(byte[] data) {
        return Base64.getUrlEncoder().encodeToString(data);
    }
    public byte[] fromBase64URL(String dataBase64) {
        return Base64.getUrlDecoder().decode(dataBase64.getBytes());
    }
    public static String toHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
    public static byte[] ParseHexBinary(String hex) {
        if (hex == null || hex.length() % 2 != 0) {
            throw new IllegalArgumentException("La chaîne doit être non nulle et avoir une longueur paire.");
        }
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int hi = Character.digit(hex.charAt(i), 16);
            int lo = Character.digit(hex.charAt(i + 1), 16);
            if (hi == -1 || lo == -1) {
                throw new IllegalArgumentException("Caractère hexadécimal invalide : " + hex.substring(i, i + 2));
            }
            data[i / 2] = (byte) ((hi << 4) + lo);
        }
        return data;
    }

    public SecretKey generateSecretKey() throws Exception {
        KeyGenerator keyGenerator= KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }
    public String encryptAES(byte[] data, SecretKey secretKey) throws Exception {
        Cipher cipher=Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE,secretKey);
        byte[] encryptedData = cipher.doFinal(data);
        return Base64.getEncoder().encodeToString(encryptedData);
    }
    public byte[] decryptAES(String encryptedData, SecretKey secretKey) throws Exception {
        byte[] decodeEcryptedData = Base64.getDecoder().decode(encryptedData);
        Cipher cipher=Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(decodeEcryptedData);
    }
    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(512);
        return keyPairGenerator.generateKeyPair();
    }

    public PublicKey publicKeyFromBase64(String publicKeyBase64) throws Exception{
        KeyFactory keyFactory=KeyFactory.getInstance("RSA");
        byte[] decodedPublicKey =Base64.getDecoder().decode(publicKeyBase64);
        PublicKey publicKey;
        publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(decodedPublicKey));
        return publicKey;
    }

    public PrivateKey privateKeyFromBase64(String privateKeyBase64) throws Exception{
        KeyFactory keyFactory=KeyFactory.getInstance("RSA");
        byte[] decodedPrivateKey =Base64.getDecoder().decode(privateKeyBase64);
        PrivateKey privateKey;
        privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodedPrivateKey));
        return privateKey;
    }

    public String encryptRSA(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher=Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedData = cipher.doFinal(data);
        return toBase64(encryptedData);
    }

    public byte[] decryptRSA(String dataBase64, PrivateKey privateKey) throws Exception {
        Cipher cipher=Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedEncryptedData = fromBase64(dataBase64);
        return cipher.doFinal(decodedEncryptedData);
    }
    public PublicKey publicKeyFromCertificate(String fileName) throws Exception {
        FileInputStream fileInputStream = new FileInputStream(fileName);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certificateFactory.generateCertificate(fileInputStream);
        System.out.println(certificate.toString());
        return certificate.getPublicKey();
    }
    public PrivateKey privateKeyFromJKS(String fileName , String jksPassWord, String alias) throws Exception {
        FileInputStream fileInputStream=new FileInputStream(fileName);
        KeyStore keyStore=KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(fileInputStream,jksPassWord.toCharArray());
        Key key = keyStore.getKey(alias, jksPassWord.toCharArray());
        return (PrivateKey) key;

    }
    public String hmacSign(byte[] data,String privateSecret) throws Exception {
        SecretKeySpec secretKeySpec=new SecretKeySpec(privateSecret.getBytes(),"HmacSHA256");
        Mac mac=Mac.getInstance("HmacSHA256");
        mac.init(secretKeySpec);
        byte[] signature = mac.doFinal(data);
        return Base64.getEncoder().encodeToString(signature);
    }
    public boolean hmacVerify(String signedDocument,String secret) throws Exception {
        SecretKeySpec secretKeySpec=new SecretKeySpec(secret.getBytes(),"HmacSHA256");
        Mac mac=Mac.getInstance("HmacSHA256");
        String[] splitedDocument=signedDocument.split("_.._");
        String document=splitedDocument[0];
        String documentSignature=splitedDocument[1];
        mac.init(secretKeySpec);
        byte[] sign = mac.doFinal(document.getBytes());
        String base64Sign=Base64.getEncoder().encodeToString(sign);
        return (base64Sign.equals(documentSignature));
    }

    public String rsaSign(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature=Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey,new SecureRandom());
        signature.update(data);
        byte[] sign = signature.sign();
        return Base64.getEncoder().encodeToString(sign);
    }

    public boolean rsaSignVerify(String signedDoc,PublicKey publicKey) throws Exception {
        Signature signature=Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        String[] data=signedDoc.split("_.._");
        String document=data[0];
        String sign=data[1];
        byte[] decodeSignature = Base64.getDecoder().decode(sign);
        signature.update(document.getBytes());
        return signature.verify(decodeSignature);
    }

}
