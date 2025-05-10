package com.mba;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.FixedSecureRandom;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

public class RSA {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // Load the public key from DER file
    public static PublicKey loadPublicKey(String filePath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(derFilePath));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    // Encrypt data using the public key
    public static byte[] encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // Use RSA with PKCS1 padding
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plainText.getBytes("UTF-8"));
    }

    //Get public key with X509 encoded key bytes
    private static PublicKey getRsaPublicKeyFromX509(byte[] x509DerBytes) throws Exception {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(x509DerBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    //Get public key with key bytes in PKCS1 format
    private static PublicKey getRsaPublicKeyFromPkcs1(byte[] pkcs1Bytes) throws Exception {
        try (ASN1InputStream asn1InputStream = new ASN1InputStream(pkcs1Bytes)) {
            RSAPublicKey rsaPub = RSAPublicKey.getInstance(asn1InputStream.readObject());
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(rsaPub.getModulus(), rsaPub.getPublicExponent());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(keySpec);
        }
    }

    public static byte[] encryptWithRsaDer(PublicKey derKey, String dataToEncrypt) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(dataToEncrypt);
        return encryptedBytes;
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private static String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
    public static void main(String[] args) {
        try {

            String derKey = "X509 Public Key";
            // Parse RSA public key
            PublicKey publicKey = getRsaPublicKeyFromX509(derKey);

            String message = "Hello, this is a secret!";
            // Convert hex string to byte array
            byte[] dataToEncrypt = hexStringToByteArray(message);

            // Encrypt using RSA
            byte[] encryptedBytes = encryptWithRsaDer(publicKey, dataToEncrypt);

            System.out.println("Encrypted (hex): " + byteArrayToHexString(encryptedBytes));
            System.out.println("Encrypted (base64): " + Base64.getEncoder().encodeToString(encryptedBytes));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
