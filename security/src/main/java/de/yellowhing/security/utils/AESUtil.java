package de.yellowhing.security.utils;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AESUtil {
    private static final String ALGORITHM = "AES";
    private AESUtil(){}


    public static byte[] encrypt(byte[] key, byte[] data) throws KeyStoreException {
        SecretKey secretKey = new SecretKeySpec(key, ALGORITHM);
        return encrypt(secretKey, data);
    }

    public static byte[] encrypt(SecretKey key, byte[] data) throws KeyStoreException {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new KeyStoreException(e);
        }
    }

    public static byte[] decrypt(byte[] key, byte[] data) throws KeyStoreException {
        SecretKey secretKey = new SecretKeySpec(key, ALGORITHM);
        return decrypt(secretKey, data);
    }

    public static byte[] decrypt(SecretKey key, byte[] data) throws KeyStoreException {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new KeyStoreException(e);
        }
    }

    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        // Generate a 256-bit key, 32byte
        return generateAESKey(256);
    }

    public static SecretKey generateAESKey(int kenLen) throws NoSuchAlgorithmException {
        final int outputKeyLength = kenLen;
        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(outputKeyLength, secureRandom);
        return keyGenerator.generateKey();
    }
}
