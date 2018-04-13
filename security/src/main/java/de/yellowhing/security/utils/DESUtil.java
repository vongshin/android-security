package de.yellowhing.security.utils;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class DESUtil {
    private static final String ALGORITHM = "DES";
    private static final String TRANSFORMATION = "DES/ECB/NoPadding";
    private DESUtil(){}

    public static byte[] encrypt(byte[] key, byte[] data) throws KeyStoreException{
        try {
            SecretKey secretKey = new SecretKeySpec(key, ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
