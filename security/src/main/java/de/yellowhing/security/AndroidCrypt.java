package de.yellowhing.security;

import android.app.AppGlobals;
import android.content.Context;
import android.os.Build;
import android.util.Base64;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import de.yellowhing.security.key.AndroidKeyStore;
import de.yellowhing.security.key.AndroidKeyStoreFactory;
import de.yellowhing.security.utils.AESUtil;

/**
 * @author huangxingzhan
 * @date 2019/12/9
 */
public abstract class AndroidCrypt {
    private final static Charset UTF_8 = Charset.forName("UTF-8");
    private final static String ALIAS_SUFFIX = "_android_key_store";

    private AndroidCrypt(){}
    /**
     * Encrypt the raw bytes
     * @param data raw data
     * @return encrypt data
     */
    public static byte[] encrypt(byte[] data){
        return encrypt(data, getDefaultAlias());
    }
    /**
     * Encrypt the raw bytes
     * @param data raw data
     * @param alias key alias
     * @return encrypt data
     */
    public static byte[] encrypt(byte[] data, String alias){
        try {
            Context context = AppGlobals.getInitialApplication();
            AndroidKeyStore androidKeyStore = AndroidKeyStoreFactory.getInstance(context);
            androidKeyStore.createKeyPairIfInvalid(alias);
            PublicKey publicKey;
            publicKey = androidKeyStore.getKeyStore().getCertificate(alias).getPublicKey();
            Cipher cipher = createCipher();
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);
            cipherOutputStream.write(data);
            cipherOutputStream.close();
            return outputStream.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
            throw new UnsupportedOperationException(e);
        }
    }
    /**
     * Decrypt the encrypted bytes
     * @param data decrypt data
     * @return raw data
     */
    public static byte[] decrypt(byte[] data){
        return decrypt(data, getDefaultAlias());
    }

    /**
     * Decrypt the encrypted bytes
     * @param data decrypt data
     * @param alias key alias
     * @return raw data
     */
    public static byte[] decrypt(byte[] data, String alias){
        try {
            Context context = AppGlobals.getInitialApplication();
            AndroidKeyStore androidKeyStore = AndroidKeyStoreFactory.getInstance(context);
            PrivateKey privateKey = (PrivateKey) androidKeyStore.getKeyStore().getKey(alias, null);
            Cipher cipher = createCipher();
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            CipherInputStream cipherInputStream =
                    new CipherInputStream(new ByteArrayInputStream(data), cipher);
            ArrayList<Byte> values = new ArrayList<>();
            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) {
                values.add((byte)nextByte);
            }
            final byte[] bytes = new byte[values.size()];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = values.get(i);
            }
            return bytes;
        } catch (Exception e) {
            throw new UnsupportedOperationException(e);
        }
    }

    public static String encrypt(String text){
        return encrypt(text, getDefaultAlias());
    }

    public static String encrypt(String text, String alias){
        byte[] data = encrypt(text.getBytes(UTF_8), alias);
        return Base64.encodeToString(data, Base64.NO_WRAP);
    }

    public static String decrypt(String encryptedText){
        return decrypt(encryptedText, getDefaultAlias());
    }

    public static String decrypt(String encryptedText, String alias){
        byte[] data = decrypt(Base64.decode(encryptedText, Base64.NO_WRAP), alias);
        return new String(data, UTF_8);
    }

    /**
     * Encrypt the raw bytes like tls, for encrypt large data
     * asymmetric-key rsa  encrypt the raw bytes symmetric-key
     * symmetric-key aes  encrypt the raw bytes
     */
    public static byte[] encryptByTls(byte[] data){
        return encryptByTls(data, getDefaultAlias());
    }

    public static byte[] encryptByTls(byte[] data, String alias){
        try {
            SecretKey secretKey = AESUtil.generateAESKey();
            byte[] encoded = secretKey.getEncoded();
            byte[] encryptEncoded = encrypt(encoded, alias);
            byte[] encryptData = AESUtil.encrypt(secretKey, data);
            ByteBuffer buffer = ByteBuffer.allocate(Integer.SIZE/Byte.SIZE + encryptEncoded.length + encryptData.length);
            buffer.putInt(encryptEncoded.length)
                    .put(encryptEncoded)
                    .put(encryptData);
            return buffer.array();
        }catch (Exception e){
            e.printStackTrace();
            throw new UnsupportedOperationException(e);
        }
    }

    public static byte[] decryptByTls(byte[] encryptedText){
        return decryptByTls(encryptedText, getDefaultAlias());
    }

    public static byte[] decryptByTls(byte[] encryptedText, String alias){
        try {
            ByteBuffer buffer = ByteBuffer.wrap(encryptedText);
            int keyLen = buffer.getInt();
            byte[] encryptEncoded = new byte[keyLen];
            buffer.get(encryptEncoded);
            byte[] encryptData = new byte[buffer.remaining()];
            buffer.get(encryptData);
            byte[] encoded = decrypt(encryptEncoded, alias);
            return AESUtil.decrypt(encoded, encryptData);
        }catch (Exception e){
            e.printStackTrace();
            throw new UnsupportedOperationException(e);
        }
    }

    public static String encryptByTls(String text){
        return encryptByTls(text, getDefaultAlias());
    }

    public static String encryptByTls(String text, String alias){
        byte[] data = encryptByTls(text.getBytes(UTF_8), alias);
        return Base64.encodeToString(data, Base64.NO_WRAP);
    }

    public static String decryptByTls(String encryptedText){
        return decryptByTls(encryptedText, getDefaultAlias());
    }

    public static String decryptByTls(String encryptedText, String alias){
        byte[] data = decryptByTls(Base64.decode(encryptedText, Base64.NO_WRAP), alias);
        return new String(data, UTF_8);
    }

    private static Cipher createCipher() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return Cipher.getInstance("RSA/ECB/PKCS1Padding");
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            return Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
        } else  {
            throw new UnsupportedOperationException("Not supported yet");
        }
    }

    /**
     * @return default alias
     */
    private static String getDefaultAlias(){
        Context context = AppGlobals.getInitialApplication();
        return context.getPackageName()+ ALIAS_SUFFIX;
    }
}
