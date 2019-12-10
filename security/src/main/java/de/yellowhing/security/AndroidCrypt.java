package de.yellowhing.security;
import android.content.Context;
import android.os.Build;
import android.util.Base64;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.KeyStoreException;
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

import de.yellowhing.security.charset.Charsets;
import de.yellowhing.security.key.AndroidKeyStore;
import de.yellowhing.security.key.AndroidKeyStoreFactory;
import de.yellowhing.security.utils.AESUtil;

public class AndroidCrypt {
    private final static String ALIAS_SUFFIX = "_android_key_store";
    private final AndroidKeyStore androidKeyStore;
    private String alias;

    public AndroidCrypt(Context context) throws KeyStoreException {
        this(context, context.getPackageName()+ALIAS_SUFFIX);
    }

    public AndroidCrypt(Context context, String alias) throws KeyStoreException{
        this.alias = alias;
        try {
            this.androidKeyStore = AndroidKeyStoreFactory.getInstance(context);
        } catch (Exception e) {
            throw new KeyStoreException();
        }
    }
    /**
     * Encrypt the raw bytes
     * @param data raw data
     * @return encrypt data
     */
    public byte[] encrypt(byte[] data) throws KeyStoreException{
        try {
            androidKeyStore.createKeyPairIfInvalid(alias);
            PublicKey publicKey = androidKeyStore.getKeyStore().getCertificate(alias).getPublicKey();
            Cipher cipher = createCipher();
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);
            cipherOutputStream.write(data);
            cipherOutputStream.close();
            return outputStream.toByteArray();
        } catch (Exception e) {
            throw new KeyStoreException(e);
        }
    }

    /**
     * Decrypt the encrypted bytes
     * @param data decrypt data
     * @return raw data
     */
    public byte[] decrypt(byte[] data) throws KeyStoreException{
        try {
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
            throw new KeyStoreException(e);
        }
    }

    public String encrypt(String text) throws KeyStoreException{
        byte[] data = encrypt(text.getBytes(Charsets.UTF_8));
        return Base64.encodeToString(data, Base64.NO_WRAP);
    }

    public String decrypt(String encryptedText) throws KeyStoreException{
        byte[] data = decrypt(Base64.decode(encryptedText, Base64.NO_WRAP));
        return new String(data, Charsets.UTF_8);
    }

    /**
     * Encrypt the raw bytes like tls, for encrypt large data
     * asymmetric-key rsa  encrypt the raw bytes symmetric-key
     * symmetric-key aes  encrypt the raw bytes
     */
    public byte[] encryptByTls(byte[] data) throws KeyStoreException{
        try {
            SecretKey secretKey = AESUtil.generateAESKey();
            byte[] encoded = secretKey.getEncoded();
            byte[] encryptEncoded = encrypt(encoded);
            byte[] encryptData = AESUtil.encrypt(secretKey, data);
            ByteBuffer buffer = ByteBuffer.allocate(Integer.SIZE/Byte.SIZE + encryptEncoded.length + encryptData.length);
            buffer.putInt(encryptEncoded.length)
                    .put(encryptEncoded)
                    .put(encryptData);
            return buffer.array();
        }catch (Exception e){
            throw new KeyStoreException(e);
        }
    }

    public byte[] decryptByTls(byte[] encryptedText) throws KeyStoreException{
        try {
            ByteBuffer buffer = ByteBuffer.wrap(encryptedText);
            int keyLen = buffer.getInt();
            byte[] encryptEncoded = new byte[keyLen];
            buffer.get(encryptEncoded);
            byte[] encryptData = new byte[buffer.remaining()];
            buffer.get(encryptData);
            byte[] encoded = decrypt(encryptEncoded);
            return AESUtil.decrypt(encoded, encryptData);
        }catch (Exception e){
            e.printStackTrace();
            throw new KeyStoreException(e);
        }
    }

    public String encryptByTls(String text) throws KeyStoreException{
        byte[] data = encryptByTls(text.getBytes(Charsets.UTF_8));
        return Base64.encodeToString(data, Base64.NO_WRAP);
    }

    public String decryptByTls(String encryptedText) throws KeyStoreException{
        byte[] data = decryptByTls(Base64.decode(encryptedText, Base64.NO_WRAP));
        return new String(data, Charsets.UTF_8);
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
}
