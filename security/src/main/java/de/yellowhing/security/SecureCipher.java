package de.yellowhing.security;

import android.content.Context;
import android.os.Build;
import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import de.yellowhing.security.key.AndroidKeyStore;
import de.yellowhing.security.key.AndroidKeyStoreFactory;

public class SecureCipher {
    private final AndroidKeyStore androidKeyStore;
    private String alias;

    public SecureCipher(Context context) throws KeyStoreException {
        this(context, context.getPackageName()+"_android_key_store");
    }

    public SecureCipher(Context context, String alias) throws KeyStoreException{
        this.alias = alias;
        try {
            this.androidKeyStore = AndroidKeyStoreFactory.getInstance(context);
        } catch (Exception e) {
            e.printStackTrace();
            throw new KeyStoreException();
        }
    }

    public byte[] encrypt(byte[] data) throws KeyStoreException{
        try {
            androidKeyStore.createKeyPairIfInvalid(alias);
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) androidKeyStore.getKeyStore().getEntry(alias, null);
            RSAPublicKey publicKey = (RSAPublicKey) privateKeyEntry.getCertificate().getPublicKey();

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
    public byte[] decrypt(byte[] data) throws KeyStoreException{
        try {
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) androidKeyStore.getKeyStore().getEntry(alias, null);
            Cipher cipher = createCipher();
            cipher.init(Cipher.DECRYPT_MODE, privateKeyEntry.getPrivateKey());
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
        try {
            byte[] data = encrypt(text.getBytes("UTF-8"));
            return Base64.encodeToString(data, Base64.NO_WRAP);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            throw new KeyStoreException();
        }
    }

    public String decrypt(String text) throws KeyStoreException{
        try {
            byte[] data = decrypt(Base64.decode(text, Base64.NO_WRAP));
            return new String(data,"UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            throw new KeyStoreException();
        }
    }

    private Cipher createCipher() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return Cipher.getInstance("RSA/ECB/PKCS1Padding");
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            return Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
        } else  {
            throw new UnsupportedOperationException("Not supported yet");
        }
    }
}
