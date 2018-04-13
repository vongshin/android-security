package de.yellowhing.security.key;

import android.content.Context;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public abstract class AndroidKeyStore {
    static String X500_PRINCIPAL = "CN=YellowHing, OU=AndroidSoft, O=Freedom, C=CN";
    static String ANDROID_KEYSTORE = "AndroidKeyStore";
    KeyStore keyStore;
    Context context;
    AndroidKeyStore(Context context) throws KeyStoreException{
        try {
            this.context = context;
            keyStore = java.security.KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
            throw new KeyStoreException(e);
        }
    }

    public KeyStore getKeyStore(){
        return keyStore;
    }

    /**
     * 生成非对称密钥，保存在Android 密钥库系统
     * @param alias 密钥别名
     * @throws KeyStoreException
     */
    public abstract void createKeyPairIfInvalid(String alias) throws KeyStoreException;
}
