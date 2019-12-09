package de.yellowhing.security.key;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import androidx.annotation.RequiresApi;

import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.util.Calendar;

import javax.security.auth.x500.X500Principal;

class AndroidKeyStoreApi23Impl extends AndroidKeyStore {

    AndroidKeyStoreApi23Impl(Context context) throws KeyStoreException {
        super(context);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    public void createKeyPairIfInvalid(String alias) throws KeyStoreException {
        if (!keyStore.containsAlias(alias)) {
            try {
                Calendar start = Calendar.getInstance();
                Calendar end = Calendar.getInstance();
                end.add(Calendar.YEAR, 100);
                KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE);
                KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setCertificateSubject(new X500Principal(X500_PRINCIPAL))
                        .setCertificateSerialNumber(BigInteger.ONE)
                        .setCertificateNotBefore(start.getTime())
                        .setCertificateNotAfter(end.getTime())
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                        .setRandomizedEncryptionRequired(false)
                        .setDigests()
                        .build();
                keyGenerator.initialize(spec);
                keyGenerator.generateKeyPair();
            } catch (Exception e) {
                e.printStackTrace();
                throw new KeyStoreException(e);
            }
        }
    }
}
