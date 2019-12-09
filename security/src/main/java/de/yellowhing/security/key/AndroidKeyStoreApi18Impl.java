package de.yellowhing.security.key;

import android.content.Context;
import android.security.KeyPairGeneratorSpec;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.util.Calendar;

import javax.security.auth.x500.X500Principal;

class AndroidKeyStoreApi18Impl extends AndroidKeyStore{
    AndroidKeyStoreApi18Impl(Context context) throws KeyStoreException {
        super(context);
    }
    @Override
    public void createKeyPairIfInvalid(String alias) throws KeyStoreException {
        try {
            if (!keyStore.containsAlias(alias)) {
                Calendar start = Calendar.getInstance();
                Calendar end = Calendar.getInstance();
                end.add(Calendar.YEAR, 100);
                KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                        .setAlias(alias)
                        .setSubject(new X500Principal(X500_PRINCIPAL))
                        .setSerialNumber(BigInteger.ONE)
                        .setStartDate(start.getTime())
                        .setEndDate(end.getTime())
                        .build();
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", ANDROID_KEYSTORE);
                generator.initialize(spec);
                generator.generateKeyPair();
            }
        } catch (Exception e) {
            throw new KeyStoreException(e);
        }
    }
}
