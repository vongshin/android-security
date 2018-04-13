package de.yellowhing.security.key;
import android.content.Context;
import android.os.Build;
import java.security.KeyStoreException;

public class AndroidKeyStoreFactory {
    public static AndroidKeyStore getInstance(Context context) throws KeyStoreException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
           return new AndroidKeyStoreApi23Impl(context);
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            return new AndroidKeyStoreApi18Impl(context);
        } else  {
            throw new UnsupportedOperationException("Not supported yet");
        }
    }
}
