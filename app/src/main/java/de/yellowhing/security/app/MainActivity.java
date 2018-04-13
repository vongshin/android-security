package de.yellowhing.security.app;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import java.security.KeyStoreException;
import de.yellowhing.security.SecureCipher;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";
    SecureCipher secureCipher;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        try {
            secureCipher = new SecureCipher(this);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        findViewById(R.id.btn_tap).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    String encryptText = secureCipher.encrypt("huangxingzhan666999");
                    Log.d(TAG, "encryptText: "+encryptText);
                    String  decryptText = secureCipher.decrypt(encryptText);
                    Log.d(TAG, "decryptText: "+decryptText);
                } catch (KeyStoreException e) {
                    e.printStackTrace();
                }
            }
        });
    }

    private String byteToHexString(byte[] bytes){
        StringBuilder sb = new StringBuilder();
        for (byte b:bytes) {
            String hex = Integer.toHexString(b);
            if(hex.length()==1){
                sb.append(0);
            }
            sb.append(hex);
        }
        return sb.toString();
    }
}
