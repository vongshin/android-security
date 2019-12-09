package de.yellowhing.security.app;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import androidx.appcompat.app.AppCompatActivity;
import javax.crypto.SecretKey;

import de.yellowhing.security.AndroidCrypt;
import de.yellowhing.security.utils.AESUtil;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";
    String data = "afagwadas";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        findViewById(R.id.btn_tap).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    SecretKey secretKey = AESUtil.generateAESKey();
                    byte[] p = secretKey.getEncoded();
                    byte[] ep = AndroidCrypt.encrypt(p);
                    byte[] dp = AndroidCrypt.decrypt(ep);
                    byte[] aep = AESUtil.encrypt(p, data.getBytes());
                    byte[] adp = AESUtil.decrypt(dp, aep);
                    Log.d(TAG, "onCreate: "+ new String(adp));

                    String a = AndroidCrypt.encryptByTls(data);
                    Log.d(TAG, "onCreate: a =  "+a);
                    String b = AndroidCrypt.decryptByTls(a);
                    Log.d(TAG, "onCreate: b =  "+b);
                    String c = AndroidCrypt.encrypt("189shfshafka");
                    Log.d(TAG, "onCreate: c = "+c);
                    String d = AndroidCrypt.decrypt(c);
                    Log.d(TAG, "onCreate: d = "+ d);
                } catch (Exception e) {
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
