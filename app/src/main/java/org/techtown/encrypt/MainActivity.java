package org.techtown.encrypt;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Enumeration;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {

    public String TAG="hello";
    public String sentence="안녕하세요";
    public String key = "secretKey1234567"; //지금 16글자

    public static String alias = "ItsAlias"; //안드로이드 키스토어 내에서 보여질 키의 별칭

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        TextView textView=findViewById(R.id.textView);
        TextView textView2=findViewById(R.id.textView2);
        TextView textView3=findViewById(R.id.textView3);

        //1. 평문 암호화할 AES키를 만들고 keystore키로 암호화함
        //2. 암호화된 키로 평문 암호화
        try {
            // 방법1. 키를 직접 지정해서 암호화, 복호화 하는 방법
            //String key = "secretKey1234567";

            //1.평문 암호화할 AES키를 만들고 keystore키로 암호화함
            if (!AES.isExistKey(alias)) {
                AES.generateKey(alias);
            }
            SecretKey secretKey = AES.getKeyStoreKey(alias);
            String[] enc = AES.encByKeyStoreKey(secretKey, key);
            textView.setText(enc[0]); //암호화 된 키
            textView2.setText(enc[1]); //키 벡터

            //key=enc[0];
            //key="BCYIifewxEAwgdjQEbQ";
            Log.d(TAG ,"암호화 결과33333333 : " + enc[0].length());
            Log.d(TAG ,"암호화 결과33333333 : " + enc[1].length());
//            Log.d(TAG ,"암호화 결과33333333 : " + enc[1].getBytes());
//            Log.d(TAG ,"암호화 결과33333333 : " + enc[1].getBytes().toString().length());

            //String[] encText = AES.encByKey(enc[0], sentence);

            key=enc[0].substring(0,32); //16, 32개로 맞춰줘야됨.. //128, 256
            Log.d(TAG ,"암호화33333 : " +  enc[0]);
            Log.d(TAG ,"암호화33333 : " + key);
            //Log.d(TAG ,"암호화33333 : " + key.getBytes().toString().length()); //10 ,9
            String[] encText = AES.encByKey(key, sentence);
            String decText = AES.decByKey(key, encText[0],encText[1]);
//            Log.d(TAG ,"암과 : " + encText[0].getBytes().toString().length());
//            Log.d(TAG ,"암과 : " + encText[1].getBytes().toString().length());
            Log.d(TAG ,"복호화 결과 : " + decText);

            Log.d(TAG ,"암호화 결과33333333 : " + encText[1]);
            Log.d(TAG ,"암호화 결과33333333 : " + encText[1].length()); //???왜 17이나와
            //2.암호화된 키(enc[0])로 평문 암호화, 복호화 -벡터 얻어야됨
//            String[] encText = AES.encByKey(enc[0], sentence);
//            String decText = AES.decByKey(enc[0], encText[0], encText[1]); //키, 암호문, 벡터
//            //복호화 복호문만 출력하도록
//            Log.d(TAG ,"암호화 결과 : " + encText);
//            Log.d(TAG ,"복호화 결과 : " + decText);
            textView3.setText(decText);


            // 방법2. 키스토어에서 생성한 키를 사용해서 암호화, 복호화 하는 방법
//            if (!AES.isExistKey(alias)) {
//                AES.generateKey(alias);
//            }
//            SecretKey secretKey = AES.getKeyStoreKey(alias);
//            String[] enc = AES.encByKeyStoreKey(secretKey, sentence);
//            textView.setText(enc[0]);
//            textView2.setText(enc[1]);
//
//            Log.d(TAG, "암호화 결과 : " + enc[0]);
//            Log.d(TAG, "암호화 IV : " + enc[1]);
//            String dec = AES.decByKeyStoreKey(secretKey, enc[0], enc[1]);
//
//            Log.d(TAG, "복호화 결과 : " + dec);
//            textView3.setText(dec);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}