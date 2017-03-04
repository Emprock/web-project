package com.example.jxwang.testinject;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        pingInject();

        try {
            File tf = File.createTempFile("test_inject", null);
            tf.setWritable(true);
            tf.setReadable(true);

            FileWriter fw = new FileWriter(tf);
            fw.write("this is a test content.");
            fw.flush();
            fw.close();
            Log.i("TEST_INJECT", "write file!");

            char[] buffer = new char[24];
            FileReader fr = new FileReader(tf);
            fr.read(buffer);
            fr.close();
            Log.i("TEST_INJECT", String.copyValueOf(buffer));
            tf.delete();

        } catch (IOException e) {
            Log.e("TEST_INJECT", e.getMessage());
            e.printStackTrace();
        }
    }

    static {
        //try {
            // Preform su to get root privledges
            //Runtime.getRuntime().exec("su");
            System.loadLibrary("hook");
        //} catch (IOException e) {
            // TODO Code to run in input/output exception
        //    Log.w("TEST_INJECT", "not root");
        //}
    }

    public native void pingInject();
}
