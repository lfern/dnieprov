/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.dnieprov.crypto.digests;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import org.dnieprov.crypto.ExtendedDigest;

/**
 *
 * @author luis
 */
public class NoneDigest implements ExtendedDigest{

    private ByteArrayOutputStream ostream = new ByteArrayOutputStream();
    private static int MAX_LENGTH = 64;// 512-bits
    private String digestName = "NONE";
    @Override
    public int getByteLength() {
        return ostream.size();
    }

    @Override
    public String getAlgorithmName() {
        //return digestName;
        return "NONE";
    }

    @Override
    public int getDigestSize() {
        return getByteLength();
    }

    @Override
    public void update(byte in) {
        ostream.write(in);
    }

    @Override
    public void update(byte[] in, int inOff, int len) {
        ostream.write(in,inOff,len);
    }

    @Override
    public int doFinal(byte[] out, int outOff) {
        byte[]b=ostream.toByteArray();
        
        switch (b.length){
            case 20:
                digestName = "SHA1";
                break;
            case 36:
                //digestName = "SHA1+MD5";
                digestName = "SHA1";
                break;
            case 32:
                digestName = "SHA-256";
                break;
            case 48:
                digestName = "SHA-384";
                break;
            case 64:
                digestName = "SHA-512";
                break;
            case 16:
                digestName = "MD5";
                break;
            default:
                digestName = "NONE";
        }
        
        System.arraycopy(b,0,out, outOff,b.length);
        return b.length;
    }

    @Override
    public void reset() {
        ostream.reset();
    }
    
}
