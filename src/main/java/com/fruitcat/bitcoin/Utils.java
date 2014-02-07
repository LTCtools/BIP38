/**
 *
 * Copyright 2014 Diego Basch
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.fruitcat.bitcoin;

import com.google.bitcoin.core.AddressFormatException;
import com.google.bitcoin.core.Base58;
import org.bouncycastle.math.ec.ECPoint;
import org.spongycastle.crypto.BufferedBlockCipher;
import org.spongycastle.crypto.DataLengthException;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.engines.AESFastEngine;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Utils {

    /**
     * Compress a point.
     * @param uncompressed
     * @return
     */
    public static ECPoint compressPoint(ECPoint uncompressed) {
        return new ECPoint.Fp(uncompressed.getCurve(), uncompressed.getX(), uncompressed.getY(), true);
    }

    /**
     * Performs a double SHA-256 hash on a byte array (or a portion of it).
     * @param data
     * @param off
     * @param len
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static byte[] doubleHash(byte[] data, int off, int len) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(data, off, len);
        return md.digest(md.digest());
    }

    /**
     * Performs a RIPEMD-160 hash of a SHA-256 hash of a byte array.
     * @param data
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static byte[] sha256ripe160(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest r = MessageDigest.getInstance("RIPEMD160");
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        return r.digest(sha.digest(data));
    }

    /**
     * Appends a Bitcoin-style checksum to a byte array and encodes the result as Base58.
     * @param b a byte array
     * @return the encoded concatenation of the byte array and its checksum
     * @throws NoSuchAlgorithmException
     */

    public static String base58Check(byte [] b) throws NoSuchAlgorithmException {
        byte[] r = new byte[b.length + 4];
        System.arraycopy(b, 0, r, 0, b.length);
        System.arraycopy(doubleHash(b, 0, b.length), 0, r, b.length, 4);
        return Base58.encode(r);
    }

    /**
     * Encrypts plaintext with AES
     * @param plainTextAsBytes
     * @param key
     * @return
     * @throws GeneralSecurityException
     */
    public static byte[] AESEncrypt(byte[] plainTextAsBytes, byte[] key) throws GeneralSecurityException {
        try
        {
            final BufferedBlockCipher cipher = new BufferedBlockCipher(new CBCBlockCipher(new AESFastEngine()));
            KeyParameter aesKey = new KeyParameter(key);

            cipher.init(true, aesKey);

            final byte[] encryptedBytes = new byte[cipher.getOutputSize(plainTextAsBytes.length)];
            final int length = cipher.processBytes(plainTextAsBytes, 0, plainTextAsBytes.length, encryptedBytes, 0);

            cipher.doFinal(encryptedBytes, length);

            return encryptedBytes;
        }
        catch (final InvalidCipherTextException x)
        {
            throw new GeneralSecurityException("Could not encrypt bytes", x);
        }
        catch (final DataLengthException x)
        {
            throw new GeneralSecurityException("Could not encrypt bytes", x);
        }
    }

    /**
     * Decrypts ciphertext with AES
     * @param cipherBytes
     * @param key
     * @return
     * @throws GeneralSecurityException
     */
    public static byte[] AESDecrypt(byte[] cipherBytes, byte[] key) throws GeneralSecurityException {
        try
        {
            final BufferedBlockCipher cipher = new BufferedBlockCipher(new CBCBlockCipher(new AESFastEngine()));
            KeyParameter aesKey = new KeyParameter(key);
            cipher.init(false, aesKey);

            final byte[] decryptedBytes = new byte[cipher.getOutputSize(cipherBytes.length)];
            final int length = cipher.processBytes(cipherBytes, 0, cipherBytes.length, decryptedBytes, 0);

            cipher.doFinal(decryptedBytes, length);

            return decryptedBytes;
        }
        catch (final InvalidCipherTextException x)
        {
            throw new GeneralSecurityException("Could not decrypt input string", x);
        }
        catch (final DataLengthException x)
        {
            throw new GeneralSecurityException("Could not decrypt input string", x);
        }
    }

    /**
     * Concatenates many arrays of bytes into one.
     * @param buffers
     * @return
     */
    public static byte[] concat(byte[]... buffers) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (byte [] b : buffers) {
            try {
                baos.write(b);
            }
            catch (java.io.IOException e) {
                throw new RuntimeException(e.getMessage());
            }
        }
        return baos.toByteArray();
    }

    /**
     * Gets the lot and sequence for a key (-1, -1 if not present)
     * @param encryptedKey
     * @return 4096 * lot + sequence
     * @throws AddressFormatException
     */
    public static long getLotSequence(String encryptedKey) throws AddressFormatException {

        long ret = -4097; //-1 lot, -1 sequence
        byte[] keyBytes = Base58.decode(encryptedKey);
        byte flagByte = keyBytes[2];
        if ((flagByte & 4) == 4) {
            ByteBuffer b = ByteBuffer.wrap(keyBytes, 11, 4);
            b.order(ByteOrder.BIG_ENDIAN);
            ret = (long) b.getInt() & 0xffffffffL;
        }
        return ret;
    }

    //for debugging
    protected static void pb(String name, byte[] x) {
        System.out.print(name + ": ");
        for (byte b : x) {
            int l = b >= 0 ? b : 256 + b;
            System.out.print(l + " ");
        }
        System.out.println();
    }
}
